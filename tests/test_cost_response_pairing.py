"""Provider charges pair with their own response's estimate by response id."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from agents.models.fake_id import FAKE_RESPONSES_ID
from agents.usage import Usage

from strix.core.hooks import ReportUsageHooks
from strix.report import usage as usage_module
from strix.report.state import (
    ReportState,
    litellm_cost_callback,
    sdk_response_id,
    set_global_report_state,
)
from strix.report.usage import LLMUsageLedger


if TYPE_CHECKING:
    from pathlib import Path


def _usage(tokens: int) -> Usage:
    return Usage(requests=1, input_tokens=tokens, output_tokens=0, total_tokens=tokens)


def test_sdk_chat_completion_output_preserves_provider_response_id() -> None:
    response = SimpleNamespace(
        response_id=None,
        output=[SimpleNamespace(provider_data={"response_id": "gen-123"})],
    )
    assert sdk_response_id(response) == "gen-123"
    response.output.append(SimpleNamespace(provider_data={"response_id": "gen-other"}))
    assert sdk_response_id(response) is None


def test_sdk_response_id_skips_the_placeholder_streamed_chat_completions_carry() -> None:
    # A streamed Chat Completions response comes back from the SDK with the
    # constant FAKE_RESPONSES_ID, which says nothing about the response.
    streamed = SimpleNamespace(
        response_id=FAKE_RESPONSES_ID,
        output=[SimpleNamespace(provider_data={"response_id": "gen-123"})],
    )
    assert sdk_response_id(streamed) == "gen-123"

    assert sdk_response_id(SimpleNamespace(response_id=FAKE_RESPONSES_ID, output=[])) is None
    assert sdk_response_id(SimpleNamespace(response_id="resp_1", output=[])) == "resp_1"


async def test_streamed_chat_completion_charge_replaces_its_sdk_estimate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        usage_module,
        "_estimate_litellm_cost",
        lambda used, _model: used.input_tokens / 1000,
    )
    state = ReportState(run_name="streamed")
    hooks = ReportUsageHooks(model="openrouter/z-ai/glm-5.3-flash")
    context = SimpleNamespace(context={"agent_id": "root"})
    agent = SimpleNamespace(name="root")

    def sdk_response(tokens: int, provider_id: str) -> SimpleNamespace:
        return SimpleNamespace(
            response_id=FAKE_RESPONSES_ID,
            usage=_usage(tokens),
            output=[SimpleNamespace(provider_data={"response_id": provider_id})],
        )

    try:
        set_global_report_state(state)
        for tokens, provider_id, charge in [(400, "gen-1", 0.25), (700, "gen-2", 0.5)]:
            # The provider callback runs before the SDK hook, as it does in a
            # real stream; the order must not matter.
            litellm_cost_callback(
                {"response_cost": charge},
                SimpleNamespace(id=provider_id, usage=SimpleNamespace(cost=charge)),
            )
            await hooks.on_llm_end(context, agent, sdk_response(tokens, provider_id))  # type: ignore[arg-type]
        # The SDK hook runs first for this one.
        await hooks.on_llm_end(context, agent, sdk_response(600, "gen-3"))  # type: ignore[arg-type]
        litellm_cost_callback(
            {"response_cost": 0.125},
            SimpleNamespace(id="gen-3", usage=SimpleNamespace(cost=0.125)),
        )
    finally:
        set_global_report_state(None)

    # Each charge replaced its own estimate: 0.25 + 0.5 + 0.125, no estimate on top.
    assert state.get_total_llm_cost() == pytest.approx(0.875)


def test_mixed_provider_prices_keep_estimate_for_unpriced_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        usage_module,
        "_estimate_litellm_cost",
        lambda used, _model: used.input_tokens / 1000,
    )
    ledger = LLMUsageLedger()
    ledger.record(agent_id="a", usage=_usage(400), model="model", response_id="charged")
    ledger.record(agent_id="a", usage=_usage(700), model="model", response_id="unpriced")
    ledger.record_observed_cost(0.2, response_id="charged")
    assert ledger.total_cost == pytest.approx(0.9)

    # A callback can arrive before the SDK usage hook and must still replace
    # only its own estimate. A provider-only call is included as well.
    ledger.record_observed_cost(0.3, response_id="early")
    ledger.record(agent_id="a", usage=_usage(600), model="model", response_id="early")
    ledger.record_observed_cost(0.1, response_id="provider-only")
    assert ledger.total_cost == pytest.approx(1.3)

    restored = LLMUsageLedger()
    restored.hydrate(ledger.to_record())
    assert restored.total_cost == pytest.approx(1.3)
    restored.record(agent_id="a", usage=_usage(200), model="model", response_id="new")
    assert restored.total_cost == pytest.approx(1.5)


def test_sdk_usage_correlates_request_ids_per_agent_and_keeps_upstream_contract_when_ambiguous(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        usage_module,
        "_estimate_litellm_cost",
        lambda used, _model: used.input_tokens / 1000,
    )
    state = ReportState(run_name="pricing")

    # A failed provider attempt is never queued. The retry's success is paired
    # with its own SDK usage, even as another agent completes in between.
    state.note_llm_response("root", "retry-ok")
    state.note_llm_response("child", "child-ok")
    state.record_observed_llm_cost(0.12, response_id="child-ok")
    state.record_sdk_usage(agent_id="child", usage=_usage(500), model="model")
    state.record_observed_llm_cost(0.25, response_id="retry-ok")
    state.record_sdk_usage(agent_id="root", usage=_usage(400), model="model")
    assert state.get_total_llm_cost() == pytest.approx(0.37)

    # A later root call cannot consume the previous one's id.
    state.note_llm_response("root", "next")
    state.record_sdk_usage(agent_id="root", usage=_usage(300), model="model")
    assert state.get_total_llm_cost() == pytest.approx(0.67)

    # Two successes before a single SDK hook are ambiguous (for example,
    # concurrent calls or a response conversion error), so the estimate stays
    # unkeyed. Both charges count and replace it, as upstream does: adding the
    # estimate on top would count the same calls twice and stop a scan early.
    state.note_llm_response("root", "ambiguous-a")
    state.note_llm_response("root", "ambiguous-b")
    state.record_observed_llm_cost(0.1, response_id="ambiguous-a")
    state.record_observed_llm_cost(0.2, response_id="ambiguous-b")
    state.record_sdk_usage(agent_id="root", usage=_usage(500), model="model")
    assert state.get_total_llm_cost() == pytest.approx(0.97)
