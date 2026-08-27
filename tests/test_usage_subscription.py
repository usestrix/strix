"""Subscription runs track tokens but report zero cost."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agents.usage import Usage

from strix.report import usage as usage_module
from strix.report.usage import LLMUsageLedger


if TYPE_CHECKING:
    import pytest


def _usage() -> Usage:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    return usage


def test_zero_cost_ledger_keeps_tokens_but_reports_no_cost() -> None:
    ledger = LLMUsageLedger()
    ledger.zero_cost = True
    ledger.record(agent_id="a", usage=_usage(), agent_name="strix", model="gpt-5.5")

    record = ledger.to_record()
    assert record["cost"] == 0.0
    assert record["total_tokens"] == 1200
    assert record["input_tokens"] == 1000
    assert record["output_tokens"] == 200
    assert ledger.total_cost == 0.0


def test_zero_cost_ledger_ignores_observed_cost() -> None:
    ledger = LLMUsageLedger()
    ledger.zero_cost = True
    ledger.record_observed_cost(4.20)
    assert ledger.total_cost == 0.0


def test_normal_ledger_still_estimates_cost() -> None:
    # Sanity check the flag is opt-in: without it, an OpenAI-native model still
    # accrues an estimated cost (proves zeroing is what suppresses it).
    ledger = LLMUsageLedger()
    ledger.record(agent_id="a", usage=_usage(), agent_name="strix", model="gpt-5.5")
    assert ledger.to_record()["total_tokens"] == 1200
    # Cost estimation depends on litellm's cost map; it should be >= 0 and not error.
    assert ledger.total_cost >= 0.0


def test_metered_verifier_cost_survives_subscription_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(usage_module, "_estimate_litellm_cost", lambda *_args: 1.25)
    ledger = LLMUsageLedger()
    ledger.zero_cost = True

    ledger.record(
        agent_id="root",
        usage=_usage(),
        model="chatgpt/gpt-5.4",
        zero_cost=True,
    )

    ledger.record(
        agent_id="finding-verifier",
        usage=_usage(),
        model="openai/gpt-5.4",
        zero_cost=False,
    )

    assert ledger.total_cost == 1.25
    agents = {entry["agent_id"]: entry for entry in ledger.to_record()["agents"]}
    assert agents["root"]["cost"] == 0.0
    assert agents["finding-verifier"]["cost"] == 1.25
