from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import patch

import litellm
import pytest
from agents.usage import Usage, serialize_usage
from pydantic import ValidationError

from strix.config import loader
from strix.config.settings import LlmSettings
from strix.core.hooks import recomputed_budget_flags
from strix.report.pricing import resolve_litellm_model
from strix.report.state import ReportState
from strix.report.usage import LLMUsageLedger


if TYPE_CHECKING:
    from pathlib import Path


PRICE_ENV = (
    "STRIX_LLM_INPUT_COST_PER_MTOK",
    "STRIX_LLM_OUTPUT_COST_PER_MTOK",
    "STRIX_LLM_CACHED_INPUT_COST_PER_MTOK",
)


@pytest.fixture(autouse=True)
def _isolated_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in PRICE_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("STRIX_LLM", "gateway/unpriced-model")
    monkeypatch.setattr(loader, "_override", tmp_path / "missing.json")
    monkeypatch.setattr(loader, "_cached", None)


def _usage(input_tokens: int, output_tokens: int = 0, cached_tokens: int = 0) -> Usage:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = input_tokens
    usage.output_tokens = output_tokens
    usage.total_tokens = input_tokens + output_tokens
    usage.input_tokens_details.cached_tokens = cached_tokens
    return usage


def _configure_manual_model(
    monkeypatch: pytest.MonkeyPatch,
    model: str,
    *,
    input_rate: float,
    output_rate: float | None = None,
    cached_rate: float | None = None,
) -> None:
    monkeypatch.setenv("STRIX_LLM", model)
    monkeypatch.setenv("STRIX_LLM_INPUT_COST_PER_MTOK", str(input_rate))
    if output_rate is None:
        monkeypatch.delenv("STRIX_LLM_OUTPUT_COST_PER_MTOK", raising=False)
    else:
        monkeypatch.setenv("STRIX_LLM_OUTPUT_COST_PER_MTOK", str(output_rate))
    if cached_rate is None:
        monkeypatch.delenv("STRIX_LLM_CACHED_INPUT_COST_PER_MTOK", raising=False)
    else:
        monkeypatch.setenv("STRIX_LLM_CACHED_INPUT_COST_PER_MTOK", str(cached_rate))
    monkeypatch.setattr(loader, "_cached", None)


def test_resolves_common_bare_model_names() -> None:
    resolve_litellm_model.cache_clear()
    assert resolve_litellm_model("deepseek-v4-flash") == "deepseek/deepseek-v4-flash"
    assert resolve_litellm_model("openai/deepseek-v4-flash") == "deepseek/deepseek-v4-flash"
    # LiteLLM prices grok-4.5 identically under xai/, perplexity/xai/ and
    # openrouter/x-ai/, so the resolver may return any of them; the contract
    # is a provider-qualified name LiteLLM can price.
    grok = resolve_litellm_model("grok-4.5")
    assert grok is not None
    assert grok.endswith("/grok-4.5")
    assert grok in litellm.model_cost
    # MiniMax-M3 is sold by several LiteLLM providers at different prices, so
    # the resolver must not guess from its bare name. A provider-qualified
    # model remains deterministic.
    assert resolve_litellm_model("minimax/MiniMax-M3") == "minimax/MiniMax-M3"


def test_resolver_returns_none_for_unresolvable_model() -> None:
    resolve_litellm_model.cache_clear()
    assert resolve_litellm_model("provider/not-a-real-model") is None


def test_ledger_uses_estimate_when_routed_provider_reports_no_cost() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()

    with patch("litellm.completion_cost", return_value=0.42):
        ledger.record(agent_id="a", usage=usage, model="openai/deepseek-v4-flash")

    assert ledger.total_cost == 0.42


def test_ledger_prefers_observed_cost_over_estimate() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()

    with patch("litellm.completion_cost", return_value=0.42):
        ledger.record(agent_id="a", usage=usage, model="openai/deepseek-v4-flash")
    ledger.record_observed_cost(0.17)

    assert ledger.total_cost == 0.17


def test_unpriced_model_without_manual_rates_costs_zero() -> None:
    ledger = LLMUsageLedger()

    ledger.record(agent_id="a", usage=_usage(1000, 200), model="gateway/unpriced-model")

    assert ledger.total_cost == 0.0


def test_manual_rates_price_usage_and_override_observed_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM_INPUT_COST_PER_MTOK", "2")
    monkeypatch.setenv("STRIX_LLM_OUTPUT_COST_PER_MTOK", "8")
    ledger = LLMUsageLedger()

    ledger.record(agent_id="a", usage=_usage(1000, 200), model="gateway/unpriced-model")
    ledger.record_observed_cost(0.17)

    assert ledger.total_cost == 0.0036
    assert ledger.to_record()["agents"][0]["cost"] == 0.0036


def test_manual_rates_from_config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "env": {
                    "STRIX_LLM_INPUT_COST_PER_MTOK": "2",
                    "STRIX_LLM_OUTPUT_COST_PER_MTOK": "8",
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(loader, "_override", path)
    ledger = LLMUsageLedger()

    ledger.record(agent_id="a", usage=_usage(1000, 200), model="gateway/unpriced-model")

    assert ledger.total_cost == 0.0036


def test_manual_rates_only_price_the_configured_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM_INPUT_COST_PER_MTOK", "2")
    monkeypatch.setenv("STRIX_LLM_OUTPUT_COST_PER_MTOK", "8")
    ledger = LLMUsageLedger()

    ledger.record(agent_id="a", usage=_usage(1000, 200), model="gateway/unpriced-model")
    with patch("litellm.completion_cost", return_value=0.42):
        ledger.record(agent_id="dedupe", usage=_usage(500, 50), model="deepseek/deepseek-v4-flash")
    record = ledger.to_record()

    assert ledger.total_cost == 0.4236
    assert {agent["agent_id"]: agent["cost"] for agent in record["agents"]} == {
        "a": 0.0036,
        "dedupe": 0.42,
    }


def test_cached_tokens_fall_back_to_input_rate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM_INPUT_COST_PER_MTOK", "5")
    monkeypatch.setenv("STRIX_LLM_OUTPUT_COST_PER_MTOK", "7")
    ledger = LLMUsageLedger()

    ledger.record(
        agent_id="a", usage=_usage(10, 1, cached_tokens=2), model="gateway/unpriced-model"
    )

    assert ledger.total_cost == 0.000057


def test_hydrated_usage_uses_configured_rates_not_persisted_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM_INPUT_COST_PER_MTOK", "2")
    monkeypatch.setenv("STRIX_LLM_OUTPUT_COST_PER_MTOK", "8")
    original = LLMUsageLedger()
    original.record(agent_id="a", usage=_usage(1000, 200), model="gateway/unpriced-model")
    persisted = original.to_record()
    persisted.pop("model_usage")
    persisted["cost"] = 42.0
    persisted["agents"][0]["cost"] = 42.0
    hydrated = LLMUsageLedger()

    hydrated.hydrate(persisted)

    assert hydrated.total_cost == 0.0036


@pytest.mark.parametrize(
    ("model_b_rate", "expected", "budget", "expected_flags"),
    [
        (8.0, 0.01, 0.012, (False, False)),
        (0.5, 0.0025, 0.0023, (True, True)),
    ],
)
def test_resumed_agent_model_switch_preserves_historical_cost(
    model_b_rate: float,
    expected: float,
    budget: float,
    expected_flags: tuple[bool, bool],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_manual_model(monkeypatch, "gateway/model-a", input_rate=2)
    original = LLMUsageLedger()
    original.record(agent_id="root", usage=_usage(1000), model="gateway/model-a")

    _configure_manual_model(monkeypatch, "gateway/model-b", input_rate=model_b_rate)
    resumed = LLMUsageLedger()
    resumed.hydrate(original.to_record())
    resumed.record(agent_id="root", usage=_usage(1000), model="gateway/model-b")

    assert resumed.total_cost == expected
    assert resumed.to_record()["cost"] == expected
    assert recomputed_budget_flags(expected, budget, interactive=False) == expected_flags


def test_repeated_model_switches_keep_each_models_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_manual_model(monkeypatch, "gateway/model-a", input_rate=2)
    first = LLMUsageLedger()
    first.record(agent_id="root", usage=_usage(1000), model="gateway/model-a")

    _configure_manual_model(monkeypatch, "gateway/model-b", input_rate=8)
    second = LLMUsageLedger()
    second.hydrate(first.to_record())
    second.record(agent_id="root", usage=_usage(1000), model="gateway/model-b")

    _configure_manual_model(monkeypatch, "gateway/model-a", input_rate=2)
    third = LLMUsageLedger()
    third.hydrate(second.to_record())
    third.record(agent_id="root", usage=_usage(1000), model="gateway/model-a")

    assert third.total_cost == 0.012
    record = third.to_record()
    assert len(record["agents"]) == 1
    assert record["agents"][0]["input_tokens"] == 3000
    assert record["model_usage"]["version"] == 1
    assert len(record["model_usage"]["entries"]) == 2


def test_model_usage_round_trips_for_root_child_and_dedupe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_manual_model(monkeypatch, "gateway/model-a", input_rate=2)
    original = LLMUsageLedger()
    for agent_id in ("root", "child"):
        original.record(agent_id=agent_id, usage=_usage(1000), model="gateway/model-a")
    with patch("litellm.completion_cost", return_value=0.42):
        original.record(agent_id="dedupe", usage=_usage(500), model="deepseek/deepseek-v4-flash")

    _configure_manual_model(monkeypatch, "gateway/model-b", input_rate=8)
    resumed = LLMUsageLedger()
    resumed.hydrate(original.to_record())
    for agent_id in ("root", "child"):
        resumed.record(agent_id=agent_id, usage=_usage(1000), model="gateway/model-b")

    assert resumed.total_cost == 0.44
    persisted = resumed.to_record()
    hydrated = LLMUsageLedger()
    hydrated.hydrate(persisted)
    assert hydrated.to_record() == persisted
    assert {entry["agent_id"] for entry in persisted["agents"]} == {
        "root",
        "child",
        "dedupe",
    }


def test_model_switch_uses_matching_cached_token_rates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_manual_model(monkeypatch, "gateway/model-a", input_rate=5, cached_rate=1)
    original = LLMUsageLedger()
    original.record(
        agent_id="root",
        usage=_usage(10, cached_tokens=4),
        model="gateway/model-a",
    )

    _configure_manual_model(monkeypatch, "gateway/model-b", input_rate=10, cached_rate=2)
    resumed = LLMUsageLedger()
    resumed.hydrate(original.to_record())
    resumed.record(
        agent_id="root",
        usage=_usage(10, cached_tokens=4),
        model="gateway/model-b",
    )

    assert resumed.total_cost == 0.000102


def test_legacy_agent_record_freezes_cost_when_model_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_usage = serialize_usage(_usage(1000))
    legacy_usage.update(
        {
            "cost": 0.002,
            "agents": [
                {
                    **serialize_usage(_usage(1000)),
                    "agent_id": "root",
                    "agent_name": "root",
                    "model": "gateway/model-a",
                    "cost": 0.002,
                }
            ],
        }
    )
    _configure_manual_model(monkeypatch, "gateway/model-b", input_rate=8)
    resumed = LLMUsageLedger()

    resumed.hydrate(legacy_usage)
    resumed.record(agent_id="root", usage=_usage(1000), model="gateway/model-b")

    assert resumed.total_cost == 0.01


def test_legacy_same_model_resume_reprices_without_double_counting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_usage = {
        **serialize_usage(_usage(1000)),
        "cost": 42.0,
        "agents": [
            {
                **serialize_usage(_usage(1000)),
                "agent_id": "root",
                "agent_name": "root",
                "model": "gateway/model-a",
                "cost": 42.0,
            }
        ],
    }
    _configure_manual_model(monkeypatch, "gateway/model-a", input_rate=2)
    resumed = LLMUsageLedger()

    resumed.hydrate(legacy_usage)
    resumed.record(agent_id="root", usage=_usage(1000), model="gateway/model-a")

    record = resumed.to_record()
    assert resumed.total_cost == 0.004
    assert record["input_tokens"] == 2000
    assert record["model_usage"]["entries"][0]["input_tokens"] == 2000


def test_observed_cost_precedence_survives_model_switch() -> None:
    ledger = LLMUsageLedger()
    with patch("litellm.completion_cost", side_effect=[0.42, 0.17]):
        ledger.record(agent_id="root", usage=_usage(1000), model="deepseek/deepseek-v4-flash")
        ledger.record(agent_id="root", usage=_usage(1000), model="openai/gpt-4o")
    ledger.record_observed_cost(0.25)

    assert ledger.total_cost == 0.25


def test_zero_cost_model_switch_remains_free(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_manual_model(monkeypatch, "gateway/model-a", input_rate=2)
    ledger = LLMUsageLedger()
    ledger.zero_cost = True
    ledger.record(agent_id="root", usage=_usage(1000), model="gateway/model-a")
    _configure_manual_model(monkeypatch, "gateway/model-b", input_rate=8)
    ledger.record(agent_id="root", usage=_usage(1000), model="gateway/model-b")

    assert ledger.total_cost == 0.0


def test_run_record_and_live_budget_agree_after_model_switch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _configure_manual_model(monkeypatch, "gateway/model-a", input_rate=2)
    initial = ReportState(run_name="model-switch")
    initial.record_sdk_usage(agent_id="root", usage=_usage(1000), model="gateway/model-a")

    _configure_manual_model(monkeypatch, "gateway/model-b", input_rate=8)
    resumed = ReportState(run_name="model-switch")
    resumed.hydrate_from_run_dir()
    resumed.record_sdk_usage(agent_id="root", usage=_usage(1000), model="gateway/model-b")

    persisted = json.loads((resumed.get_run_dir() / "run.json").read_text())
    assert resumed.get_total_llm_cost() == 0.01
    assert persisted["llm_usage"]["cost"] == 0.01
    assert recomputed_budget_flags(resumed.get_total_llm_cost(), 0.012, interactive=False) == (
        False,
        False,
    )


@pytest.mark.parametrize("value", ["invalid", "-1", "nan", "inf"])
def test_invalid_manual_rate_is_rejected(value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM_INPUT_COST_PER_MTOK", value)
    with pytest.raises(ValidationError):
        LlmSettings()


def test_zero_cost_overrides_manual_rates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM_INPUT_COST_PER_MTOK", "10")
    ledger = LLMUsageLedger()
    ledger.zero_cost = True

    ledger.record(agent_id="a", usage=_usage(1000), model="gateway/unpriced-model")

    assert ledger.total_cost == 0.0


def test_hydrated_estimate_continues_accumulating_new_estimates() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()
    ledger.hydrate({"cost": 0.42})

    with patch("litellm.completion_cost", return_value=0.17):
        ledger.record(agent_id="a", usage=usage, model="openai/deepseek-v4-flash")

    assert ledger.total_cost == 0.59


def test_zero_cost_disables_both_observed_and_estimated_costs() -> None:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = 1000
    usage.output_tokens = 200
    usage.total_tokens = 1200
    ledger = LLMUsageLedger()
    ledger.zero_cost = True

    with patch("litellm.completion_cost", return_value=0.42) as estimate:
        ledger.record(agent_id="a", usage=usage, model="deepseek-v4-flash")
        ledger.record_observed_cost(1.0)

    estimate.assert_not_called()
    assert ledger.total_cost == 0.0


def test_resolver_uses_provider_when_bare_entry_has_one() -> None:
    original = litellm.model_cost
    litellm.model_cost = {
        "example": {
            "litellm_provider": "example-provider",
            "input_cost_per_token": 1.0,
            "output_cost_per_token": 2.0,
        }
    }
    try:
        resolve_litellm_model.cache_clear()
        assert resolve_litellm_model("example") == "example-provider/example"
    finally:
        litellm.model_cost = original
        resolve_litellm_model.cache_clear()


def test_resolver_does_not_guess_between_differently_priced_providers() -> None:
    original = litellm.model_cost
    litellm.model_cost = {
        "provider-a/example": {
            "input_cost_per_token": 1.0,
            "output_cost_per_token": 2.0,
        },
        "provider-b/example": {
            "input_cost_per_token": 3.0,
            "output_cost_per_token": 4.0,
        },
    }
    try:
        resolve_litellm_model.cache_clear()
        assert resolve_litellm_model("example") is None
    finally:
        litellm.model_cost = original
        resolve_litellm_model.cache_clear()
