"""Tests for provider-reported LLM cost capture."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, call, patch

import httpx
import litellm
import pytest
from litellm.types.utils import LlmProviders
from litellm.utils import ProviderConfigManager

from strix.config.models import (
    _configure_litellm_compatibility,
    _install_openrouter_stream_cost_capture,
)
from strix.llm import request_log
from strix.report.state import (
    ReportState,
    litellm_cost_callback,
    openrouter_stream_cost,
    set_global_report_state,
    streamed_openrouter_costs,
)
from strix.report.usage import LLMUsageLedger


if TYPE_CHECKING:
    from litellm.types.llms.openai import AllMessageValues


@pytest.fixture(autouse=True)
def _clear_streamed_costs() -> None:
    streamed_openrouter_costs.clear()


def test_streaming_logging_stays_enabled_for_cost_callback() -> None:
    with (
        patch.object(litellm, "disable_streaming_logging", new=True),
        patch("strix.config.models._register_litellm_cost_callback") as register,
    ):
        _configure_litellm_compatibility()
        assert litellm.disable_streaming_logging is False
        register.assert_called_once_with()


def test_cost_callback_reads_openrouter_stream_usage_cost() -> None:
    report_state = MagicMock()
    response = SimpleNamespace(
        usage=SimpleNamespace(cost=1.2345),
        _hidden_params={},
    )

    with patch("strix.report.state.get_global_report_state", return_value=report_state):
        litellm_cost_callback({"response_cost": None}, response)

    report_state.record_observed_llm_cost.assert_called_once_with(1.2345)


def test_cost_callback_reads_usage_cost_from_mapping_response() -> None:
    report_state = MagicMock()
    response = {"usage": {"cost": 0.125}}

    with patch("strix.report.state.get_global_report_state", return_value=report_state):
        litellm_cost_callback({}, response)

    report_state.record_observed_llm_cost.assert_called_once_with(0.125)


def test_cost_callback_reads_byok_upstream_inference_cost() -> None:
    report_state = MagicMock()
    response = SimpleNamespace(
        usage=SimpleNamespace(
            cost=0,
            is_byok=True,
            cost_details=SimpleNamespace(upstream_inference_cost=6.75e-06),
        ),
        _hidden_params={},
    )

    with patch("strix.report.state.get_global_report_state", return_value=report_state):
        litellm_cost_callback({"response_cost": None}, response)

    report_state.record_observed_llm_cost.assert_called_once_with(6.75e-06)


def test_cost_callback_sums_usage_cost_and_upstream_inference_cost() -> None:
    report_state = MagicMock()
    response = {
        "usage": {
            "cost": 0.01,
            "is_byok": True,
            "cost_details": {"upstream_inference_cost": 0.2},
        }
    }

    with patch("strix.report.state.get_global_report_state", return_value=report_state):
        litellm_cost_callback({}, response)

    report_state.record_observed_llm_cost.assert_called_once_with(pytest.approx(0.21))


def test_cost_callback_ignores_upstream_cost_for_non_byok_responses() -> None:
    report_state = MagicMock()
    response = {
        "usage": {
            "cost": 0.05,
            "is_byok": False,
            "cost_details": {"upstream_inference_cost": 0.04},
        }
    }

    with patch("strix.report.state.get_global_report_state", return_value=report_state):
        litellm_cost_callback({}, response)

    report_state.record_observed_llm_cost.assert_called_once_with(0.05)


def test_cost_callback_estimates_cost_with_provider_prefixed_model() -> None:
    report_state = MagicMock()
    response = {"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
    kwargs = {
        "response_cost": None,
        "model": "anthropic/claude-sonnet-4.5",
        "litellm_params": {"custom_llm_provider": "openrouter"},
    }

    def fake_completion_cost(**kwargs: object) -> float:
        if kwargs["model"] == "openrouter/anthropic/claude-sonnet-4.5":
            return 0.5
        raise ValueError(kwargs["model"])

    with (
        patch("strix.report.state.get_global_report_state", return_value=report_state),
        patch("litellm.completion_cost", side_effect=fake_completion_cost),
    ):
        litellm_cost_callback(kwargs, response)

    report_state.record_observed_llm_cost.assert_called_once_with(0.5)


def test_cost_callback_estimates_cost_with_bare_model_fallback() -> None:
    report_state = MagicMock()
    response = {"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
    kwargs = {
        "response_cost": None,
        "model": "openai/gpt-4o-mini",
        "litellm_params": {"custom_llm_provider": "openrouter"},
    }

    def fake_completion_cost(**kwargs: object) -> float:
        if kwargs["model"] == "openai/gpt-4o-mini":
            return 0.025
        raise ValueError(kwargs["model"])

    with (
        patch("strix.report.state.get_global_report_state", return_value=report_state),
        patch("litellm.completion_cost", side_effect=fake_completion_cost),
    ):
        litellm_cost_callback(kwargs, response)

    report_state.record_observed_llm_cost.assert_called_once_with(0.025)


def test_cost_callback_records_nothing_when_no_cost_available() -> None:
    report_state = MagicMock()
    response = {"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}

    with (
        patch("strix.report.state.get_global_report_state", return_value=report_state),
        patch("litellm.completion_cost", side_effect=ValueError("unknown model")),
    ):
        litellm_cost_callback({"response_cost": None, "model": "x/y"}, response)

    report_state.record_observed_llm_cost.assert_not_called()


def test_openrouter_stream_cost_extracts_plain_and_byok_totals() -> None:
    assert openrouter_stream_cost({"cost": 0.003168}) == pytest.approx(0.003168)
    assert openrouter_stream_cost(
        {"cost": 0.01, "is_byok": True, "cost_details": {"upstream_inference_cost": 0.2}}
    ) == pytest.approx(0.21)
    # Upstream cost is only added for BYOK responses.
    assert openrouter_stream_cost(
        {"cost": 0.05, "is_byok": False, "cost_details": {"upstream_inference_cost": 0.04}}
    ) == pytest.approx(0.05)
    assert openrouter_stream_cost({"prompt_tokens": 10}) is None
    assert openrouter_stream_cost(None) is None


def test_cost_callback_recovers_streamed_openrouter_cost_by_response_id() -> None:
    report_state = MagicMock()
    streamed_openrouter_costs.remember("gen-abc", {"cost": 0.42})
    # LiteLLM strips cost from the rebuilt streamed usage; only the id survives.
    response = SimpleNamespace(id="gen-abc", usage=SimpleNamespace(cost=None), _hidden_params={})

    with (
        patch("strix.report.state.get_global_report_state", return_value=report_state),
        patch("litellm.completion_cost", side_effect=ValueError("unknown model")),
    ):
        litellm_cost_callback({"response_cost": None, "model": "moonshotai/kimi-k3"}, response)

    report_state.record_observed_llm_cost.assert_called_once_with(0.42)
    # The entry is consumed so a later response cannot double-count it.
    assert streamed_openrouter_costs.take(response) is None


def test_streamed_openrouter_cost_prefers_provider_report_over_estimate() -> None:
    report_state = MagicMock()
    streamed_openrouter_costs.remember("gen-xyz", {"cost": 0.9})
    response = SimpleNamespace(
        id="gen-xyz",
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15),
        _hidden_params={},
    )

    with (
        patch("strix.report.state.get_global_report_state", return_value=report_state),
        patch("litellm.completion_cost", return_value=0.1) as estimate,
    ):
        litellm_cost_callback({"response_cost": None, "model": "moonshotai/kimi-k3"}, response)

    report_state.record_observed_llm_cost.assert_called_once_with(0.9)
    estimate.assert_not_called()


def test_streamed_openrouter_costs_ignores_entries_without_cost() -> None:
    streamed_openrouter_costs.remember("gen-none", {"prompt_tokens": 10})
    streamed_openrouter_costs.remember("", {"cost": 0.5})
    assert streamed_openrouter_costs.take(SimpleNamespace(id="gen-none")) is None


def test_streamed_openrouter_costs_cleared_on_new_run() -> None:
    streamed_openrouter_costs.remember("gen-stale", {"cost": 0.7})
    try:
        set_global_report_state(ReportState.__new__(ReportState))
        assert streamed_openrouter_costs.take(SimpleNamespace(id="gen-stale")) is None
    finally:
        set_global_report_state(None)


def test_openrouter_stream_handler_records_cost() -> None:
    _install_openrouter_stream_cost_capture()
    # Resolve the config the way LiteLLM does in production so we prove the
    # override is actually reachable through provider resolution, not just as a
    # directly-constructed class.
    config = ProviderConfigManager.get_provider_chat_config(
        model="moonshotai/kimi-k3", provider=LlmProviders.OPENROUTER
    )
    assert config is not None
    assert type(config).__name__ == "_StrixOpenrouterConfig"
    handler = config.get_model_response_iterator(streaming_response=iter([]), sync_stream=True)

    chunk = {
        "id": "gen-stream",
        "created": 1,
        "model": "moonshotai/kimi-k3",
        "choices": [{"index": 0, "delta": {"content": None}}],
        "usage": {"prompt_tokens": 89, "completion_tokens": 138, "cost": 0.0035055},
    }
    handler.chunk_parser(chunk)

    assert streamed_openrouter_costs.take(SimpleNamespace(id="gen-stream")) == pytest.approx(
        0.0035055
    )


def test_openrouter_tallies_provider() -> None:
    _install_openrouter_stream_cost_capture()
    config = ProviderConfigManager.get_provider_chat_config(
        model="z-ai/glm-5.3", provider=LlmProviders.OPENROUTER
    )
    assert config is not None
    handler = config.get_model_response_iterator(streaming_response=iter([]), sync_stream=True)
    report_state = MagicMock()
    usage = {
        "prompt_tokens": 1000,
        "completion_tokens": 10,
        "cost": 0.002,
        "prompt_tokens_details": {"cached_tokens": 900},
    }
    with patch("strix.report.state.get_global_report_state", return_value=report_state):
        handler.chunk_parser(
            {
                "id": "gen-a",
                "created": 1,
                "model": "z-ai/glm-5.3",
                "provider": "Together",
                "choices": [{"index": 0, "delta": {"content": None}}],
                "usage": usage,
            }
        )
        # Non-streamed replies (LLM_DISABLE_STREAMING) carry the same fields.
        reply = {
            "choices": [{"message": {"role": "assistant"}}],
            "provider": "Together",
            "usage": usage,
        }
        config.transform_response(
            "z-ai/glm-5.3",
            httpx.Response(200, json=reply),
            litellm.ModelResponse(),
            MagicMock(),
            {},
            [],
            {},
            {},
            None,
        )

    tally = call("Together", agent_id=None, input_tokens=1000, cached_tokens=900, cost=0.002)
    assert report_state.record_llm_provider.call_args_list == [tally, tally]


def test_provider_tally_survives_run_record_round_trip() -> None:
    ledger = LLMUsageLedger()
    for input_tokens, cached_tokens, cost in [(1000, 900, 0.002), (500, 0, 0.001)]:
        ledger.record_provider(
            "Together",
            agent_id=None,
            input_tokens=input_tokens,
            cached_tokens=cached_tokens,
            cost=cost,
            cache_block_tokens=128,
        )

    restored = LLMUsageLedger()
    restored.hydrate(ledger.to_record())

    assert restored.to_record()["providers"] == {
        "Together": {
            "requests": 2,
            "input_tokens": 1500,
            "cached_tokens": 900,
            "cost": 0.003,
            "cache_misses": 0,
            "missed_tokens": 0,
        }
    }


def test_provider_tally_counts_cache_misses_per_agent() -> None:
    ledger = LLMUsageLedger()
    calls = [
        ("Z.AI", "a1", 1000, 0),  # first call: nothing to miss
        ("Z.AI", "a1", 1200, 960),  # 40 short of the previous 1000: within a block
        ("DeepInfra", "a1", 1500, 200),  # 1000 of the previous 1200 lost
        ("Z.AI", "a2", 800, 0),  # another agent's first call
        ("Z.AI", "a1", 600, 0),  # prompt shrank: compaction, not a miss
    ]
    for provider, agent_id, input_tokens, cached_tokens in calls:
        ledger.record_provider(
            provider,
            agent_id=agent_id,
            input_tokens=input_tokens,
            cached_tokens=cached_tokens,
            cost=0.0,
            cache_block_tokens=128,
        )

    providers = ledger.to_record()["providers"]
    assert providers["DeepInfra"]["cache_misses"] == 1
    assert providers["DeepInfra"]["missed_tokens"] == 1000
    assert providers["Z.AI"]["cache_misses"] == 0


def test_openrouter_request_carries_agent_session_id() -> None:
    _install_openrouter_stream_cost_capture()
    config = ProviderConfigManager.get_provider_chat_config(
        model="moonshotai/kimi-k3", provider=LlmProviders.OPENROUTER
    )
    assert config is not None
    messages: list[AllMessageValues] = [{"role": "user", "content": "hi"}]

    def body() -> dict[str, Any]:
        return config.transform_request("moonshotai/kimi-k3", messages, {}, {}, {})

    assert "session_id" not in body()
    token = request_log.bind_call_context("a1b2c3d4", "root")
    try:
        assert "session_id" not in body()
        with patch("strix.config.models.load_settings") as settings:
            settings.return_value.llm.openrouter_sticky_sessions = True
            session_id = body()["session_id"]
            assert str(uuid.UUID(session_id)) == session_id
            assert body()["session_id"] == session_id
    finally:
        request_log.reset_call_context(token)
