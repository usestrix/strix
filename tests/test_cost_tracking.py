"""Tests for provider-reported LLM cost capture."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import litellm
import pytest
from litellm.types.utils import LlmProviders
from litellm.utils import ProviderConfigManager

from strix.config.models import (
    _configure_litellm_compatibility,
    _install_openrouter_stream_cost_capture,
)
from strix.report.state import (
    ReportState,
    litellm_cost_callback,
    openrouter_stream_cost,
    set_global_report_state,
    streamed_openrouter_costs,
)


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
        if kwargs["model"] == "gpt-4o-mini":
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
    set_global_report_state(ReportState.__new__(ReportState))
    assert streamed_openrouter_costs.take(SimpleNamespace(id="gen-stale")) is None


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
