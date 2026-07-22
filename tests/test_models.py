"""Tests for LLM model recommendation helpers."""

from __future__ import annotations

import importlib
import os

import pytest
from agents.model_settings import ModelSettings

from strix.config.models import (
    RECOMMENDED_MODEL_NAMES,
    StrixProvider,
    _mirror_api_key_to_provider_env,
    is_recommended_or_frontier_model,
    request_timeout_extra_args,
)


NVIDIA_MODEL = "nvidia_nim/openai/gpt-oss-120b"


@pytest.mark.parametrize("model_name", RECOMMENDED_MODEL_NAMES)
def test_recommended_models_are_accepted(model_name: str) -> None:
    assert is_recommended_or_frontier_model(model_name)


def test_request_timeout_extra_args_positive() -> None:
    assert request_timeout_extra_args(300) == {"timeout": 300}
    assert request_timeout_extra_args(10) == {"timeout": 10}


def test_request_timeout_extra_args_survives_model_settings_json_dump() -> None:
    """The Chat Completions and LiteLLM paths pydantic-serialize ModelSettings for
    their tracing span; a non-JSON-serializable timeout fails every turn there."""
    settings = ModelSettings(extra_args=request_timeout_extra_args(300))
    assert settings.to_json_dict()["extra_args"] == {"timeout": 300}


@pytest.mark.parametrize("value", [None, 0, -1])
def test_request_timeout_extra_args_disabled(value: float | None) -> None:
    assert request_timeout_extra_args(value) is None


def test_nvidia_nim_route_preserves_namespaced_model_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LITELLM_LOCAL_MODEL_COST_MAP", "True")

    model = StrixProvider().get_model(NVIDIA_MODEL)

    assert type(model).__name__ == "LitellmModel"
    assert vars(model)["model"] == NVIDIA_MODEL

    litellm = importlib.import_module("litellm")

    resolved_model, provider, _, api_base = litellm.get_llm_provider(NVIDIA_MODEL)
    assert resolved_model == "openai/gpt-oss-120b"
    assert provider == "nvidia_nim"
    assert api_base == "https://integrate.api.nvidia.com/v1"


def test_nvidia_nim_route_mirrors_generic_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LITELLM_LOCAL_MODEL_COST_MAP", "True")
    monkeypatch.delenv("NVIDIA_NIM_API_KEY", raising=False)

    _mirror_api_key_to_provider_env(NVIDIA_MODEL, "test-key")

    assert os.environ["NVIDIA_NIM_API_KEY"] == "test-key"


@pytest.mark.parametrize(
    ("configured_model", "outbound_model"),
    [
        ("openai/gpt-5.4", "gpt-5.4"),
        ("openai/moonshotai/kimi-k2.5", "moonshotai/kimi-k2.5"),
        ("openai/openai/gpt-oss-120b", "openai/gpt-oss-120b"),
    ],
)
def test_openai_route_strips_only_its_routing_prefix(
    monkeypatch: pytest.MonkeyPatch,
    configured_model: str,
    outbound_model: str,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    model = StrixProvider().get_model(configured_model)

    assert vars(model)["model"] == outbound_model


def test_recommended_models_are_matched_case_insensitively() -> None:
    assert is_recommended_or_frontier_model("Vertex_AI/Gemini-3-Pro-Preview")


@pytest.mark.parametrize(
    "model_name",
    [
        "gpt-5.5",
        "litellm/openai/gpt-5.4-pro",
        "azure_ai/gpt-5.5-pro",
        "bedrock_mantle/openai.gpt-5.5",
        "anthropic/claude-opus-4-8",
        "anthropic.claude-opus-4-8",
        "anthropic/claude-opus-4-7",
        "anthropic/claude-fable-5",
        "anthropic/claude-sonnet-5",
        "vertex_ai/claude-sonnet-5@default",
        "vertex_ai/claude-sonnet-4-6@default",
        "any-llm/anthropic/claude-sonnet-4-6",
        "vertex_ai/gemini-3.1-pro-preview",
        "openrouter/google/gemini-3.1-pro-preview",
        "deepseek/deepseek-v4-pro",
        "deepseek/deepseek-r1-0528",
        "deepseek/deepseek-reasoner",
        "dashscope/qwen3-max-2026-01-23",
        "qwen3.7-max",
        "moonshot/kimi-k2.6",
        "kimi-k2.7-code",
    ],
)
def test_frontier_model_families_are_accepted(model_name: str) -> None:
    assert is_recommended_or_frontier_model(model_name)


@pytest.mark.parametrize(
    "model_name",
    [
        "",
        "openai/gpt-4.1",
        "anthropic/claude-3-5-sonnet-latest",
        "ollama/llama3.1",
        "deepseek/deepseek-chat",
        "custom-ollama/gpt-5-mini-local",
        "custom-provider/claude-opus-4-local",
        "xai/grok-4.5",
        "openrouter/x-ai/grok-4",
        "mistral/mistral-medium-3-5",
        "mistral/magistral-medium-latest",
    ],
)
def test_non_frontier_models_are_rejected(model_name: str) -> None:
    assert not is_recommended_or_frontier_model(model_name)
