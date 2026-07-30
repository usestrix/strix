"""Tests for LLM model recommendation helpers."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

import litellm
import pytest
from agents.model_settings import ModelSettings

from strix.config import (
    ProviderDisabledError,
    apply_config_override,
    reset_settings_cache,
    save_custom_provider,
    set_custom_provider_enabled,
    update_config_env,
)
from strix.config.models import (
    RECOMMENDED_MODEL_NAMES,
    StrixProvider,
    configure_sdk_model_defaults,
    is_recommended_or_frontier_model,
    request_timeout_extra_args,
    resolve_model_config,
)
from strix.config.settings import LlmSettings, Settings


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def isolated_model_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "STRIX_LLM",
        "LLM_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENROUTER_API_KEY",
        "LLM_API_BASE",
        "OPENAI_BASE_URL",
        "OLLAMA_API_BASE",
        "AZURE_API_BASE",
        "AZURE_API_KEY",
        "AZURE_API_VERSION",
    ):
        monkeypatch.delenv(key, raising=False)
    apply_config_override(tmp_path / "config.json")
    reset_settings_cache()


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


def test_recommended_models_are_matched_case_insensitively() -> None:
    assert is_recommended_or_frontier_model("Vertex_AI/Gemini-3-Pro-Preview")


@pytest.mark.parametrize(
    "model_name",
    [
        "gpt-5.5",
        "chatgpt/gpt-5.4",
        "litellm/openai/gpt-5.4-pro",
        "azure_ai/gpt-5.5-pro",
        "bedrock_mantle/openai.gpt-5.5",
        "anthropic/claude-opus-5",
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
        "dashscope/qwen3.8-max",
        "moonshot/kimi-k2.6",
        "kimi-k2.7-code",
        "moonshot/kimi-k3",
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


@pytest.mark.usefixtures("isolated_model_config")
def test_openai_key_is_not_used_for_anthropic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "openai-only")
    settings = Settings(llm=LlmSettings(STRIX_LLM="anthropic/claude"))

    resolved = resolve_model_config(settings)

    assert resolved.provider == "anthropic"
    assert resolved.api_key is None
    assert "ANTHROPIC_API_KEY" not in os.environ


@pytest.mark.usefixtures("isolated_model_config")
def test_persisted_provider_key_is_bound_to_litellm_model() -> None:
    update_config_env({"ANTHROPIC_API_KEY": "anthropic-key"})
    settings = Settings(llm=LlmSettings(STRIX_LLM="anthropic/claude"))

    model = StrixProvider("anthropic/claude", settings).get_model("anthropic/claude")

    assert model.api_key == "anthropic-key"  # type: ignore[attr-defined]


@pytest.mark.usefixtures("isolated_model_config")
def test_provider_resolves_each_requested_model_route() -> None:
    update_config_env(
        {
            "ANTHROPIC_API_KEY": "primary-key",
            "OPENROUTER_API_KEY": "alternate-key",
        }
    )
    settings = Settings(llm=LlmSettings(STRIX_LLM="anthropic/claude"))

    model = StrixProvider(settings=settings).get_model("openrouter/test-model")

    assert model.api_key == "alternate-key"  # type: ignore[attr-defined]


@pytest.mark.usefixtures("isolated_model_config")
def test_legacy_key_is_bound_to_primary_model_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LLM_API_KEY", "legacy-key")
    settings = Settings(llm=LlmSettings(STRIX_LLM="anthropic/claude"))

    resolved = resolve_model_config(settings)

    assert resolved.provider == "anthropic"
    assert resolved.api_key == "legacy-key"


@pytest.mark.usefixtures("isolated_model_config")
def test_persisted_generic_key_is_not_rebound_by_process_model_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    update_config_env(
        {
            "STRIX_LLM": "anthropic/claude",
            "LLM_API_KEY": "persisted-anthropic-key",
        }
    )
    monkeypatch.setenv("STRIX_LLM", "openrouter/model")
    settings = Settings(llm=LlmSettings(STRIX_LLM="openrouter/model"))

    assert resolve_model_config(settings).api_key is None


@pytest.mark.usefixtures("isolated_model_config")
def test_explicit_route_key_is_bound_to_its_provider() -> None:
    settings = Settings(llm=LlmSettings(STRIX_LLM="openai/gpt-5.4"))

    model = StrixProvider(
        "deepseek/cheap",
        settings,
        api_key="route-key",
    ).get_model("deepseek/cheap")

    assert model.api_key == "route-key"  # type: ignore[attr-defined]


@pytest.mark.usefixtures("isolated_model_config")
def test_model_override_does_not_reuse_configured_provider_generic_key() -> None:
    os.environ["LLM_API_KEY"] = "primary-model-key"
    update_config_env(
        {
            "STRIX_LLM": "openai/gpt-5.4",
            "LLM_API_BASE": "https://openai-compatible.example",
        }
    )
    settings = Settings(
        llm=LlmSettings.model_validate(
            {
                "model": "openai/gpt-5.4",
                "api_base": "https://openai-compatible.example",
            }
        )
    )

    resolved = resolve_model_config(settings, "anthropic/claude")

    assert resolved.provider == "anthropic"
    assert resolved.api_key is None
    assert resolved.api_base is None


@pytest.mark.usefixtures("isolated_model_config")
def test_programmatic_legacy_settings_still_bind_to_requested_route() -> None:
    settings = Settings(
        llm={
            "model": "anthropic/claude",
            "api_key": "programmatic-key",
            "api_base": "https://programmatic.example/v1",
        }
    )

    resolved = resolve_model_config(settings)

    assert resolved.api_key == "programmatic-key"
    assert resolved.api_base == "https://programmatic.example/v1"


@pytest.mark.usefixtures("isolated_model_config")
def test_programmatic_legacy_settings_do_not_cross_provider_override() -> None:
    settings = Settings(
        llm={
            "model": "openai/gpt-5",
            "api_key": "openai-programmatic-key",
            "api_base": "https://openai-programmatic.example/v1",
        }
    )

    resolved = resolve_model_config(settings, "anthropic/claude")

    assert resolved.api_key is None
    assert resolved.api_base is None


@pytest.mark.usefixtures("isolated_model_config")
def test_litellm_base_url_precedes_special_provider_route_aliases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LITELLM_BASE_URL", "https://litellm-proxy.example/v1")
    settings = Settings(llm={"model": "litellm/openai/gpt-5"})

    resolved = resolve_model_config(settings)

    assert resolved.api_base == "https://litellm-proxy.example/v1"


@pytest.mark.usefixtures("isolated_model_config")
def test_compatibility_settings_fields_do_not_override_route_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://openai.example/v1")
    settings = Settings(llm=LlmSettings(STRIX_LLM="anthropic/claude"))

    assert settings.llm.api_key == "openai-key"
    assert settings.llm.api_base == "https://openai.example/v1"
    assert resolve_model_config(settings).api_key is None
    assert resolve_model_config(settings).api_base is None
    assert "openai-key" not in repr(settings.llm)


@pytest.mark.usefixtures("isolated_model_config")
def test_ollama_base_is_normalized_for_inference(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_API_BASE", "http://[::1]:11434/v1/")
    settings = Settings(llm=LlmSettings(STRIX_LLM="ollama/qwen3"))

    resolved = resolve_model_config(settings)

    assert resolved.api_base == "http://[::1]:11434"


@pytest.mark.usefixtures("isolated_model_config")
def test_sdk_configuration_clears_legacy_litellm_credentials() -> None:
    litellm_module: Any = litellm
    litellm_module.api_key = "stale-key"
    litellm_module.api_base = "https://stale.example"

    configure_sdk_model_defaults(Settings())

    assert litellm_module.api_key is None
    assert litellm_module.api_base is None


@pytest.mark.usefixtures("isolated_model_config")
@pytest.mark.parametrize(
    ("kind", "transport"),
    [("openai", "openai"), ("llama_cpp", "openai"), ("vllm", "hosted_vllm")],
)
def test_custom_provider_routes_openai_compatible_transport(kind: str, transport: str) -> None:
    item = save_custom_provider("Local", "http://localhost:8000/v1", kind=kind)
    settings = Settings(llm=LlmSettings(STRIX_LLM=f"{item.id}/local-model"))

    resolved = resolve_model_config(settings)

    assert resolved.provider == item.id
    assert resolved.model == f"{transport}/local-model"
    assert resolved.api_base == "http://localhost:8000/v1"
    assert resolved.api_key == "not-needed"


@pytest.mark.usefixtures("isolated_model_config")
def test_custom_provider_key_is_bound_to_model_client() -> None:
    item = save_custom_provider("Secured", "https://models.example/v1", "custom-secret")
    settings = Settings(llm=LlmSettings(STRIX_LLM=f"{item.id}/private-model"))

    model = StrixProvider(settings=settings).get_model(f"{item.id}/private-model")

    assert model.model == "openai/private-model"  # type: ignore[attr-defined]
    assert model.api_key == "custom-secret"  # type: ignore[attr-defined]
    assert model.base_url == "https://models.example/v1"  # type: ignore[attr-defined]


@pytest.mark.usefixtures("isolated_model_config")
def test_disabled_custom_provider_fails_before_model_client_construction() -> None:
    item = save_custom_provider("Disabled", "https://models.example/v1", "hidden-secret")
    set_custom_provider_enabled(item.id, enabled=False)
    settings = Settings(llm=LlmSettings(STRIX_LLM=f"{item.id}/private-model"))

    with pytest.raises(ProviderDisabledError, match="disconnected"):
        resolve_model_config(settings)
    with pytest.raises(ProviderDisabledError, match="disconnected"):
        StrixProvider(settings=settings)


@pytest.mark.usefixtures("isolated_model_config")
def test_azure_route_carries_api_version_for_direct_litellm_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AZURE_API_BASE", "https://azure.example")
    monkeypatch.setenv("AZURE_API_KEY", "azure-secret")
    monkeypatch.setenv("AZURE_API_VERSION", "2026-01-01-preview")
    monkeypatch.setattr(litellm, "api_version", "unchanged-global")
    settings = Settings(llm=LlmSettings(STRIX_LLM="azure/deployment"))

    route = resolve_model_config(settings)

    assert route.api_version == "2026-01-01-preview"
    assert litellm.api_version == "unchanged-global"
    assert "azure-secret" not in repr(route)
