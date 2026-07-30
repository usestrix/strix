"""Tests for provider/model discovery and credential persistence."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace
from typing import TYPE_CHECKING

import litellm
import pytest
import requests

import strix.config.loader as config_loader
import strix.config.providers as provider_module
from strix.config import (
    ProviderAuthState,
    ProviderCredentialSource,
    ProviderDisabledError,
    apply_config_override,
    clear_provider_credentials_invalid,
    codex,
    configured_provider_model_groups,
    custom_provider,
    disconnect_provider,
    is_provider_configured,
    list_custom_providers,
    list_providers,
    load_settings,
    persist_selected_model,
    provider_api_key_env,
    provider_auth_status,
    provider_authentication_error,
    provider_authentication_error_message,
    provider_can_disconnect,
    provider_chat_models,
    provider_credential_source,
    provider_display_name,
    provider_for_model,
    read_config_env,
    reset_settings_cache,
    resolve_provider_api_key,
    save_custom_provider,
    set_custom_provider_enabled,
    set_provider_api_key,
    update_config_env,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _isolated_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    provider_module._custom_model_cache.clear()
    provider_module._custom_model_failures.clear()
    provider_module._invalid_provider_credentials.clear()
    for key in (
        "STRIX_LLM",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "LLM_API_KEY",
        "LLM_API_BASE",
        "FIREWORKS_API_KEY",
        "FIREWORKS_AI_API_KEY",
        "AZURE_API_KEY",
        "AZURE_API_BASE",
        "AZURE_API_VERSION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_BEARER_TOKEN_BEDROCK",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "VERTEXAI_CREDENTIALS",
        "CLOUDSDK_CONFIG",
        "OLLAMA_API_BASE",
        "OLLAMA_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    apply_config_override(tmp_path / "cli-config.json")
    reset_settings_cache()


def test_list_providers_includes_openrouter_and_common() -> None:
    providers = list_providers()
    assert "openrouter" in providers
    assert "anthropic" in providers
    assert "openai" in providers
    # Preferred providers come first.
    assert providers.index("openai") < providers.index("openrouter") or "openai" in providers
    assert "ollama_chat" not in providers


def test_provider_inventory_includes_litellm_chat_catalog_and_selected_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        litellm,
        "LITELLM_CHAT_PROVIDERS",
        ["registry_only", "ollama_chat"],
    )
    monkeypatch.setattr(
        litellm,
        "models_by_provider",
        {
            "catalog_only": {"catalog_only/chat-model"},
            "image_only": {"image_only/image-model"},
        },
    )
    monkeypatch.setattr(
        litellm,
        "model_cost",
        {
            "catalog_only/chat-model": {"mode": "chat"},
            "image_only/image-model": {"mode": "image_generation"},
        },
    )
    monkeypatch.setenv("STRIX_LLM", "direct_provider/model")
    reset_settings_cache()

    providers = list_providers()

    assert "registry_only" in providers
    assert "catalog_only" in providers
    assert "direct_provider" in providers
    assert "chatgpt" in providers
    assert "image_only" not in providers
    assert "ollama_chat" not in providers


def test_custom_provider_inventory_deduplicates_normalized_ids_in_persisted_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        config_loader,
        "read_custom_provider_records",
        lambda: [
            {
                "id": " CUSTOM-Z ",
                "name": "First",
                "api_base": "http://first.example/v1",
            },
            {
                "id": "custom-z",
                "name": "Malformed duplicate",
                "api_base": "http://duplicate.example/v1",
            },
            {
                "id": "custom-a",
                "name": "Second",
                "api_base": "http://second.example/v1",
            },
        ],
    )

    providers = list_custom_providers()

    assert [(provider.id, provider.name) for provider in providers] == [
        ("custom-z", "First"),
        ("custom-a", "Second"),
    ]


def test_custom_provider_ids_are_appended_once_in_persisted_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = save_custom_provider("First", "http://first.example/v1")
    second = save_custom_provider("Second", "http://second.example/v1")
    monkeypatch.setattr(litellm, "LITELLM_CHAT_PROVIDERS", [second.id, "registry_only"])
    monkeypatch.setattr(litellm, "models_by_provider", {})
    monkeypatch.setattr(provider_module, "_effective_model", lambda: f"{first.id}/selected")

    providers = list_providers()

    assert providers[-2:] == [first.id, second.id]
    assert providers.count(first.id) == 1
    assert providers.count(second.id) == 1


def test_provider_chat_models_are_prefixed() -> None:
    models = provider_chat_models("anthropic")
    assert models
    assert all(m.startswith("anthropic/") for m in models)


def test_openrouter_models_available() -> None:
    models = provider_chat_models("openrouter")
    assert models
    assert all(m.startswith("openrouter/") for m in models)


def test_provider_api_key_env() -> None:
    assert provider_api_key_env("anthropic") == "ANTHROPIC_API_KEY"
    assert provider_api_key_env("openrouter") == "OPENROUTER_API_KEY"
    assert provider_api_key_env("fireworks_ai") == "FIREWORKS_AI_API_KEY"
    assert provider_api_key_env("unknown_provider") is None


def test_dynamic_single_api_key_requirement_can_be_saved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        provider_module,
        "_representative_model",
        lambda _provider, _selected=None: "longtail/model",
    )
    monkeypatch.setattr(
        litellm,
        "validate_environment",
        lambda **_kwargs: {"keys_in_environment": False, "missing_keys": ["LONGTAIL_API_KEY"]},
    )

    assert provider_api_key_env("longtail") == "LONGTAIL_API_KEY"
    assert provider_auth_status("longtail").state is ProviderAuthState.MISSING

    set_provider_api_key("longtail", "longtail-secret")

    assert read_config_env()["LONGTAIL_API_KEY"] == "longtail-secret"
    assert resolve_provider_api_key("longtail") == "longtail-secret"
    assert provider_credential_source("longtail") is ProviderCredentialSource.CONFIG


@pytest.mark.parametrize(
    "requirements",
    [
        ["SERVICE_API_KEY", "SERVICE_API_BASE"],
        ["SERVICE_TOKEN"],
    ],
)
def test_dynamic_ambiguous_requirements_are_reported_not_guessed(
    requirements: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        provider_module,
        "_representative_model",
        lambda _provider, _selected=None: "longtail/model",
    )
    monkeypatch.setattr(
        litellm,
        "validate_environment",
        lambda **_kwargs: {"keys_in_environment": False, "missing_keys": requirements},
    )

    status = provider_auth_status("longtail")

    assert status.state is ProviderAuthState.MISSING
    assert all(requirement in status.detail for requirement in requirements)
    assert provider_api_key_env("longtail") is None

    update_config_env(dict.fromkeys(requirements, "not-runtime-bound"))
    assert provider_auth_status("longtail").state is ProviderAuthState.MISSING


@pytest.mark.parametrize(
    ("model", "provider"),
    [
        ("gpt-5.4", "openai"),
        ("openai/gpt-5.4", "openai"),
        ("anthropic/claude", "anthropic"),
        ("litellm/anthropic/claude", "anthropic"),
        ("any-llm/openrouter/model", "openrouter"),
        ("openrouter/anthropic/claude", "openrouter"),
    ],
)
def test_provider_for_model(model: str, provider: str) -> None:
    assert provider_for_model(model) == provider


def test_is_provider_configured_reflects_env() -> None:
    os.environ.pop("ANTHROPIC_API_KEY", None)
    reset_settings_cache()
    assert is_provider_configured("anthropic") is False
    os.environ["ANTHROPIC_API_KEY"] = "sk-ant"
    reset_settings_cache()
    assert is_provider_configured("anthropic") is True
    os.environ.pop("ANTHROPIC_API_KEY", None)


def test_legacy_key_only_configures_provider_selected_by_model(tmp_path: Path) -> None:
    config_path = tmp_path / "cli-config.json"
    config_path.write_text(
        json.dumps(
            {
                "env": {
                    "STRIX_LLM": "openrouter/anthropic/claude-3.5-sonnet",
                    "LLM_API_KEY": "sk-or-generic",
                }
            }
        ),
        encoding="utf-8",
    )
    apply_config_override(config_path)
    reset_settings_cache()
    load_settings()

    assert is_provider_configured("openrouter") is True
    assert resolve_provider_api_key("openrouter") == "sk-or-generic"
    assert is_provider_configured("anthropic") is False
    assert is_provider_configured("openai") is False

    assert json.loads(config_path.read_text(encoding="utf-8"))["env"] == {
        "STRIX_LLM": "openrouter/anthropic/claude-3.5-sonnet",
        "LLM_API_KEY": "sk-or-generic",
    }


def test_environment_legacy_key_is_not_exported_to_provider_env() -> None:
    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4-6"
    os.environ["LLM_API_KEY"] = "legacy-anthropic-key"
    reset_settings_cache()

    assert resolve_provider_api_key("anthropic") == "legacy-anthropic-key"
    assert resolve_provider_api_key("openrouter") is None
    assert "ANTHROPIC_API_KEY" not in os.environ


def test_legacy_key_configures_only_its_selected_unknown_provider() -> None:
    os.environ["STRIX_LLM"] = "custom-provider/custom-model"
    os.environ["LLM_API_KEY"] = "legacy-key"
    reset_settings_cache()

    assert resolve_provider_api_key("custom-provider") == "legacy-key"
    assert resolve_provider_api_key("another-provider") is None


def test_provider_key_wins_over_legacy_key(tmp_path: Path) -> None:
    config_path = tmp_path / "cli-config.json"
    config_path.write_text(
        json.dumps(
            {
                "env": {
                    "STRIX_LLM": "anthropic/claude-sonnet-4-6",
                    "ANTHROPIC_API_KEY": "canonical-key",
                }
            }
        ),
        encoding="utf-8",
    )
    os.environ["LLM_API_KEY"] = "legacy-key"
    apply_config_override(config_path)
    reset_settings_cache()

    assert resolve_provider_api_key("anthropic") == "canonical-key"


def test_set_provider_api_key_persists(tmp_path: Path) -> None:
    config_path = tmp_path / "cli-config.json"
    apply_config_override(config_path)
    reset_settings_cache()
    os.environ.pop("ANTHROPIC_API_KEY", None)

    set_provider_api_key("anthropic", "sk-ant-123")

    assert "ANTHROPIC_API_KEY" not in os.environ
    assert is_provider_configured("anthropic") is True
    assert resolve_provider_api_key("anthropic") == "sk-ant-123"

    stored = json.loads(config_path.read_text(encoding="utf-8"))
    assert stored["env"]["ANTHROPIC_API_KEY"] == "sk-ant-123"


def test_saved_provider_key_can_be_disconnected() -> None:
    set_provider_api_key("anthropic", "sk-ant")

    assert provider_credential_source("anthropic") == "config"
    assert provider_can_disconnect("anthropic") is True

    disconnect_provider("anthropic")

    assert provider_auth_status("anthropic").ready is False
    assert "ANTHROPIC_API_KEY" not in read_config_env()


def test_environment_provider_key_cannot_be_disconnected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "environment-key")

    assert provider_credential_source("anthropic") == "env"
    assert provider_can_disconnect("anthropic") is False
    with pytest.raises(ValueError, match="not managed"):
        disconnect_provider("anthropic")


def test_persisted_provider_key_reloads(tmp_path: Path) -> None:
    config_path = tmp_path / "cli-config.json"
    config_path.write_text(
        json.dumps({"env": {"ANTHROPIC_API_KEY": "sk-reload"}}), encoding="utf-8"
    )
    os.environ.pop("ANTHROPIC_API_KEY", None)
    apply_config_override(config_path)
    reset_settings_cache()

    load_settings()

    assert os.environ.get("ANTHROPIC_API_KEY") is None
    assert is_provider_configured("anthropic") is True


def test_openai_key_never_configures_anthropic() -> None:
    os.environ["OPENAI_API_KEY"] = "sk-openai"
    assert resolve_provider_api_key("anthropic") is None
    assert provider_auth_status("anthropic").ready is False


@pytest.mark.parametrize(
    "error",
    [
        ValueError("401 Unauthorized"),
        ValueError("Incorrect API key provided"),
    ],
)
def test_provider_authentication_error_detects_rejected_keys(error: BaseException) -> None:
    assert provider_authentication_error(error) is True


def test_provider_authentication_error_detects_exception_type() -> None:
    class AuthenticationError(RuntimeError):
        pass

    assert provider_authentication_error(AuthenticationError("rejected")) is True


def test_provider_authentication_error_does_not_misclassify_transient_failures() -> None:
    assert provider_authentication_error(RuntimeError("429 rate limit exceeded")) is False
    assert provider_authentication_error(RuntimeError("connection timed out")) is False
    assert provider_authentication_error(RuntimeError("403 model access denied")) is False


def test_rejected_saved_key_can_be_replaced() -> None:
    set_provider_api_key("anthropic", "wrong-key")

    message = provider_authentication_error_message(
        "anthropic/claude",
        RuntimeError("HTTP 401 Unauthorized"),
    )

    status = provider_auth_status("anthropic")
    assert message is not None and "authentication failed" in message
    assert status.state is ProviderAuthState.INVALID
    assert status.ready is False
    assert "select this provider to replace it" in status.detail

    set_provider_api_key("anthropic", "replacement-key")

    assert provider_auth_status("anthropic").state is ProviderAuthState.CONFIGURED
    clear_provider_credentials_invalid("anthropic")


def test_rejected_environment_key_requires_environment_update(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "wrong-env-key")

    provider_authentication_error_message("anthropic/claude", RuntimeError("HTTP 401"))

    status = provider_auth_status("anthropic")
    assert status.state is ProviderAuthState.INVALID
    assert "environment" in status.detail


def test_legacy_fireworks_key_alias_remains_readable() -> None:
    os.environ["FIREWORKS_API_KEY"] = "legacy-key"
    assert resolve_provider_api_key("fireworks_ai") == "legacy-key"


def test_azure_requires_endpoint_and_version() -> None:
    os.environ["AZURE_API_KEY"] = "azure-key"
    status = provider_auth_status("azure")
    assert status.ready is False
    assert "AZURE_API_BASE" in status.detail
    assert "AZURE_API_VERSION" in status.detail


def test_multiple_custom_providers_persist_with_optional_keys(tmp_path: Path) -> None:
    config_path = tmp_path / "cli-config.json"
    apply_config_override(config_path)

    llama = save_custom_provider("Local llama", "http://localhost:8080", kind="llama_cpp")
    vllm = save_custom_provider(
        "GPU server",
        "http://localhost:8000/v1",
        "secret",
        "vllm",
    )

    assert llama.api_base == "http://localhost:8080/v1"
    assert llama.api_key is None
    assert vllm.api_key == "secret"
    assert [item.name for item in list_custom_providers()] == ["Local llama", "GPU server"]
    assert custom_provider(llama.id) == llama
    assert is_provider_configured(llama.id)
    stored = json.loads(config_path.read_text(encoding="utf-8"))
    assert "api_key" not in stored["custom_providers"][0]
    assert stored["custom_providers"][1]["api_key"] == "secret"


def test_custom_provider_disconnect_is_reversible() -> None:
    item = save_custom_provider("Local", "http://localhost:9001/v1")

    assert provider_can_disconnect(item.id) is True
    disconnect_provider(item.id)

    disconnected = custom_provider(item.id)
    assert disconnected is not None and disconnected.disabled is True
    assert provider_auth_status(item.id).ready is False
    assert provider_can_disconnect(item.id) is False

    set_custom_provider_enabled(item.id, enabled=True)

    reconnected = custom_provider(item.id)
    assert reconnected is not None and reconnected.disabled is False
    assert provider_auth_status(item.id).ready is True


def test_disabled_custom_provider_guard_precedes_secret_and_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = save_custom_provider(
        "Disabled secret endpoint",
        "https://models.example/v1",
        "must-not-appear",
    )
    set_custom_provider_enabled(item.id, enabled=False)
    monkeypatch.setattr(
        requests,
        "get",
        lambda *_args, **_kwargs: pytest.fail("disabled provider attempted discovery"),
    )

    disabled = custom_provider(item.id)
    assert disabled is not None
    assert "must-not-appear" not in repr(disabled)
    with pytest.raises(ProviderDisabledError, match="disconnected"):
        resolve_provider_api_key(item.id)
    with pytest.raises(ProviderDisabledError, match="disconnected"):
        provider_chat_models(item.id)


def test_custom_provider_requires_absolute_http_url() -> None:
    with pytest.raises(ValueError, match="absolute HTTP"):
        save_custom_provider("Broken", "localhost:8000", kind="vllm")


@pytest.mark.parametrize(
    ("api_key", "headers"),
    [(None, {}), ("secret", {"Authorization": "Bearer secret"})],
)
def test_custom_provider_discovers_openai_models(
    monkeypatch: pytest.MonkeyPatch,
    api_key: str | None,
    headers: dict[str, str],
) -> None:
    item = save_custom_provider("Endpoint", "http://localhost:9000/v1", api_key)
    calls: list[tuple[str, dict[str, str], tuple[float, float]]] = []

    def get(
        url: str,
        *,
        headers: dict[str, str],
        timeout: tuple[float, float],
    ) -> SimpleNamespace:
        calls.append((url, headers, timeout))
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"data": [{"id": "z-model"}, {"id": "a/model"}]},
        )

    monkeypatch.setattr("strix.config.providers.requests.get", get)

    assert provider_chat_models(item.id) == [f"{item.id}/a/model", f"{item.id}/z-model"]
    assert calls == [("http://localhost:9000/v1/models", headers, (0.25, 0.75))]


def test_ollama_uses_live_installed_model_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, str], tuple[float, float]]] = []

    def get(
        url: str,
        *,
        headers: dict[str, str],
        timeout: tuple[float, float],
    ) -> SimpleNamespace:
        calls.append((url, headers, timeout))
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"models": [{"name": "qwen3:8b"}, {"model": "llama3.3"}]},
        )

    monkeypatch.setattr("strix.config.providers.requests.get", get)

    assert provider_chat_models("ollama") == ["ollama/llama3.3", "ollama/qwen3:8b"]
    assert calls == [("http://localhost:11434/api/tags", {}, (0.5, 1.5))]


def test_ollama_normalizes_openai_compatible_base(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_API_BASE", "http://[::1]:11434/v1/")
    calls: list[str] = []

    def get(url: str, **_kwargs: object) -> SimpleNamespace:
        calls.append(url)
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"models": []})

    monkeypatch.setattr("strix.config.providers.requests.get", get)

    assert provider_chat_models("ollama") == []
    assert calls == ["http://[::1]:11434/api/tags"]


def test_unreachable_ollama_is_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    def get(*_args: object, **_kwargs: object) -> None:
        raise requests.ConnectionError

    monkeypatch.setattr("strix.config.providers.requests.get", get)
    monkeypatch.setattr("strix.config.providers.shutil.which", lambda _name: None)

    status = provider_auth_status("ollama")

    assert status.state is ProviderAuthState.UNAVAILABLE
    assert status.ready is False
    assert "not installed" in status.detail


def test_external_provider_requires_dependency_even_when_selected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("strix.config.providers._module_available", lambda _name: False)

    assert provider_auth_status("bedrock").state is ProviderAuthState.MISSING

    os.environ["STRIX_LLM"] = "bedrock/anthropic.claude-v2"
    reset_settings_cache()
    selected = provider_auth_status("bedrock")

    assert selected.state is ProviderAuthState.MISSING
    assert selected.ready is False
    assert "selected model" in selected.detail


@pytest.mark.parametrize(
    "provider",
    [
        "vertex_ai",
        "vertex_ai_beta",
        "bedrock",
        "bedrock_mantle",
        "sagemaker",
        "sagemaker_chat",
        "sagemaker_nova",
        "amazon_nova",
    ],
)
def test_cloud_provider_aliases_are_not_ready_without_dependencies(
    provider: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(provider_module, "_module_available", lambda _name: False)

    status = provider_auth_status(provider)

    assert status.state is ProviderAuthState.MISSING
    assert status.ready is False


def test_aws_profile_region_alone_is_not_treated_as_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "aws-config"
    config.write_text("[default]\nregion = us-east-1\n", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "missing"))
    monkeypatch.setattr("strix.config.providers._module_available", lambda _name: True)

    status = provider_auth_status("bedrock")
    assert status.state is ProviderAuthState.MISSING
    assert status.ready is False
    assert "not detected locally" in status.detail

    config.write_text(
        "[default]\nregion = us-east-1\ncredential_process = get-credentials\n",
        encoding="utf-8",
    )
    assert "AWS credentials detected" in provider_auth_status("bedrock").detail


def test_switching_provider_clears_persisted_generic_base() -> None:
    update_config_env(
        {
            "STRIX_LLM": "openai/local-model",
            "LLM_API_BASE": "http://localhost:9000/v1",
        }
    )

    persist_selected_model("anthropic/claude-sonnet-4-6")

    stored = read_config_env()
    assert stored["STRIX_LLM"] == "anthropic/claude-sonnet-4-6"
    assert "LLM_API_BASE" not in stored


def test_switching_provider_rejects_process_legacy_key_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    update_config_env({"STRIX_LLM": "openai/gpt-5.4", "KEEP": "unchanged"})
    monkeypatch.setenv("LLM_API_KEY", "process-openai-key")
    before = read_config_env()
    updates: list[dict[str, str | None]] = []
    monkeypatch.setattr(config_loader, "update_config_env", updates.append)

    with pytest.raises(
        ValueError,
        match=r"move it to OPENAI_API_KEY.*unset LLM_API_KEY before switching",
    ):
        persist_selected_model("anthropic/claude-sonnet-4-6")

    assert updates == []
    assert "STRIX_LLM" not in os.environ
    assert read_config_env() == before


def test_switching_provider_rejects_persisted_legacy_key_without_mutation() -> None:
    update_config_env(
        {
            "STRIX_LLM": "openai/gpt-5.4",
            "LLM_API_KEY": "persisted-openai-key",
            "KEEP": "unchanged",
        }
    )
    before = read_config_env()

    with pytest.raises(ValueError, match="save a provider-specific key"):
        persist_selected_model("anthropic/claude-sonnet-4-6")

    assert read_config_env() == before
    assert "STRIX_LLM" not in os.environ


def test_first_model_selection_can_bind_process_legacy_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LLM_API_KEY", "first-provider-key")

    persist_selected_model("anthropic/claude-sonnet-4-6")

    assert os.environ["STRIX_LLM"] == "anthropic/claude-sonnet-4-6"
    assert os.environ["LLM_API_KEY"] == "first-provider-key"
    assert read_config_env() == {"STRIX_LLM": "anthropic/claude-sonnet-4-6"}
    assert resolve_provider_api_key("anthropic") == "first-provider-key"


def test_first_model_selection_can_bind_persisted_legacy_key() -> None:
    update_config_env({"LLM_API_KEY": "first-persisted-key"})

    persist_selected_model("anthropic/claude-sonnet-4-6")

    assert read_config_env() == {
        "LLM_API_KEY": "first-persisted-key",
        "STRIX_LLM": "anthropic/claude-sonnet-4-6",
    }
    assert (
        resolve_provider_api_key(
            "anthropic",
            primary_model="anthropic/claude-sonnet-4-6",
        )
        == "first-persisted-key"
    )


def test_first_model_selection_clears_stale_persisted_generic_base() -> None:
    update_config_env({"LLM_API_BASE": "http://stale.example/v1"})

    persist_selected_model("anthropic/claude-sonnet-4-6")

    assert read_config_env() == {"STRIX_LLM": "anthropic/claude-sonnet-4-6"}


def test_switching_provider_rejects_environment_generic_base() -> None:
    os.environ["STRIX_LLM"] = "openai/local-model"
    os.environ["LLM_API_BASE"] = "http://localhost:9000/v1"
    reset_settings_cache()

    with pytest.raises(ValueError, match="unset it before switching"):
        persist_selected_model("anthropic/claude-sonnet-4-6")

    assert os.environ["STRIX_LLM"] == "openai/local-model"


def test_first_model_selection_rejects_environment_base_before_mutation() -> None:
    os.environ["LLM_API_BASE"] = "http://stale.example/v1"

    with pytest.raises(ValueError, match="unset it before switching"):
        persist_selected_model("anthropic/claude-sonnet-4-6")

    assert "STRIX_LLM" not in os.environ
    assert read_config_env() == {}


def test_selected_model_requires_nonempty_routed_id() -> None:
    with pytest.raises(ValueError, match="model ID"):
        persist_selected_model("azure/")


@pytest.mark.asyncio
async def test_configured_provider_groups_include_all_ready_providers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    os.environ["OPENAI_API_KEY"] = "openai-key"
    os.environ["ANTHROPIC_API_KEY"] = "anthropic-key"
    monkeypatch.setattr(provider_module, "list_providers", lambda: ["openai", "anthropic"])
    monkeypatch.setattr(
        provider_module,
        "_catalog_chat_models",
        lambda provider: [f"{provider}/model"],
    )

    groups = await configured_provider_model_groups()

    assert [(group.provider, group.models) for group in groups] == [
        ("openai", ("openai/model",)),
        ("anthropic", ("anthropic/model",)),
    ]
    assert all(group.allow_manual for group in groups)


@pytest.mark.asyncio
async def test_selected_custom_provider_has_one_group_and_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = save_custom_provider("Selected", "http://selected.example/v1")
    monkeypatch.setattr(litellm, "LITELLM_CHAT_PROVIDERS", [])
    monkeypatch.setattr(litellm, "models_by_provider", {})
    monkeypatch.setattr(provider_module, "_effective_model", lambda: f"{item.id}/selected")
    calls: list[str] = []

    def discover(custom: provider_module.CustomProvider) -> tuple[list[str], None]:
        calls.append(custom.id)
        return [f"{custom.id}/discovered"], None

    monkeypatch.setattr(provider_module, "_discover_custom_models", discover)

    groups = await configured_provider_model_groups()

    custom_groups = [group for group in groups if group.provider == item.id]
    assert len(custom_groups) == 1
    assert calls == [item.id]


@pytest.mark.asyncio
async def test_chatgpt_subscription_status_and_model_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(codex, "is_authenticated", lambda: True)
    monkeypatch.setattr(provider_module, "list_providers", lambda: ["chatgpt"])

    status = provider_auth_status("chatgpt")
    groups = await configured_provider_model_groups("chatgpt/gpt-5.6-sol")

    assert status.state is ProviderAuthState.CONFIGURED
    assert provider_display_name("chatgpt") == "ChatGPT subscription"
    assert provider_api_key_env("chatgpt") is None
    assert groups == [
        provider_module.ProviderModelGroup(
            provider="chatgpt",
            label="ChatGPT subscription",
            models=("chatgpt/gpt-5.4", "chatgpt/gpt-5.6-sol"),
            allow_manual=True,
        )
    ]


@pytest.mark.asyncio
async def test_openrouter_model_group_is_always_last(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.setenv("OPENROUTER_API_KEY", "openrouter-key")
    item = save_custom_provider("Local", "http://localhost:9996/v1")
    monkeypatch.setattr(
        provider_module,
        "list_providers",
        lambda: ["openrouter", "openai", item.id],
    )
    monkeypatch.setattr(
        provider_module,
        "_catalog_chat_models",
        lambda provider: [f"{provider}/model"],
    )
    monkeypatch.setattr(
        provider_module,
        "_discover_custom_models",
        lambda _item: ([f"{item.id}/model"], None),
    )

    groups = await configured_provider_model_groups()

    assert [group.provider for group in groups] == ["openai", item.id, "openrouter"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "detector"),
    [
        ("bedrock", "_aws_credentials_detected"),
        ("vertex_ai", "_vertex_credentials_detected"),
    ],
)
async def test_undetected_unselected_cloud_providers_are_hidden_from_models(
    provider: str,
    detector: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(provider_module, "list_providers", lambda: [provider])
    monkeypatch.setattr(provider_module, "_module_available", lambda _name: True)
    monkeypatch.setattr(provider_module, "_effective_model", lambda: None)
    monkeypatch.setattr(provider_module, detector, lambda **_kwargs: False)
    monkeypatch.setattr(
        provider_module,
        "_catalog_chat_models",
        lambda _provider: pytest.fail("hidden providers must not load their model catalog"),
    )

    groups = await configured_provider_model_groups()

    assert groups == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "detector"),
    [
        ("bedrock", "_aws_credentials_detected"),
        ("vertex_ai", "_vertex_credentials_detected"),
    ],
)
async def test_detected_cloud_credentials_include_provider_models(
    provider: str,
    detector: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = f"{provider}/test-model"
    monkeypatch.setattr(provider_module, "list_providers", lambda: [provider])
    monkeypatch.setattr(provider_module, "_module_available", lambda _name: True)
    monkeypatch.setattr(provider_module, "_effective_model", lambda: None)
    monkeypatch.setattr(provider_module, detector, lambda **_kwargs: True)
    monkeypatch.setattr(provider_module, "_catalog_chat_models", lambda _provider: [model])

    groups = await configured_provider_model_groups()

    assert [(group.provider, group.models) for group in groups] == [(provider, (model,))]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "detector"),
    [
        ("bedrock", "_aws_credentials_detected"),
        ("vertex_ai", "_vertex_credentials_detected"),
    ],
)
async def test_selected_cloud_models_keep_unverified_ambient_provider_available(
    provider: str,
    detector: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = f"{provider}/test-model"
    monkeypatch.setattr(provider_module, "list_providers", lambda: [provider])
    monkeypatch.setattr(provider_module, "_module_available", lambda _name: True)
    monkeypatch.setattr(provider_module, "_effective_model", lambda: model)
    monkeypatch.setattr(provider_module, detector, lambda **_kwargs: False)
    monkeypatch.setattr(provider_module, "_catalog_chat_models", lambda _provider: [model])

    groups = await configured_provider_model_groups(current_model=model)

    assert [(group.provider, group.models) for group in groups] == [(provider, (model,))]


@pytest.mark.asyncio
async def test_failed_custom_discovery_keeps_manual_model_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = save_custom_provider("Offline", "http://localhost:9999/v1")
    monkeypatch.setattr(provider_module, "list_providers", lambda: [item.id])

    def get(*_args: object, **_kwargs: object) -> None:
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(requests, "get", get)

    groups = await configured_provider_model_groups()

    assert len(groups) == 1
    assert groups[0].provider == item.id
    assert groups[0].allow_manual is True
    assert groups[0].error == "Endpoint unavailable; enter a model ID manually"


@pytest.mark.asyncio
async def test_custom_provider_unauthorized_response_marks_key_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = save_custom_provider("Rejected", "http://localhost:9995/v1", "wrong-key")
    monkeypatch.setattr(provider_module, "list_providers", lambda: [item.id])
    response = requests.Response()
    response.status_code = 401

    def get(*_args: object, **_kwargs: object) -> None:
        raise requests.HTTPError("401 Client Error: Unauthorized", response=response)

    monkeypatch.setattr(requests, "get", get)

    groups = await configured_provider_model_groups()

    assert len(groups) == 1
    assert groups[0].allow_manual is True
    assert groups[0].error is not None and "rejected" in groups[0].error
    assert provider_auth_status(item.id).state is ProviderAuthState.INVALID
    assert await configured_provider_model_groups() == []


@pytest.mark.asyncio
async def test_custom_timeout_uses_cooldown_without_blocking_repeated_picker_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = save_custom_provider("Slow", "http://localhost:9998/v1")
    monkeypatch.setattr(provider_module, "list_providers", lambda: [item.id])
    calls = 0

    def get(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        raise requests.Timeout

    monkeypatch.setattr(requests, "get", get)

    first = await configured_provider_model_groups()
    second = await configured_provider_model_groups()

    assert calls == 1
    assert first[0].error == "Model discovery timed out; enter a model ID manually"
    assert second[0].error == first[0].error
    assert second[0].allow_manual is True


def test_custom_model_cache_avoids_repeated_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    item = save_custom_provider("Cached", "http://localhost:9997/v1")
    calls = 0

    def get(*_args: object, **_kwargs: object) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"data": [{"id": "cached-model"}]},
        )

    monkeypatch.setattr(requests, "get", get)

    first = provider_chat_models(item.id)
    second = provider_chat_models(item.id)

    assert first == second == [f"{item.id}/cached-model"]
    assert calls == 1
