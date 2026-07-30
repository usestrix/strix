"""Strix application settings.

Public surface:

- :class:`Settings` — composite model. Get via :func:`load_settings`.
- :class:`LlmSettings`, :class:`RuntimeSettings`, :class:`TelemetrySettings`,
  :class:`IntegrationSettings` — sub-models, attribute-accessed off
  ``Settings``.
- :func:`load_settings` — memoized resolve (env > JSON file > defaults).
- :func:`apply_config_override` — switch the JSON source to a custom path.
- :func:`resolve_env_value` — resolve env/config aliases without mutating env.
- :func:`update_config_env` — atomically merge values into the active config.
- :func:`persist_current` — merge currently-set env vars into the active file.
"""

from strix.config.loader import (
    apply_config_override,
    load_settings,
    persist_current,
    read_config_env,
    read_custom_provider_records,
    reset_settings_cache,
    resolve_env_value,
    update_config_env,
)
from strix.config.providers import (
    CUSTOM_PROVIDER_ADD,
    CUSTOM_PROVIDER_KINDS,
    CustomProvider,
    ProviderAuthState,
    ProviderAuthStatus,
    ProviderCredentialSource,
    ProviderDisabledError,
    ProviderModelGroup,
    clear_provider_credentials_invalid,
    configured_provider_model_groups,
    custom_provider,
    disconnect_provider,
    is_provider_configured,
    list_custom_providers,
    list_providers,
    mark_provider_credentials_invalid,
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
    require_provider_enabled,
    resolve_provider_api_key,
    save_custom_provider,
    set_custom_provider_enabled,
    set_provider_api_key,
)
from strix.config.settings import (
    ContextSettings,
    DedupeSettings,
    IntegrationSettings,
    LlmSettings,
    RuntimeSettings,
    Settings,
    TelemetrySettings,
)


__all__ = [
    "CUSTOM_PROVIDER_ADD",
    "CUSTOM_PROVIDER_KINDS",
    "ContextSettings",
    "CustomProvider",
    "DedupeSettings",
    "IntegrationSettings",
    "LlmSettings",
    "ProviderAuthState",
    "ProviderAuthStatus",
    "ProviderCredentialSource",
    "ProviderDisabledError",
    "ProviderModelGroup",
    "RuntimeSettings",
    "Settings",
    "TelemetrySettings",
    "apply_config_override",
    "clear_provider_credentials_invalid",
    "configured_provider_model_groups",
    "custom_provider",
    "disconnect_provider",
    "is_provider_configured",
    "list_custom_providers",
    "list_providers",
    "load_settings",
    "mark_provider_credentials_invalid",
    "persist_current",
    "persist_selected_model",
    "provider_api_key_env",
    "provider_auth_status",
    "provider_authentication_error",
    "provider_authentication_error_message",
    "provider_can_disconnect",
    "provider_chat_models",
    "provider_credential_source",
    "provider_display_name",
    "provider_for_model",
    "read_config_env",
    "read_custom_provider_records",
    "require_provider_enabled",
    "reset_settings_cache",
    "resolve_env_value",
    "resolve_provider_api_key",
    "save_custom_provider",
    "set_custom_provider_enabled",
    "set_provider_api_key",
    "update_config_env",
]
