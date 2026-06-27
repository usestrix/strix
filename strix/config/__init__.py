"""Strix application settings.

Public surface:

- :class:`Settings` — composite model. Get via :func:`load_settings`.
- :class:`LlmSettings`, :class:`RuntimeSettings`, :class:`TelemetrySettings`,
  :class:`IntegrationSettings` — sub-models, attribute-accessed off
  ``Settings``.
- :func:`load_settings` — memoized resolve (env > JSON file > defaults).
- :func:`apply_config_override` — switch the JSON source to a custom path.
- :func:`invalidate_settings_cache` — drop the memoized settings.
- :func:`persist_current` — write currently-set env vars to the active file.
"""

from strix.config.loader import (
    apply_config_override,
    invalidate_settings_cache,
    load_settings,
    persist_current,
)
from strix.config.settings import (
    IntegrationSettings,
    LlmSettings,
    RuntimeSettings,
    Settings,
    TelemetrySettings,
)


__all__ = [
    "IntegrationSettings",
    "LlmSettings",
    "RuntimeSettings",
    "Settings",
    "TelemetrySettings",
    "apply_config_override",
    "invalidate_settings_cache",
    "load_settings",
    "persist_current",
]
