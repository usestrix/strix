"""Regression tests for issue #1095.

LLM CONNECTION FAILED — duplicate api_key keyword argument when LLM_API_BASE
is set to a custom endpoint.

When LLM_API_BASE is configured the model resolves through openai-agents'
LitellmModel, which always forwards api_key=self.api_key (None by default) as
an *explicit* kwarg on every litellm.acompletion() call.  If litellm.api_key
is also set as a module-level global by configure_sdk_model_defaults, litellm's
internal dispatch merges the global into the same kwargs dict that already
carries the explicit kwarg and raises:

    TypeError: acompletion() got multiple values for keyword argument 'api_key'
                                   (anthropic/ / litellm/ prefix path)
    TypeError: AsyncCompletions.create() got an unexpected keyword argument
               'api_key'            (openai/ prefix path)

The fix: skip _configure_litellm_default("api_key", ...) when api_base is set.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import litellm
import pytest

from strix.config import loader
from strix.config.loader import load_settings
from strix.config.models import configure_sdk_model_defaults


if TYPE_CHECKING:
    from collections.abc import Iterator


_ENV_KEYS = [
    # Primary Strix settings
    "STRIX_LLM",
    "LLM_API_KEY",
    "LLM_API_BASE",
    # All aliases that LlmSettings maps to api_base (settings.py AliasChoices),
    # so configure_sdk_model_defaults()'s os.environ["OPENAI_BASE_URL"] write
    # in one test does not bleed into the next test's load_settings() call.
    "OPENAI_API_BASE",
    "OPENAI_BASE_URL",
    "LITELLM_BASE_URL",
    "OLLAMA_API_BASE",
]


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Isolate litellm.api_key and the settings cache between tests."""
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)

    saved_api_key = litellm.api_key
    litellm.api_key = None
    try:
        yield
    finally:
        litellm.api_key = saved_api_key



# ---------------------------------------------------------------------------
# Core regression: litellm.api_key must NOT be set when api_base is active
# ---------------------------------------------------------------------------


def test_litellm_api_key_global_not_set_when_api_base_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #1095 (anthropic/ path): litellm.api_key must remain None when
    LLM_API_BASE is set, so that LitellmModel's explicit api_key=None kwarg
    does not collide with a module-level global."""
    monkeypatch.setenv("STRIX_LLM", "anthropic/deepseek-main")
    monkeypatch.setenv("LLM_API_KEY", "placeholder")
    monkeypatch.setenv("LLM_API_BASE", "http://192.168.1.18:8081")

    configure_sdk_model_defaults(load_settings())

    # The module-level litellm.api_key must NOT be set; the key reaches the
    # provider through provider-specific env vars (_mirror_api_key_to_provider_env).
    assert litellm.api_key is None, (
        "litellm.api_key was set as a module-level global even though "
        "LLM_API_BASE is configured. This causes "
        "'acompletion() got multiple values for keyword argument api_key' "
        "(issue #1095)."
    )


def test_litellm_api_key_global_not_set_for_openai_prefix_with_custom_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #1095 (openai/ path): same guard applies regardless of the
    STRIX_LLM prefix used."""
    monkeypatch.setenv("STRIX_LLM", "openai/deepseek-main")
    monkeypatch.setenv("LLM_API_KEY", "placeholder")
    monkeypatch.setenv("LLM_API_BASE", "http://192.168.1.18:8081/v1")

    configure_sdk_model_defaults(load_settings())

    assert litellm.api_key is None, (
        "litellm.api_key was set as a module-level global even though "
        "LLM_API_BASE is configured (openai/ prefix path). This causes "
        "'AsyncCompletions.create() got an unexpected keyword argument api_key'"
        " (issue #1095)."
    )


def test_litellm_api_key_global_set_when_no_api_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Positive case: litellm.api_key IS set when no custom api_base is given
    (standard direct-to-provider path)."""
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-5.4")
    monkeypatch.setenv("LLM_API_KEY", "sk-real-key")
    # LLM_API_BASE is intentionally absent

    configure_sdk_model_defaults(load_settings())

    assert litellm.api_key == "sk-real-key", (
        "litellm.api_key should be set globally when no custom api_base is "
        "configured (standard direct-to-provider path)."
    )
