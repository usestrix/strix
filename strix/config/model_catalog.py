"""Small, verified model metadata owned by Strix.

LiteLLM remains the source of truth for the general provider catalog.  These
entries cover MiniMax text IDs whose direct or gateway contracts are known to
Strix, so an upstream catalog update cannot silently change the default API
route or token budget.  Unknown and user supplied IDs continue through the
existing LiteLLM/fallback path.
"""

from __future__ import annotations

from typing import Any


_MINIMAX_FLASH = {
    "max_input_tokens": 1_000_000,
    "max_output_tokens": 524_288,
    "supports_reasoning": True,
    "supports_vision": True,
    "supported_endpoints": ["/v1/responses", "/v1/chat/completions"],
}

_MINIMAX_M3 = {
    "max_input_tokens": 1_000_000,
    "supports_reasoning": True,
    "supported_endpoints": ["/v1/chat/completions"],
}

_MINIMAX_GATEWAY_FLASH = {
    "supports_reasoning": True,
    "supported_endpoints": ["/v1/chat/completions"],
}


# Keys are lower-case because provider and model IDs are case-insensitive at the
# routing boundary.  Gateway IDs remain exact in the values sent by callers.
MINIMAX_TEXT_MODELS = (
    "openai/MiniMax-M3.1-Flash",
    "openai/MiniMax-M3",
)
DEFAULT_MINIMAX_TEXT_MODEL = MINIMAX_TEXT_MODELS[0]


_MINIMAX_TEXT_CATALOG: dict[str, dict[str, Any]] = {
    key: dict(value)
    for keys, value in (
        (
            (
                "minimax-m3.1-flash",
                "openai/minimax-m3.1-flash",
                "minimax/minimax-m3.1-flash",
            ),
            _MINIMAX_FLASH,
        ),
        (
            (
                "openrouter/minimax/minimax-m3.1-flash:free",
                "opencode/minimax-m3.1-flash-free",
            ),
            _MINIMAX_GATEWAY_FLASH,
        ),
        (
            (
                "minimax-m3",
                "openai/minimax-m3",
                "minimax/minimax-m3",
                "openrouter/minimax/minimax-m3",
                "opencode/minimax-m3",
            ),
            _MINIMAX_M3,
        ),
    )
    for key in keys
}


def minimax_text_entry(model_name: str) -> dict[str, Any] | None:
    """Return a copy of verified MiniMax text metadata for ``model_name``."""
    entry = _MINIMAX_TEXT_CATALOG.get(model_name.strip().lower())
    return dict(entry) if entry is not None else None


def local_model_entry(model_name: str) -> dict[str, Any] | None:
    """Return locally-owned metadata before consulting dynamic provider data."""
    return minimax_text_entry(model_name)


def local_model_info(model_name: str) -> dict[str, int] | None:
    """Return token limits for known local entries when they are documented."""
    entry = local_model_entry(model_name)
    if entry is None:
        return None
    info = {
        "max_input_tokens": int(entry.get("max_input_tokens") or 0),
        "max_output_tokens": int(entry.get("max_output_tokens") or 0),
    }
    return info if any(info.values()) else None
