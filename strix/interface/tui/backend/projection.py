"""Wire-safe projections of runtime state for the TUI backend."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from strix.config import (
    ProviderAuthState,
    custom_provider,
    provider_api_key_env,
    provider_auth_status,
    provider_can_disconnect,
    provider_credential_source,
    provider_display_name,
    resolve_provider_api_key,
)


SCAN_MODES = ("quick", "standard", "deep")
SCOPE_MODES = ("auto", "diff", "full")
MAX_PROJECTION_STRING = 64 * 1024
MAX_COLLECTION_ITEM_BYTES = 512 * 1024
MAX_TERMINAL_EVENTS = 5_000
MAX_TERMINAL_VULNERABILITIES = 1_000
MODEL_LISTING_TTL_SECONDS = 60.0
MAX_MODEL_LISTINGS = 32
MODEL_GROUP_TARGET_BYTES = 24 * 1024
MODEL_PAGE_TARGET_BYTES = 48 * 1024
STATE_TARGET_BYTES = 48 * 1024
TERMINAL_ESCAPE_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_][0-?]*[ -/]*[@-~]")


def sanitize_terminal_text(value: str) -> str:
    without_escapes = TERMINAL_ESCAPE_RE.sub("", value)
    return "".join(
        character
        for character in without_escapes
        if character in "\n\t" or (ord(character) >= 32 and not 127 <= ord(character) <= 159)
    )


def terminal_projection(  # noqa: PLR0911
    value: Any,
    *,
    max_string: int = MAX_PROJECTION_STRING,
    max_items: int = 200,
    depth: int = 0,
) -> Any:
    """Copy and bound terminal-only data without changing durable history."""
    if isinstance(value, str):
        clean = sanitize_terminal_text(value)
        if len(clean) <= max_string:
            return clean
        omitted = len(clean) - max_string
        return f"{clean[:max_string]}\n...[{omitted} characters omitted from terminal projection]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if depth >= 8:
        return "[nested value omitted from terminal projection]"
    if isinstance(value, dict):
        items = list(value.items())
        projected = {
            sanitize_terminal_text(str(key)): terminal_projection(
                item,
                max_string=max_string,
                max_items=max_items,
                depth=depth + 1,
            )
            for key, item in items[:max_items]
        }
        if len(items) > max_items:
            projected["_projection_notice"] = (
                f"{len(items) - max_items} fields omitted from terminal projection"
            )
        return projected
    if isinstance(value, list | tuple):
        projected_items = [
            terminal_projection(
                item,
                max_string=max_string,
                max_items=max_items,
                depth=depth + 1,
            )
            for item in value[:max_items]
        ]
        if len(value) > max_items:
            projected_items.append(
                f"[{len(value) - max_items} items omitted from terminal projection]"
            )
        return projected_items
    return terminal_projection(
        str(value),
        max_string=max_string,
        max_items=max_items,
        depth=depth,
    )


def collection_item_projection(item: dict[str, Any]) -> dict[str, Any]:
    projected = terminal_projection(item)
    assert isinstance(projected, dict)
    if len(json.dumps(projected, default=str, separators=(",", ":")).encode()) <= (
        MAX_COLLECTION_ITEM_BYTES
    ):
        return projected

    projected = terminal_projection(item, max_string=8 * 1024, max_items=40)
    assert isinstance(projected, dict)
    projected["projection_truncated"] = True
    if len(json.dumps(projected, default=str, separators=(",", ":")).encode()) <= (
        MAX_COLLECTION_ITEM_BYTES
    ):
        return projected

    # Preserve identity and useful summary fields even for pathological nested
    # tool output or finding evidence.
    compact: dict[str, Any] = {
        key: terminal_projection(item[key], max_string=8 * 1024, max_items=10)
        for key in (
            "id",
            "version",
            "type",
            "agent_id",
            "timestamp",
            "title",
            "severity",
            "description",
        )
        if key in item
    }
    compact["projection_truncated"] = True
    return compact


def bounded_state_projection(state: dict[str, Any]) -> dict[str, Any]:
    """Keep mutable control state comfortably below the 64 KiB frame limit."""

    def encoded_size(value: dict[str, Any]) -> int:
        return len(
            json.dumps(value, default=str, ensure_ascii=False, separators=(",", ":")).encode()
        )

    if encoded_size(state) <= STATE_TARGET_BYTES:
        return state

    state["projection_truncated"] = True
    state["targets"] = [
        terminal_projection(target, max_string=64) for target in state["targets"][:8]
    ]
    state["instruction"] = terminal_projection(state["instruction"], max_string=512)
    state["messages"] = [
        {
            **message,
            "text": terminal_projection(message.get("text", ""), max_string=128),
        }
        for message in state["messages"][-5:]
    ]
    state["usage"] = {}
    state["error"] = terminal_projection(state["error"], max_string=512)
    state["model_warning"] = terminal_projection(state["model_warning"], max_string=256)
    state["caido_url"] = terminal_projection(state["caido_url"], max_string=256)
    state["viewer_url"] = terminal_projection(state["viewer_url"], max_string=256)
    if encoded_size(state) <= STATE_TARGET_BYTES:
        return state

    # Defensive final projection: use an explicit schema so future snapshot
    # fields cannot silently bypass the aggregate byte budget.
    return {
        "setup_mode": state["setup_mode"],
        "scan_started": state["scan_started"],
        "scan_state": state["scan_state"],
        "targets": state["targets"][:4],
        "target_count": state["target_count"],
        "instruction": terminal_projection(state["instruction"], max_string=128),
        "scan_mode": state["scan_mode"],
        "max_budget_usd": state["max_budget_usd"],
        "max_turns": state["max_turns"],
        "scope_mode": state["scope_mode"],
        "diff_base": state["diff_base"],
        "provider": state["provider"],
        "model": state["model"],
        "model_warning": "",
        "caido_url": None,
        "messages": [],
        "usage": {},
        "viewer_status": state["viewer_status"],
        "viewer_url": None,
        "error": terminal_projection(state["error"], max_string=256),
        "projection_truncated": True,
    }


def provider_record(provider: str) -> dict[str, Any]:
    status = provider_auth_status(provider)
    source = provider_credential_source(provider)
    item = custom_provider(provider)
    key_env = None if item is not None else provider_api_key_env(provider)
    if item is None and (
        source == "env"
        or (status.state is not ProviderAuthState.INVALID and resolve_provider_api_key(provider))
    ):
        key_env = None
    return {
        "name": provider,
        "label": provider_display_name(provider),
        "configured": status.ready,
        "key_env": key_env,
        "custom": item is not None,
        "state": status.state.value,
        "detail": status.detail,
        "source": source,
        "disconnectable": provider_can_disconnect(provider),
    }


@dataclass(frozen=True)
class ModelListing:
    expires_at: float
    pages: tuple[dict[str, Any], ...]
