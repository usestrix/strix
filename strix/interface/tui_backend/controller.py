"""UI-independent state and command controller for interactive Strix clients."""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import re
import secrets
import time
import webbrowser
from collections.abc import Awaitable, Callable
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from strix.config import (
    CUSTOM_PROVIDER_ADD,
    ProviderAuthState,
    configured_provider_model_groups,
    custom_provider,
    disconnect_provider,
    list_providers,
    load_settings,
    persist_selected_model,
    provider_api_key_env,
    provider_auth_status,
    provider_can_disconnect,
    provider_credential_source,
    provider_display_name,
    provider_for_model,
    resolve_provider_api_key,
    save_custom_provider,
    set_custom_provider_enabled,
    set_provider_api_key,
)
from strix.config.models import is_recommended_or_frontier_model
from strix.core.inputs import DEFAULT_MAX_TURNS
from strix.interface.tui_backend.live_view import TuiLiveView
from strix.interface.utils import build_mount_targets_info, read_target_list_file


if TYPE_CHECKING:
    import argparse

    from strix.report.state import ReportState


ChangeCallback = Callable[[], None]
StartCallback = Callable[[], Awaitable[None]]
QuitCallback = Callable[[], Awaitable[None]]
SCAN_MODES = ("quick", "standard", "deep")
SCOPE_MODES = ("auto", "diff", "full")
_STOPPABLE_AGENT_STATUSES = frozenset({"running", "waiting", "budget_paused"})
_MAX_PROJECTION_STRING = 64 * 1024
_MAX_COLLECTION_ITEM_BYTES = 512 * 1024
_MAX_TERMINAL_EVENTS = 5_000
_MAX_TERMINAL_VULNERABILITIES = 1_000
_MODEL_LISTING_TTL_SECONDS = 60.0
_MAX_MODEL_LISTINGS = 32
_MODEL_GROUP_TARGET_BYTES = 24 * 1024
_MODEL_PAGE_TARGET_BYTES = 48 * 1024
_STATE_TARGET_BYTES = 48 * 1024
_TERMINAL_ESCAPE_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_][0-?]*[ -/]*[@-~]")


def sanitize_terminal_text(value: str) -> str:
    without_escapes = _TERMINAL_ESCAPE_RE.sub("", value)
    return "".join(
        character
        for character in without_escapes
        if character in "\n\t" or (ord(character) >= 32 and not 127 <= ord(character) <= 159)
    )


def _terminal_projection(  # noqa: PLR0911
    value: Any,
    *,
    max_string: int = _MAX_PROJECTION_STRING,
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
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if depth >= 8:
        return "[nested value omitted from terminal projection]"
    if isinstance(value, dict):
        items = list(value.items())
        projected = {
            sanitize_terminal_text(str(key)): _terminal_projection(
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
    if isinstance(value, (list, tuple)):
        projected_items = [
            _terminal_projection(
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
    return _terminal_projection(
        str(value),
        max_string=max_string,
        max_items=max_items,
        depth=depth,
    )


def _collection_item_projection(item: dict[str, Any]) -> dict[str, Any]:
    projected = _terminal_projection(item)
    assert isinstance(projected, dict)
    if len(json.dumps(projected, default=str, separators=(",", ":")).encode()) <= (
        _MAX_COLLECTION_ITEM_BYTES
    ):
        return projected

    projected = _terminal_projection(item, max_string=8 * 1024, max_items=40)
    assert isinstance(projected, dict)
    projected["projection_truncated"] = True
    if len(json.dumps(projected, default=str, separators=(",", ":")).encode()) <= (
        _MAX_COLLECTION_ITEM_BYTES
    ):
        return projected

    # Preserve identity and useful summary fields even for pathological nested
    # tool output or finding evidence.
    compact: dict[str, Any] = {
        key: _terminal_projection(item[key], max_string=8 * 1024, max_items=10)
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


def _bounded_state_projection(state: dict[str, Any]) -> dict[str, Any]:
    """Keep mutable control state comfortably below the 64 KiB frame limit."""

    def encoded_size(value: dict[str, Any]) -> int:
        return len(
            json.dumps(value, default=str, ensure_ascii=False, separators=(",", ":")).encode()
        )

    if encoded_size(state) <= _STATE_TARGET_BYTES:
        return state

    state["projection_truncated"] = True
    state["targets"] = [
        _terminal_projection(target, max_string=64) for target in state["targets"][:8]
    ]
    state["mounts"] = [_terminal_projection(mount, max_string=64) for mount in state["mounts"][:8]]
    state["instruction"] = _terminal_projection(state["instruction"], max_string=512)
    state["messages"] = [
        {
            **message,
            "text": _terminal_projection(message.get("text", ""), max_string=128),
        }
        for message in state["messages"][-5:]
    ]
    state["usage"] = {}
    state["error"] = _terminal_projection(state["error"], max_string=512)
    state["model_warning"] = _terminal_projection(state["model_warning"], max_string=256)
    state["caido_url"] = _terminal_projection(state["caido_url"], max_string=256)
    state["viewer_url"] = _terminal_projection(state["viewer_url"], max_string=256)
    if encoded_size(state) <= _STATE_TARGET_BYTES:
        return state

    # Defensive final projection: use an explicit schema so future snapshot
    # fields cannot silently bypass the aggregate byte budget.
    return {
        "setup_mode": state["setup_mode"],
        "scan_started": state["scan_started"],
        "scan_state": state["scan_state"],
        "targets": state["targets"][:4],
        "target_count": state["target_count"],
        "mounts": state["mounts"][:4],
        "mount_count": state["mount_count"],
        "instruction": _terminal_projection(state["instruction"], max_string=128),
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
        "error": _terminal_projection(state["error"], max_string=256),
        "projection_truncated": True,
    }


def _provider_record(provider: str) -> dict[str, Any]:
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
class _ModelListing:
    expires_at: float
    pages: tuple[dict[str, Any], ...]


class TuiController:
    """Own setup state and expose serializable scan state to any TUI."""

    def __init__(
        self,
        args: argparse.Namespace,
        *,
        live_view: TuiLiveView | None = None,
        coordinator: Any = None,
        report_state: ReportState | None = None,
        on_start: StartCallback | None = None,
        on_quit: QuitCallback | None = None,
        on_change: ChangeCallback | None = None,
    ) -> None:
        self.args = args
        self.live_view = live_view or TuiLiveView()
        self.coordinator = coordinator
        self.report_state = report_state
        self.scan_loop: asyncio.AbstractEventLoop | None = None
        self.setup_mode = bool(getattr(args, "needs_setup", False))
        self.scan_started = not self.setup_mode
        self._start_in_progress = False
        self.scan_state = "setup" if self.setup_mode else "running"
        self.targets = [
            str(target["original"])
            for target in getattr(args, "targets_info", [])
            if isinstance(target, dict) and target.get("original")
        ]
        self.mounts = [
            str(target["original"])
            for target in getattr(args, "targets_info", [])
            if isinstance(target, dict)
            and target.get("original")
            and bool(target.get("details", {}).get("mount"))
        ]
        instruction = getattr(args, "instruction", "")
        self.instruction = instruction.strip() if isinstance(instruction, str) else ""
        requested_scan_mode = str(getattr(args, "scan_mode", "deep"))
        self.scan_mode = requested_scan_mode if requested_scan_mode in SCAN_MODES else "deep"
        raw_budget = getattr(args, "max_budget_usd", None)
        self.max_budget_usd = (
            float(raw_budget)
            if isinstance(raw_budget, int | float)
            and not isinstance(raw_budget, bool)
            and math.isfinite(float(raw_budget))
            and raw_budget > 0
            else None
        )
        raw_turns = getattr(args, "max_turns", DEFAULT_MAX_TURNS)
        self.max_turns = (
            raw_turns
            if isinstance(raw_turns, int) and not isinstance(raw_turns, bool) and raw_turns > 0
            else DEFAULT_MAX_TURNS
        )
        requested_scope = str(getattr(args, "scope_mode", "auto"))
        self.scope_mode = requested_scope if requested_scope in SCOPE_MODES else "auto"
        raw_diff_base = getattr(args, "diff_base", None)
        self.diff_base = raw_diff_base.strip() if isinstance(raw_diff_base, str) else None
        self.messages: list[dict[str, str]] = []
        self._next_message_id = 1
        self._model_listings: dict[str, _ModelListing] = {}
        self.error: str | None = None
        self.viewer_status = "idle"
        self.viewer_url: str | None = None
        self._viewer_httpd: Any = None
        self._on_start = on_start
        self._on_quit = on_quit
        self._on_change = on_change
        if self.setup_mode:
            invalid_provider = getattr(args, "setup_invalid_provider", None)
            guidance = getattr(args, "setup_guidance", None)
            if isinstance(invalid_provider, str) and invalid_provider.strip():
                self._append_message(
                    f"Provider requiring setup: {invalid_provider.strip()}",
                    "warning",
                )
            if isinstance(guidance, str) and guidance.strip():
                self._append_message(guidance.strip(), "warning")

    def set_change_callback(self, callback: ChangeCallback) -> None:
        self._on_change = callback

    def notify_changed(self) -> None:
        if self._on_change is not None:
            self._on_change()

    def set_runtime(
        self,
        *,
        report_state: ReportState | None = None,
        scan_loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        if report_state is not None:
            self.report_state = report_state
        if scan_loop is not None:
            self.scan_loop = scan_loop

    def add_message(self, text: str, level: str = "info") -> None:
        self._append_message(text, level)
        self.notify_changed()

    def _append_message(self, text: str, level: str) -> None:
        self.messages.append(
            {
                "id": f"message-{self._next_message_id}",
                "text": sanitize_terminal_text(text),
                "level": sanitize_terminal_text(level),
            }
        )
        self._next_message_id += 1
        self.messages = self.messages[-200:]

    def snapshot(self) -> dict[str, Any]:
        """Return small mutable state; histories are streamed as collections."""
        model = ""
        with contextlib.suppress(Exception):
            model = (load_settings().llm.model or "").strip()
        usage: dict[str, Any] = {}
        if self.report_state is not None:
            usage = dict(self.report_state.get_total_llm_usage())
        model_warning = ""
        if model and not is_recommended_or_frontier_model(model):
            model_warning = (
                f"{model} is not a recommended frontier model; pentest quality could be degraded"
            )
        state = {
            "setup_mode": self.setup_mode,
            "scan_started": self.scan_started,
            "scan_state": self.scan_state,
            "targets": [
                _terminal_projection(target, max_string=128) for target in self.targets[:16]
            ],
            "target_count": len(self.targets),
            "mounts": [_terminal_projection(mount, max_string=128) for mount in self.mounts[:16]],
            "mount_count": len(self.mounts),
            "instruction": _terminal_projection(self.instruction, max_string=2 * 1024),
            "scan_mode": self.scan_mode,
            "max_budget_usd": self.max_budget_usd,
            "max_turns": self.max_turns,
            "scope_mode": self.scope_mode,
            "diff_base": _terminal_projection(self.diff_base, max_string=256),
            "provider": _terminal_projection(provider_for_model(model), max_string=256),
            "model": _terminal_projection(model, max_string=256),
            "model_warning": _terminal_projection(model_warning, max_string=512),
            "caido_url": _terminal_projection(
                getattr(self.report_state, "caido_url", None), max_string=1024
            ),
            "messages": [
                {
                    "id": str(message.get("id", ""))[:64],
                    "text": _terminal_projection(message.get("text", ""), max_string=256),
                    "level": str(message.get("level", "info"))[:32],
                }
                for message in self.messages[-10:]
            ],
            "usage": _terminal_projection(usage, max_string=256, max_items=20),
            "viewer_status": self.viewer_status,
            "viewer_url": _terminal_projection(self.viewer_url, max_string=1024),
            "error": _terminal_projection(self.error, max_string=2 * 1024),
        }
        return _bounded_state_projection(state)

    def collection(self, name: str) -> list[dict[str, Any]]:
        """Return one bounded terminal projection with stable item identities."""
        if name == "agents":
            return [
                {
                    key: _terminal_projection(agent.get(key), max_string=256, max_items=5)
                    for key in (
                        "id",
                        "name",
                        "parent_id",
                        "status",
                        "error_message",
                        "created_at",
                        "updated_at",
                    )
                    if key in agent
                }
                for agent in self.live_view.agents.values()
            ]
        if name == "events":
            return [_collection_item_projection(event) for event in self.live_view.events]
        if name == "vulnerabilities":
            reports = (
                self.report_state.vulnerability_reports if self.report_state is not None else []
            )[-_MAX_TERMINAL_VULNERABILITIES:]
            result: list[dict[str, Any]] = []
            for index, report in enumerate(reports):
                projected = _collection_item_projection(report)
                report_id = projected.get("id")
                if not isinstance(report_id, str) or not report_id:
                    projected["id"] = f"vulnerability-{index}"
                result.append(projected)
            return result
        raise ValueError(f"Unknown collection: {name}")

    def collection_snapshot(self, name: str) -> tuple[int | None, list[dict[str, Any]]]:
        """Return a collection cursor and complete bounded projection."""
        if name == "events":
            cursor, events = self.live_view.event_snapshot(limit=_MAX_TERMINAL_EVENTS)
            return cursor, [_collection_item_projection(event) for event in events]
        return None, self.collection(name)

    def collection_changes(
        self,
        name: str,
        cursor: int,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Return event upserts since a monotonic source cursor."""
        if name != "events":
            raise ValueError(f"Collection {name!r} does not expose incremental changes")
        next_cursor, events = self.live_view.event_changes_since(cursor)
        return next_cursor, [
            _collection_item_projection(event) for event in events[-_MAX_TERMINAL_EVENTS:]
        ]

    async def handle(self, command: str, payload: dict[str, Any]) -> dict[str, Any]:
        handlers = {
            "providers.list": self._providers,
            "models.list": self._models,
            "setup.select_provider": self._select_provider,
            "setup.save_api_key": self._save_api_key,
            "setup.disconnect_provider": self._disconnect_provider,
            "setup.add_custom_provider": self._add_custom_provider,
            "setup.select_model": self._select_model,
            "setup.add_target": self._add_target,
            "setup.add_mount": self._add_mount,
            "setup.load_target_list": self._load_target_list,
            "setup.clear_targets": self._clear_targets,
            "setup.set_instruction": self._set_instruction,
            "setup.load_instruction_file": self._load_instruction_file,
            "setup.set_mode": self._set_mode,
            "setup.set_budget": self._set_budget,
            "setup.set_max_turns": self._set_max_turns,
            "setup.set_scope": self._set_scope,
            "setup.start": self._start,
            "agent.send_message": self._send_message,
            "agent.stop": self._stop_agent,
            "viewer.open": self._open_viewer,
            "app.quit": self._quit,
        }
        handler = handlers.get(command)
        if handler is None:
            raise ValueError(f"Unknown command: {command}")
        result = await handler(payload)
        self.notify_changed()
        return result

    async def _providers(self, _payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()

        def rows() -> list[dict[str, Any]]:
            return [_provider_record(provider) for provider in list_providers()]

        return {
            "providers": await asyncio.to_thread(rows)
            + [
                {
                    "name": CUSTOM_PROVIDER_ADD,
                    "label": "+ Add custom provider",
                    "configured": True,
                    "key_env": None,
                    "custom": True,
                    "state": "configured",
                    "detail": "",
                    "source": None,
                    "disconnectable": False,
                }
            ]
        }

    async def _models(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        listing_id = payload.get("listing_id")
        cursor = payload.get("cursor")
        if listing_id is None and cursor is None:
            return await self._new_model_listing()
        if not isinstance(listing_id, str) or not listing_id:
            raise ValueError("listing_id must be a non-empty string")
        if not isinstance(cursor, int) or isinstance(cursor, bool) or cursor < 0:
            raise ValueError("cursor must be a non-negative integer")

        now = time.monotonic()
        self._prune_model_listings(now)
        listing = self._model_listings.get(listing_id)
        if listing is None or listing.expires_at <= now:
            self._model_listings.pop(listing_id, None)
            raise ValueError("Model listing expired or is unknown; request a new listing")
        if cursor >= len(listing.pages):
            raise ValueError("cursor is outside the model listing")
        return self._model_page(listing_id, listing.pages, cursor)

    async def _new_model_listing(self) -> dict[str, Any]:
        current_model = (load_settings().llm.model or "").strip()
        groups = await configured_provider_model_groups(current_model=current_model)
        group_records = [
            {
                "provider": _terminal_projection(group.provider, max_string=512),
                "label": _terminal_projection(group.label, max_string=512),
                "models": [
                    _terminal_projection(model, max_string=4 * 1024) for model in group.models
                ],
                "allow_manual": group.allow_manual,
                "error": _terminal_projection(group.error or "", max_string=4 * 1024),
            }
            for group in groups
        ]
        providers: list[dict[str, Any]] = []
        if not groups:
            providers = [
                _terminal_projection(provider, max_string=4 * 1024, max_items=20)
                for provider in (await self._providers({}))["providers"]
            ]
        listing_id = secrets.token_urlsafe(18)
        pages = tuple(self._model_listing_pages(listing_id, group_records, providers))
        now = time.monotonic()
        self._prune_model_listings(now)
        if len(self._model_listings) >= _MAX_MODEL_LISTINGS:
            oldest = min(self._model_listings, key=lambda key: self._model_listings[key].expires_at)
            self._model_listings.pop(oldest, None)
        self._model_listings[listing_id] = _ModelListing(
            expires_at=now + _MODEL_LISTING_TTL_SECONDS,
            pages=pages,
        )
        return self._model_page(listing_id, pages, 0)

    def _prune_model_listings(self, now: float) -> None:
        for listing_id, listing in list(self._model_listings.items()):
            if listing.expires_at <= now:
                self._model_listings.pop(listing_id, None)

    @staticmethod
    def _model_page(
        listing_id: str,
        pages: tuple[dict[str, Any], ...],
        cursor: int,
    ) -> dict[str, Any]:
        return {
            "listing_id": listing_id,
            "cursor": cursor,
            "next_cursor": cursor + 1,
            "done": cursor + 1 == len(pages),
            "groups": deepcopy(pages[cursor]["groups"]),
            "providers": deepcopy(pages[cursor]["providers"]),
        }

    @staticmethod
    def _model_listing_pages(
        listing_id: str,
        groups: list[dict[str, Any]],
        providers: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        entries: list[tuple[str, dict[str, Any]]] = []
        for group in groups:
            base = {key: value for key, value in group.items() if key != "models"}
            models = group["models"]
            if not models:
                entries.append(("groups", {**base, "models": []}))
                continue
            fragment: list[str] = []
            for model in models:
                candidate = {**base, "models": [*fragment, model]}
                if fragment and TuiController._json_size(candidate) > _MODEL_GROUP_TARGET_BYTES:
                    entries.append(("groups", {**base, "models": fragment}))
                    fragment = [model]
                else:
                    fragment.append(model)
            entries.append(("groups", {**base, "models": fragment}))
        entries.extend(("providers", provider) for provider in providers)

        pages: list[dict[str, Any]] = []
        page: dict[str, list[dict[str, Any]]] = {"groups": [], "providers": []}
        for field, entry in entries:
            candidate = {
                "listing_id": listing_id,
                "cursor": len(pages),
                "next_cursor": len(pages) + 1,
                "done": False,
                "groups": list(page["groups"]),
                "providers": list(page["providers"]),
            }
            candidate[field].append(entry)
            if (page["groups"] or page["providers"]) and (
                TuiController._json_size(candidate) > _MODEL_PAGE_TARGET_BYTES
            ):
                pages.append(page)
                page = {"groups": [], "providers": []}
            page[field].append(entry)
        pages.append(page)
        return pages

    @staticmethod
    def _json_size(value: Any) -> int:
        return len(json.dumps(value, default=str, separators=(",", ":")).encode("utf-8"))

    async def _select_provider(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        provider = self._required_string(payload, "provider")
        if provider not in list_providers():
            raise ValueError(f"Unknown provider: {provider}")
        item = custom_provider(provider)
        if item and item.disabled:
            await asyncio.to_thread(set_custom_provider_enabled, provider, enabled=True)
        status = await asyncio.to_thread(provider_auth_status, provider)
        source = provider_credential_source(provider)
        key_env = provider_api_key_env(provider)
        if source == "env" or (
            status.state is not ProviderAuthState.INVALID and resolve_provider_api_key(provider)
        ):
            key_env = None
        return {
            "provider": provider,
            "label": provider_display_name(provider),
            "configured": status.ready,
            "key_env": key_env,
            "state": status.state.value,
            "detail": status.detail,
            "source": source,
            "disconnectable": provider_can_disconnect(provider),
        }

    async def _disconnect_provider(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        provider = self._required_string(payload, "provider")
        if provider not in await asyncio.to_thread(list_providers):
            raise ValueError(f"Unknown provider: {provider}")
        await asyncio.to_thread(disconnect_provider, provider)
        return await asyncio.to_thread(_provider_record, provider)

    async def _save_api_key(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        provider = self._required_string(payload, "provider")
        api_key = self._required_string(payload, "api_key")
        await asyncio.to_thread(set_provider_api_key, provider, api_key)
        status = await asyncio.to_thread(provider_auth_status, provider)
        return {
            "provider": provider,
            "label": provider_display_name(provider),
            "configured": status.ready,
            "state": status.state.value,
            "detail": status.detail,
            "source": provider_credential_source(provider),
            "disconnectable": provider_can_disconnect(provider),
        }

    async def _add_custom_provider(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        name = self._required_string(payload, "name")
        api_base = self._required_string(payload, "api_base")
        kind = self._required_string(payload, "kind").lower()
        raw_key = payload.get("api_key", "")
        if not isinstance(raw_key, str):
            raise TypeError("api_key must be a string")
        item = await asyncio.to_thread(save_custom_provider, name, api_base, raw_key, kind)
        return {
            "provider": item.id,
            "label": item.name,
            "configured": True,
            "custom": True,
            "state": "configured",
            "detail": f"{item.kind.replace('_', '.')} endpoint at {item.api_base}",
            "source": "custom",
            "disconnectable": True,
        }

    async def _select_model(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        provider = self._required_string(payload, "provider")
        model = self._required_string(payload, "model")
        if provider not in await asyncio.to_thread(list_providers):
            raise ValueError(f"Unknown provider: {provider}")
        if provider_for_model(model) != provider:
            raise ValueError(f"Model '{model}' does not belong to provider '{provider}'")
        item = custom_provider(provider)
        if item:
            prefix = f"{item.id}/"
            if not model.startswith(prefix) or not model[len(prefix) :].strip():
                raise ValueError(f"Model '{model}' is not valid for {item.name}")
        status = await asyncio.to_thread(provider_auth_status, provider)
        if not status.ready:
            raise ValueError(f"Provider '{provider}' is not configured")
        await asyncio.to_thread(persist_selected_model, model)
        return {"model": model}

    async def _add_target(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        target = self._required_string(payload, "target")
        if target not in self.targets:
            self.targets.append(target)
        return {"target": target, "total": len(self.targets)}

    async def _add_mount(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        raw_path = self._required_string(payload, "path")
        target = (await asyncio.to_thread(build_mount_targets_info, [raw_path]))[0]
        mount = str(target["original"])
        if mount not in self.targets:
            self.targets.append(mount)
        if mount not in self.mounts:
            self.mounts.append(mount)
        return {"mount": mount, "total": len(self.targets)}

    async def _load_target_list(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        path = self._required_string(payload, "path")
        targets = await asyncio.to_thread(read_target_list_file, path)
        added = 0
        for target in targets:
            if target in self.targets:
                continue
            self.targets.append(target)
            added += 1
        return {"path": path, "added": added, "total": len(self.targets)}

    async def _clear_targets(self, _payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        self.targets.clear()
        self.mounts.clear()
        return {"targets": []}

    async def _set_instruction(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        instruction = payload.get("instruction", "")
        if not isinstance(instruction, str):
            raise TypeError("instruction must be a string")
        self.instruction = instruction.strip()
        return {"instruction": self.instruction}

    async def _load_instruction_file(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        raw_path = self._required_string(payload, "path")
        path = Path(raw_path).expanduser()

        def read_instruction() -> str:
            if not path.is_file():
                raise ValueError(f"Instruction file '{raw_path}' is not an existing file")
            try:
                instruction = path.read_text(encoding="utf-8").strip()
            except UnicodeDecodeError as exc:
                raise ValueError(
                    f"Instruction file '{raw_path}' must be valid UTF-8 text: {exc!s}"
                ) from exc
            except OSError as exc:
                raise ValueError(f"Failed to read instruction file '{raw_path}': {exc!s}") from exc
            if not instruction:
                raise ValueError(f"Instruction file '{raw_path}' is empty")
            return instruction

        self.instruction = await asyncio.to_thread(read_instruction)
        return {"path": str(path), "characters": len(self.instruction)}

    async def _set_mode(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        scan_mode = self._required_string(payload, "mode").lower()
        if scan_mode not in SCAN_MODES:
            choices = ", ".join(SCAN_MODES)
            raise ValueError(f"mode must be one of: {choices}")
        self.scan_mode = scan_mode
        return {"mode": scan_mode}

    async def _set_budget(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        budget = payload.get("budget")
        if budget is None:
            self.max_budget_usd = None
        elif (
            isinstance(budget, bool)
            or not isinstance(budget, int | float)
            or not math.isfinite(float(budget))
            or budget <= 0
        ):
            raise ValueError("budget must be a finite number greater than 0, or null")
        else:
            self.max_budget_usd = float(budget)
        return {"budget": self.max_budget_usd}

    async def _set_max_turns(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        turns = payload.get("turns")
        if isinstance(turns, bool) or not isinstance(turns, int) or turns <= 0:
            raise ValueError("turns must be an integer greater than 0")
        self.max_turns = turns
        return {"turns": turns}

    async def _set_scope(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        scope_mode = self._required_string(payload, "mode").lower()
        if scope_mode not in SCOPE_MODES:
            choices = ", ".join(SCOPE_MODES)
            raise ValueError(f"scope mode must be one of: {choices}")
        self.scope_mode = scope_mode
        if "base" in payload:
            raw_base = payload["base"]
            if raw_base is not None and not isinstance(raw_base, str):
                raise TypeError("base must be a string or null")
            self.diff_base = raw_base.strip() if isinstance(raw_base, str) else None
            self.diff_base = self.diff_base or None
        elif scope_mode == "full":
            self.diff_base = None
        return {"mode": self.scope_mode, "base": self.diff_base}

    async def _start(self, _payload: dict[str, Any]) -> dict[str, Any]:
        if self.scan_started or self._start_in_progress:
            raise RuntimeError("Scan is already starting or running")
        model = (load_settings().llm.model or "").strip()
        if not model:
            raise ValueError("No model configured. Select a provider and model first.")
        provider = provider_for_model(model) or "openai"
        if not (await asyncio.to_thread(provider_auth_status, provider)).ready:
            raise ValueError(f"Provider '{provider}' is not configured")
        if not self.targets:
            raise ValueError("No target set. Add a target first.")
        if self._on_start is None:
            raise RuntimeError("Scan start is unavailable")
        self._start_in_progress = True
        try:
            await self._on_start()
        finally:
            self._start_in_progress = False
        self.setup_mode = False
        self.scan_started = True
        self.scan_state = "running"
        return {"started": True}

    async def _send_message(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = self._required_string(payload, "agent_id")
        message = self._required_string(payload, "message")
        if self.coordinator is None:
            raise RuntimeError("Agent coordinator is unavailable")
        if self.scan_loop is None or self.scan_loop.is_closed():
            raise RuntimeError("Scan loop is not ready")
        self.live_view.record_user_message(agent_id, message)
        if self.scan_loop is asyncio.get_running_loop():
            delivered = await self.coordinator.send(
                agent_id,
                {"from": "user", "content": message, "type": "instruction"},
            )
        else:
            future = asyncio.run_coroutine_threadsafe(
                self.coordinator.send(
                    agent_id,
                    {"from": "user", "content": message, "type": "instruction"},
                ),
                self.scan_loop,
            )
            delivered = await asyncio.wrap_future(future)
        if not delivered:
            raise RuntimeError("Message could not be delivered")
        return {"sent": True}

    async def _stop_agent(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = self._required_string(payload, "agent_id")
        agent = self.live_view.agents.get(agent_id)
        if agent is None:
            raise ValueError(f"Unknown agent: {agent_id}")
        status = str(agent.get("status", ""))
        if status not in _STOPPABLE_AGENT_STATUSES:
            raise RuntimeError(f"Agent '{agent_id}' cannot be stopped while {status or 'unknown'}")
        if self.coordinator is None or self.scan_loop is None or self.scan_loop.is_closed():
            raise RuntimeError("Scan loop is not ready")
        if self.scan_loop is asyncio.get_running_loop():
            accepted = await self.coordinator.cancel_descendants_graceful(agent_id)
        else:
            future = asyncio.run_coroutine_threadsafe(
                self.coordinator.cancel_descendants_graceful(agent_id), self.scan_loop
            )
            accepted = await asyncio.wrap_future(future)
        if not accepted:
            raise RuntimeError(f"Agent '{agent_id}' is no longer active")
        return {"stopped": True}

    async def _open_viewer(self, _payload: dict[str, Any]) -> dict[str, Any]:
        if self.viewer_url:
            with contextlib.suppress(Exception):
                webbrowser.open(self.viewer_url)
            return {"status": "running", "url": self.viewer_url}
        if self.report_state is None:
            self.viewer_status = "failed"
            return {"status": self.viewer_status, "error": "Scan output is not ready"}
        try:
            from strix.interface.tui_backend.messages import (  # noqa: PLC0415
                send_user_message_to_agent,
            )
            from strix.interface.viewer.server import (  # noqa: PLC0415
                authorized_url,
                bundle_is_built,
                serve,
            )

            if not bundle_is_built():
                self.viewer_status = "unavailable"
                return {"status": self.viewer_status, "error": "Viewer UI not built"}

            def steer(agent_id: str, message: str) -> bool:
                return send_user_message_to_agent(
                    coordinator=self.coordinator,
                    loop=self.scan_loop,
                    live_view=self.live_view,
                    target_agent_id=agent_id,
                    message=message,
                    notify_changed=self.notify_changed,
                    wait_for_delivery=True,
                )

            httpd, url, token = serve(
                self.report_state.get_run_dir(),
                open_browser=True,
                steer_handler=steer,
            )
            self._viewer_httpd = httpd
            self.viewer_url = authorized_url(url, token)
            self.viewer_status = "running"
            with contextlib.suppress(Exception):
                from strix.telemetry import posthog  # noqa: PLC0415

                live = self.report_state.run_record.get("status") not in {
                    "completed",
                    "stopped",
                    "failed",
                    "interrupted",
                }
                posthog.viewer_opened(source="tui", live=live)
        except Exception:  # noqa: BLE001 - viewer startup failures must not crash the TUI
            self.viewer_status = "failed"
            return {"status": self.viewer_status, "error": "Viewer failed to start"}
        else:
            return {"status": self.viewer_status, "url": self.viewer_url}

    def close_viewer(self) -> None:
        httpd = self._viewer_httpd
        if httpd is None:
            return
        self._viewer_httpd = None
        with contextlib.suppress(Exception):
            httpd.shutdown()
            httpd.server_close()

    async def _quit(self, _payload: dict[str, Any]) -> dict[str, Any]:
        self.close_viewer()
        if self._on_quit is not None:
            await self._on_quit()
        self.scan_state = "stopped"
        return {"quitting": True}

    @staticmethod
    def _required_string(payload: dict[str, Any], name: str) -> str:
        value = payload.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()

    def _require_setup_mutable(self) -> None:
        if not self.setup_mode or self.scan_started or self._start_in_progress:
            raise RuntimeError("Setup can no longer be changed after the scan starts")
