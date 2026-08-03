"""UI-independent state and command controller for interactive Strix clients."""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import secrets
import time
import webbrowser
from collections.abc import Awaitable, Callable
from copy import deepcopy
from pathlib import Path
from typing import TYPE_CHECKING, Any

from strix.config import (
    CUSTOM_PROVIDER_ADD,
    configured_provider_model_groups,
    custom_provider,
    disconnect_provider,
    list_providers,
    load_settings,
    persist_selected_model,
    provider_auth_status,
    provider_for_model,
    save_custom_provider,
    set_custom_provider_enabled,
    set_provider_api_key,
)
from strix.config.models import is_recommended_or_frontier_model
from strix.config.settings import DEFAULT_MAX_TURNS
from strix.interface.tui.backend.live_view import TuiLiveView
from strix.interface.tui.backend.projection import (
    MAX_MODEL_LISTINGS,
    MAX_TERMINAL_EVENTS,
    MAX_TERMINAL_VULNERABILITIES,
    MODEL_GROUP_TARGET_BYTES,
    MODEL_LISTING_TTL_SECONDS,
    MODEL_PAGE_TARGET_BYTES,
    SCAN_MODES,
    SCOPE_MODES,
    ModelListing,
    bounded_state_projection,
    collection_item_projection,
    provider_record,
    sanitize_terminal_text,
    terminal_projection,
)
from strix.interface.utils import check_mountable_dir, is_subscription_run, read_target_list_file


if TYPE_CHECKING:
    import argparse

    from strix.report.state import ReportState


_STOPPABLE_AGENT_STATUSES = frozenset({"running", "waiting", "budget_paused"})

ChangeCallback = Callable[[], None]
StartCallback = Callable[[bool], Awaitable[None]]
QuitCallback = Callable[[], Awaitable[None]]


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
        self.setup_mode = bool(args.needs_setup)
        self.scan_started = not self.setup_mode
        self._start_in_progress = False
        self.scan_state = "setup" if self.setup_mode else "running"
        self.targets = [
            str(target["original"])
            for target in args.targets_info
            if isinstance(target, dict) and target.get("original")
        ]
        instruction = args.instruction
        self.instruction = instruction.strip() if isinstance(instruction, str) else ""
        requested_scan_mode = str(args.scan_mode)
        self.scan_mode = requested_scan_mode if requested_scan_mode in SCAN_MODES else "deep"
        raw_budget = args.max_budget_usd
        self.max_budget_usd = (
            float(raw_budget)
            if isinstance(raw_budget, int | float)
            and not isinstance(raw_budget, bool)
            and math.isfinite(float(raw_budget))
            and raw_budget > 0
            else None
        )
        raw_turns = args.max_turns
        self.max_turns = (
            raw_turns
            if isinstance(raw_turns, int) and not isinstance(raw_turns, bool) and raw_turns > 0
            else DEFAULT_MAX_TURNS
        )
        requested_scope = str(args.scope_mode)
        self.scope_mode = requested_scope if requested_scope in SCOPE_MODES else "auto"
        raw_diff_base = args.diff_base
        self.diff_base = raw_diff_base.strip() if isinstance(raw_diff_base, str) else None
        # Host directory mounted for the agent to work in when the scan has no
        # target, set only once the user confirms it. It is a workspace, not a
        # target: it carries no scan scope, and the instruction is the only
        # source of truth for what to do.
        self.workspace_mount: str | None = None
        # A target-less launch enters the live view and asks there before
        # anything is prepared; this holds the directory awaiting that answer.
        self.pending_workspace_mount: str | None = None
        self._pending_verify = True
        self.messages: list[dict[str, str]] = []
        self._next_message_id = 1
        self._model_listings: dict[str, ModelListing] = {}
        self.error: str | None = None
        self.viewer_status = "idle"
        self.viewer_url: str | None = None
        self._viewer_httpd: Any = None
        self._on_start = on_start
        self._on_quit = on_quit
        self._on_change = on_change
        if self.setup_mode:
            invalid_provider = args.setup_invalid_provider
            guidance = args.setup_guidance
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

    def begin_preparation(self) -> None:
        """Mark a directly-launched run as preparing behind the live TUI."""
        self.scan_state = "preparing"
        self.notify_changed()

    def fail_preparation(self, detail: str) -> None:
        self.scan_state = "failed"
        self.error = detail
        self.notify_changed()

    def enter_setup(self, *, provider: str | None = None, guidance: str | None = None) -> None:
        """Drop a live session into the setup flow, e.g. on a rejected key."""
        self.setup_mode = True
        self.scan_started = False
        self.scan_state = "setup"
        if provider and provider.strip():
            self._append_message(f"Provider requiring setup: {provider.strip()}", "warning")
        if guidance and guidance.strip():
            self._append_message(guidance.strip(), "warning")
        self.notify_changed()

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
        subscription = False
        with contextlib.suppress(Exception):
            subscription = is_subscription_run(self.report_state)
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
                terminal_projection(target, max_string=128) for target in self.targets[:16]
            ],
            "target_count": len(self.targets),
            "working_dir": str(Path.cwd()),
            "pending_mount": self.pending_workspace_mount or "",
            "instruction": terminal_projection(self.instruction, max_string=2 * 1024),
            "scan_mode": self.scan_mode,
            "max_budget_usd": self.max_budget_usd,
            "max_turns": self.max_turns,
            "scope_mode": self.scope_mode,
            "diff_base": terminal_projection(self.diff_base, max_string=256),
            "provider": terminal_projection(provider_for_model(model), max_string=256),
            "model": terminal_projection(model, max_string=256),
            "model_warning": terminal_projection(model_warning, max_string=512),
            "caido_url": terminal_projection(
                getattr(self.report_state, "caido_url", None), max_string=1024
            ),
            "messages": [
                {
                    "id": str(message.get("id", ""))[:64],
                    "text": terminal_projection(message.get("text", ""), max_string=256),
                    "level": str(message.get("level", "info"))[:32],
                }
                for message in self.messages[-10:]
            ],
            "usage": terminal_projection(usage, max_string=256, max_items=20),
            "subscription": subscription,
            "viewer_status": self.viewer_status,
            "viewer_url": terminal_projection(self.viewer_url, max_string=1024),
            "error": terminal_projection(self.error, max_string=2 * 1024),
        }
        return bounded_state_projection(state)

    def collection(self, name: str) -> list[dict[str, Any]]:
        """Return one bounded terminal projection with stable item identities."""
        if name == "agents":
            return [
                {
                    key: terminal_projection(agent.get(key), max_string=256, max_items=5)
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
            return [collection_item_projection(event) for event in self.live_view.events]
        if name == "vulnerabilities":
            reports = (
                self.report_state.vulnerability_reports if self.report_state is not None else []
            )[-MAX_TERMINAL_VULNERABILITIES:]
            result: list[dict[str, Any]] = []
            for index, report in enumerate(reports):
                projected = collection_item_projection(report)
                report_id = projected.get("id")
                if not isinstance(report_id, str) or not report_id:
                    projected["id"] = f"vulnerability-{index}"
                result.append(projected)
            return result
        raise ValueError(f"Unknown collection: {name}")

    def collection_snapshot(self, name: str) -> tuple[int | None, list[dict[str, Any]]]:
        """Return a collection cursor and complete bounded projection."""
        if name == "events":
            cursor, events = self.live_view.event_snapshot(limit=MAX_TERMINAL_EVENTS)
            return cursor, [collection_item_projection(event) for event in events]
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
            collection_item_projection(event) for event in events[-MAX_TERMINAL_EVENTS:]
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
            "setup.confirm_mount": self._confirm_mount,
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
            return [provider_record(provider) for provider in list_providers()]

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
                "provider": terminal_projection(group.provider, max_string=512),
                "label": terminal_projection(group.label, max_string=512),
                "models": [
                    terminal_projection(model, max_string=4 * 1024) for model in group.models
                ],
                "allow_manual": group.allow_manual,
                "error": terminal_projection(group.error or "", max_string=4 * 1024),
            }
            for group in groups
        ]
        providers: list[dict[str, Any]] = []
        if not groups:
            providers = [
                terminal_projection(provider, max_string=4 * 1024, max_items=20)
                for provider in (await self._providers({}))["providers"]
            ]
        listing_id = secrets.token_urlsafe(18)
        pages = tuple(self._model_listing_pages(listing_id, group_records, providers))
        now = time.monotonic()
        self._prune_model_listings(now)
        if len(self._model_listings) >= MAX_MODEL_LISTINGS:
            oldest = min(self._model_listings, key=lambda key: self._model_listings[key].expires_at)
            self._model_listings.pop(oldest, None)
        self._model_listings[listing_id] = ModelListing(
            expires_at=now + MODEL_LISTING_TTL_SECONDS,
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
                if fragment and TuiController._json_size(candidate) > MODEL_GROUP_TARGET_BYTES:
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
                TuiController._json_size(candidate) > MODEL_PAGE_TARGET_BYTES
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
        return await asyncio.to_thread(provider_record, provider)

    async def _disconnect_provider(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        provider = self._required_string(payload, "provider")
        if provider not in await asyncio.to_thread(list_providers):
            raise ValueError(f"Unknown provider: {provider}")
        await asyncio.to_thread(disconnect_provider, provider)
        return await asyncio.to_thread(provider_record, provider)

    async def _save_api_key(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        provider = self._required_string(payload, "provider")
        api_key = self._required_string(payload, "api_key")
        await asyncio.to_thread(set_provider_api_key, provider, api_key)
        return await asyncio.to_thread(provider_record, provider)

    async def _add_custom_provider(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        name = self._required_string(payload, "name")
        api_base = self._required_string(payload, "api_base")
        kind = self._required_string(payload, "kind").lower()
        raw_key = payload.get("api_key", "")
        if not isinstance(raw_key, str):
            raise TypeError("api_key must be a string")
        item = await asyncio.to_thread(save_custom_provider, name, api_base, raw_key, kind)
        return await asyncio.to_thread(provider_record, item.id)

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

        def resolve_mount_path() -> str:
            path = Path(raw_path).expanduser()
            try:
                resolved = path.resolve()
                is_dir = resolved.is_dir()
            except (OSError, RuntimeError) as e:
                raise ValueError(f"Invalid mount path '{raw_path}': {e!s}") from e
            if not is_dir:
                raise ValueError(
                    f"Mount path '{raw_path}' is not an existing directory. "
                    "/mount requires a path to a local directory."
                )
            check_mountable_dir(resolved)
            return str(resolved)

        mount = await asyncio.to_thread(resolve_mount_path)
        if mount not in self.targets:
            self.targets.append(mount)
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

    async def _start(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.scan_started or self._start_in_progress:
            raise RuntimeError("Scan is already starting or running")
        # A bare prompt launches optimistically, like a coding agent: it skips
        # the network model preflight and surfaces any model error live. A named
        # target keeps the preflight so a real scan does not commit blind.
        verify = payload.get("verify", True)
        if not isinstance(verify, bool):
            raise TypeError("verify must be a boolean")
        # Launching with no target mounts the working directory, so it requires
        # the user's explicit confirmation rather than happening silently.
        mount_working_dir = payload.get("mount_working_dir", False)
        if not isinstance(mount_working_dir, bool):
            raise TypeError("mount_working_dir must be a boolean")
        model = (load_settings().llm.model or "").strip()
        if not model:
            raise ValueError("No model configured. Select a provider and model first.")
        provider = provider_for_model(model) or "openai"
        if not (await asyncio.to_thread(provider_auth_status, provider)).ready:
            raise ValueError(f"Provider '{provider}' is not configured")
        if self._on_start is None:
            raise RuntimeError("Scan start is unavailable")
        if not self.targets:
            if not mount_working_dir:
                raise ValueError("No target set. Add a target first.")
            # Mounting the working directory needs the user's confirmation, and
            # that is asked in the live view. Enter it now and prepare nothing
            # until the answer arrives, so declining leaves no run behind.
            self.pending_workspace_mount = str(Path.cwd())
            self._pending_verify = verify
            self.setup_mode = False
            self.scan_started = True
            self.scan_state = "preparing"
            return {"started": True}
        await self._begin_scan(verify)
        return {"started": True}

    async def _begin_scan(self, verify: bool) -> None:
        if self._on_start is None:
            raise RuntimeError("Scan start is unavailable")
        self._start_in_progress = True
        try:
            await self._on_start(verify)
        finally:
            self._start_in_progress = False
        self.setup_mode = False
        self.scan_started = True
        self.scan_state = "running"

    async def _confirm_mount(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Answer the pending working-directory mount asked for in the live view."""
        mount = self.pending_workspace_mount
        if mount is None:
            raise RuntimeError("No mount confirmation is pending")
        approved = payload.get("approved")
        if not isinstance(approved, bool):
            raise TypeError("approved must be a boolean")
        self.pending_workspace_mount = None
        if not approved:
            # Nothing was prepared, so return to the start screen untouched.
            self.workspace_mount = None
            self.enter_setup()
            return {"approved": False}
        self.workspace_mount = mount
        await self._begin_scan(self._pending_verify)
        return {"approved": True}

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
            from strix.interface.tui.backend.messages import (
                send_user_message_to_agent,
            )
            from strix.interface.viewer.server import (
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
                from strix.telemetry import posthog

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
