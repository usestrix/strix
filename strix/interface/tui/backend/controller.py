"""UI-independent state and command controller for interactive Strix clients."""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import webbrowser
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from strix.config import codex, connections, load_settings
from strix.config.settings import DEFAULT_MAX_TURNS
from strix.interface.tui.backend.live_view import TuiLiveView
from strix.interface.tui.backend.projection import (
    MAX_TERMINAL_EVENTS,
    MAX_TERMINAL_VULNERABILITIES,
    SCAN_MODES,
    SCOPE_MODES,
    bounded_state_projection,
    collection_item_projection,
    sanitize_terminal_text,
    terminal_projection,
)
from strix.interface.utils import is_subscription_run


if TYPE_CHECKING:
    import argparse

    from strix.report.state import ReportState


_STOPPABLE_AGENT_STATUSES = frozenset({"running", "waiting", "budget_paused"})

ChangeCallback = Callable[[], None]
StartCallback = Callable[[], Awaitable[None]]
VerifyCallback = Callable[[], Awaitable[None]]
QuitCallback = Callable[[], Awaitable[None]]
ModelChangedCallback = Callable[[], None]

_MODEL_LIST_BUDGET = 44 * 1024
_LOGIN_TIMEOUT_S = 300


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
        on_verify: VerifyCallback | None = None,
        on_quit: QuitCallback | None = None,
        on_change: ChangeCallback | None = None,
        on_model_changed: ModelChangedCallback | None = None,
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
        self.messages: list[dict[str, str]] = []
        self._next_message_id = 1
        self.error: str | None = None
        # The run's MCP connection roster (name / tool_count / dead), pushed by
        # the engine via the mcp_status_sink once the connections are established
        # and again each time one dies. Empty for a run with no MCP connections,
        # so the Go sidebar simply omits the panel. Non-secret by construction.
        self.mcp_connections: list[dict[str, Any]] = []
        self.viewer_status = "idle"
        self.viewer_url: str | None = None
        self._viewer_httpd: Any = None
        self._on_start = on_start
        self._on_verify = on_verify
        self._on_quit = on_quit
        self._on_change = on_change
        self._on_model_changed = on_model_changed
        self.login_state = ""
        self.login_error = ""
        self._login_server: Any = None
        self._login_task: asyncio.Task[None] | None = None

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

    def set_mcp_connections(self, roster: list[dict[str, Any]]) -> None:
        """Store the run's MCP connection roster and repaint.

        ``roster`` is the engine's non-secret status snapshot: one entry per
        connection carrying ``name``, ``tool_count``, and ``dead``. Called once
        when the connections are established (all healthy) and again whenever a
        connection dies (the same whole-roster snapshot, with that one now dead)."""
        self.mcp_connections = [
            {
                "name": str(entry.get("name", "")),
                "tool_count": int(entry.get("tool_count", 0) or 0),
                "dead": bool(entry.get("dead", False)),
            }
            for entry in roster
            if isinstance(entry, dict) and entry.get("name")
        ]
        self.notify_changed()

    def fail_preparation(self, detail: str) -> None:
        self.scan_state = "failed"
        self.error = detail
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
        effort = ""
        with contextlib.suppress(Exception):
            effort = str(load_settings().llm.reasoning_effort)
        usage: dict[str, Any] = {}
        if self.report_state is not None:
            usage = dict(self.report_state.get_total_llm_usage())
        subscription = False
        with contextlib.suppress(Exception):
            subscription = is_subscription_run(self.report_state)
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
            "model": terminal_projection(model, max_string=256),
            "effort": effort,
            "login_state": self.login_state,
            "login_error": terminal_projection(self.login_error, max_string=256),
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
            "connections": [
                {
                    "name": terminal_projection(entry["name"], max_string=64),
                    "tool_count": entry["tool_count"],
                    "dead": entry["dead"],
                }
                for entry in self.mcp_connections[:32]
            ],
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
            "setup.add_target": self._add_target,
            "setup.set_instruction": self._set_instruction,
            "setup.start": self._start,
            "setup.confirm_mount": self._confirm_mount,
            "agent.send_message": self._send_message,
            "agent.stop": self._stop_agent,
            "viewer.open": self._open_viewer,
            "models.list": self._models_list,
            "models.select": self._models_select,
            "models.favorite": self._models_favorite,
            "providers.list": self._providers_list,
            "providers.connect": self._providers_connect,
            "providers.disconnect": self._providers_disconnect,
            "providers.login": self._providers_login,
            "providers.login_cancel": self._providers_login_cancel,
            "settings.set": self._settings_set,
            "app.quit": self._quit,
        }
        handler = handlers.get(command)
        if handler is None:
            raise ValueError(f"Unknown command: {command}")
        result = await handler(payload)
        self.notify_changed()
        return result

    async def _add_target(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        target = self._required_string(payload, "target")
        if target not in self.targets:
            self.targets.append(target)
        return {"target": target, "total": len(self.targets)}

    async def _set_instruction(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        instruction = payload.get("instruction", "")
        if not isinstance(instruction, str):
            raise TypeError("instruction must be a string")
        self.instruction = instruction.strip()
        return {"instruction": self.instruction}

    async def _start(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.scan_started or self._start_in_progress:
            raise RuntimeError("Scan is already starting or running")
        # Launching with no target mounts the working directory, so it requires
        # the user's explicit confirmation rather than happening silently.
        mount_working_dir = payload.get("mount_working_dir", False)
        if not isinstance(mount_working_dir, bool):
            raise TypeError("mount_working_dir must be a boolean")
        model = (load_settings().llm.model or "").strip()
        if not model:
            raise ValueError("No model selected. Press ctrl+p and choose Switch model.")
        if self._on_start is None:
            raise RuntimeError("Scan start is unavailable")
        if not self.targets and not mount_working_dir:
            raise ValueError("No target set. Add a target first.")
        if not self.targets and self.scope_mode == "diff":
            # Diff scope resolves before the working directory is attached, so it
            # would fail after the mount prompt has already locked setup.
            raise ValueError("Diff scope needs a repository target. Add one or change the scope.")
        # The model check runs while still on the start screen, for a bare
        # prompt as much as for a named target, so a failure lands in the setup
        # log where the user can fix it and retry rather than in a dead run.
        await self._verify_model()
        if not self.targets:
            # Mounting the working directory needs the user's confirmation, and
            # that is asked in the live view. Enter it now and prepare nothing
            # until the answer arrives, so declining leaves no run behind.
            self.pending_workspace_mount = str(Path.cwd())
            self.setup_mode = False
            self.scan_started = True
            self.scan_state = "preparing"
            return {"started": True}
        await self._begin_scan()
        return {"started": True}

    async def _verify_model(self) -> None:
        if self._on_verify is None:
            return
        self._start_in_progress = True
        try:
            await self._on_verify()
        finally:
            self._start_in_progress = False

    async def _begin_scan(self) -> None:
        if self._on_start is None:
            raise RuntimeError("Scan start is unavailable")
        self._start_in_progress = True
        try:
            await self._on_start()
        except Exception as exc:
            if not self.setup_mode:
                # The live view is already up, so the failure has to show there.
                self.fail_preparation(str(exc))
            raise
        finally:
            self._start_in_progress = False
        self.setup_mode = False
        self.scan_started = True
        self.scan_state = "running"

    async def _models_list(self, _payload: dict[str, Any]) -> dict[str, Any]:
        picker = await asyncio.to_thread(connections.model_picker)
        providers = picker["providers"]
        while len(json.dumps(picker)) > _MODEL_LIST_BUDGET:
            largest = max(providers, key=lambda entry: len(entry["models"]))
            if len(largest["models"]) <= 1:
                break
            largest["models"] = largest["models"][: len(largest["models"]) * 3 // 4]
        return picker

    async def _models_select(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        provider = self._required_string(payload, "provider")
        model = self._required_string(payload, "model")
        connections.select_model(provider, model)
        if self._on_model_changed is not None:
            self._on_model_changed()
        return {"provider": provider, "model": model}

    async def _models_favorite(self, payload: dict[str, Any]) -> dict[str, Any]:
        provider = self._required_string(payload, "provider")
        model = self._required_string(payload, "model")
        return {
            "provider": provider,
            "model": model,
            "favorite": connections.toggle_favorite(provider, model),
        }

    async def _providers_list(self, _payload: dict[str, Any]) -> dict[str, Any]:
        return connections.provider_directory()

    async def _providers_connect(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        provider = self._required_string(payload, "provider")
        api_key = payload.get("api_key")
        api_base = payload.get("api_base")
        if api_key is not None and not isinstance(api_key, str):
            raise TypeError("api_key must be a string")
        if api_base is not None and not isinstance(api_base, str):
            raise TypeError("api_base must be a string")
        if provider in connections.SEARCH_SERVICES:
            connections.set_setting(provider, api_key)
            return {
                "provider": provider,
                "name": connections.SEARCH_SERVICES[provider],
                "models": 0,
            }
        connections.connect(provider, api_key=api_key, api_base=api_base)
        models = await asyncio.to_thread(connections.provider_models, provider)
        return {
            "provider": provider,
            "name": connections.get_provider(provider).name,
            "models": len(models),
        }

    async def _providers_disconnect(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        provider = self._required_string(payload, "provider")
        if provider in connections.SEARCH_SERVICES:
            connections.set_setting(provider, None)
        else:
            connections.disconnect(provider)
        return {"provider": provider}

    async def _providers_login(self, _payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        from strix.interface.auth_cli import start_callback_server

        self._stop_login()
        server = start_callback_server()
        if server is None:
            raise RuntimeError(
                f"Port {codex.CALLBACK_PORT} is busy. Run: strix auth login chatgpt --manual"
            )
        verifier, challenge = codex.generate_pkce()
        state = codex.create_state()
        url = codex.build_authorize_url(challenge, state)
        self._login_server = server
        self.login_state = "pending"
        self.login_error = ""
        self._login_task = asyncio.create_task(self._finish_login(server, verifier, state))
        with contextlib.suppress(Exception):
            webbrowser.open(url)
        return {"url": url}

    async def _finish_login(self, server: Any, verifier: str, state: str) -> None:
        try:
            result = await asyncio.to_thread(server.wait, _LOGIN_TIMEOUT_S)
            code = self._login_code(result, state)
            record = await asyncio.to_thread(codex.exchange_code, code, verifier)
            codex.save_record(record)
            self.login_state = "done"
        except Exception as exc:  # noqa: BLE001
            self.login_state = "error"
            self.login_error = str(exc)
        finally:
            if self._login_server is server:
                self._login_server = None
            with contextlib.suppress(Exception):
                await asyncio.to_thread(server.shutdown)
        self.notify_changed()

    @staticmethod
    def _login_code(result: tuple[str | None, str | None, str | None] | None, state: str) -> str:
        if result is None:
            raise codex.CodexAuthError("timeout", "Sign-in timed out")
        code, returned_state, error = result
        if error:
            raise codex.CodexAuthError("oauth_error", error)
        if not code or returned_state != state:
            raise codex.CodexAuthError("state_mismatch", "Sign-in could not be verified")
        return code

    def _stop_login(self) -> None:
        task, self._login_task = self._login_task, None
        server, self._login_server = self._login_server, None
        if task is not None:
            task.cancel()
        if server is not None:
            with contextlib.suppress(Exception):
                server.cancel()
        self.login_state = ""
        self.login_error = ""

    async def _providers_login_cancel(self, _payload: dict[str, Any]) -> dict[str, Any]:
        self._stop_login()
        return {}

    async def _settings_set(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        name = self._required_string(payload, "name")
        value = payload.get("value")
        if value is not None and not isinstance(value, str):
            raise TypeError("value must be a string")
        text = (value or "").strip()
        if name == "scan_mode":
            if text not in SCAN_MODES:
                raise ValueError(f"Scan mode must be one of: {', '.join(SCAN_MODES)}")
            self.scan_mode = text
        elif name == "scope_mode":
            if text not in SCOPE_MODES:
                raise ValueError(f"Scope must be one of: {', '.join(SCOPE_MODES)}")
            self.scope_mode = text
        elif name == "max_budget_usd":
            if not text:
                self.max_budget_usd = None
            else:
                try:
                    budget = float(text.lstrip("$"))
                except ValueError as exc:
                    raise ValueError("Budget must be a number") from exc
                if not math.isfinite(budget) or budget <= 0:
                    raise ValueError("Budget must be greater than 0")
                self.max_budget_usd = budget
        else:
            connections.set_setting(name, text)
        return {"name": name, "value": text}

    async def _confirm_mount(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Answer the pending working-directory mount asked for in the live view."""
        mount = self.pending_workspace_mount
        if mount is None:
            raise RuntimeError("No mount confirmation is pending")
        approved = payload.get("approved")
        if not isinstance(approved, bool):
            raise TypeError("approved must be a boolean")
        self.pending_workspace_mount = None
        # Declining skips the mount, it does not abandon the scan. The prompt is
        # the whole of the input either way; the working directory is only an
        # extra the agent may look at, so the run goes ahead without one.
        self.workspace_mount = mount if approved else None
        await self._begin_scan()
        return {"approved": approved}

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
        self.live_view.upsert_agent(agent_id, status="waiting", error_message=None)
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
