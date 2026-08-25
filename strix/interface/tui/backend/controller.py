"""UI-independent state and command controller for interactive Strix clients."""

from __future__ import annotations

import asyncio
import contextlib
import math
import webbrowser
from collections import deque
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from strix.config import load_settings
from strix.config.models import is_recommended_or_frontier_model
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
    from strix.safety.runtime import SafetyRuntime
    from strix.safety.types import SafetyApprovalOutcome


_STOPPABLE_AGENT_STATUSES = frozenset({"running", "waiting", "budget_paused"})

ChangeCallback = Callable[[], None]
StartCallback = Callable[[bool], Awaitable[None]]
QuitCallback = Callable[[], Awaitable[None]]


@dataclass(slots=True)
class _PendingSafetyApproval:
    request_id: str
    action: str
    reason: str
    agent_id: str
    tool_name: str
    digest: str
    risk: str
    future: asyncio.Future[SafetyApprovalOutcome]


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
        self.error: str | None = None
        self.viewer_status = "idle"
        self.viewer_url: str | None = None
        self._viewer_httpd: Any = None
        self._on_start = on_start
        self._on_quit = on_quit
        self._on_change = on_change
        self._safety_approval_lock = asyncio.Lock()
        self._safety_approvals: deque[_PendingSafetyApproval] = deque()
        self._safety_approval_by_id: dict[str, _PendingSafetyApproval] = {}
        self._safety_approval_request_ids: set[str] = set()
        self._safety_approvals_closed = False
        # Set once the running scan hands back its SafetyRuntime, so an "approve
        # all" can switch the whole scan to dangerous (unreviewed) behavior.
        self._safety_runtime: SafetyRuntime | None = None
        # Latches when the user chooses "approve all": every later review is
        # auto-approved, covering any request already in flight when the runtime
        # was disabled and any run that registers its runtime afterwards.
        self._safety_disabled = False

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

    def register_safety_runtime(self, runtime: SafetyRuntime | None) -> None:
        """Receive the running scan's SafetyRuntime so it can be disabled later.

        If the user already chose "approve all" (e.g. during a previous run that
        this call is replacing), the new runtime starts disabled too.
        """
        self._safety_runtime = runtime
        if runtime is not None and self._safety_disabled:
            runtime.disable()

    def begin_preparation(self) -> None:
        """Mark a directly-launched run as preparing behind the live TUI."""
        self.scan_state = "preparing"
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

    @staticmethod
    def _safety_request_value(request: Any, name: str) -> Any:
        if isinstance(request, Mapping):
            return cast("Mapping[str, Any]", request).get(name)
        return getattr(request, name, None)

    @classmethod
    def _safety_request_text(
        cls,
        request: Any,
        name: str,
        *,
        fallback_names: tuple[str, ...] = (),
        default: str,
        max_string: int,
    ) -> str:
        value = cls._safety_request_value(request, name)
        for fallback_name in fallback_names:
            if value is not None:
                break
            value = cls._safety_request_value(request, fallback_name)
        if value is None:
            value = default
        projected = terminal_projection(str(value), max_string=max_string)
        return projected if isinstance(projected, str) else default

    async def safety_approval_callback(self, request: Any) -> SafetyApprovalOutcome:
        """Queue one safety-core request and wait until the TUI answers it."""
        # Once the user has approved everything, a review that was already past
        # the runtime's mode check when it was disabled still lands here; approve
        # it without prompting so dangerous mode stays consistent.
        if self._safety_disabled:
            return True
        request_id = self._safety_request_value(request, "request_id")
        if request_id is None:
            request_id = self._safety_request_value(request, "case_id")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("safety approval request_id must be a non-empty string")
        if len(request_id) > 128 or sanitize_terminal_text(request_id) != request_id:
            raise ValueError(
                "safety approval request_id must be terminal-safe and at most 128 characters"
            )
        raw_action = self._safety_request_value(request, "action")
        if raw_action is None:
            raw_action = self._safety_request_value(request, "action_preview")
        if raw_action is not None and len(str(raw_action)) > 512:
            return False
        action = self._safety_request_text(
            request,
            "action",
            fallback_names=("action_preview", "description", "tool_name"),
            default="Safety-sensitive action",
            max_string=512,
        )
        reason = self._safety_request_text(
            request,
            "reason",
            fallback_names=("reviewer_reason", "rationale"),
            default="No reason provided.",
            max_string=512,
        )
        agent_id = self._safety_request_text(
            request,
            "agent_id",
            default="",
            max_string=128,
        )
        if not agent_id:
            raise ValueError("safety approval agent_id must be a non-empty string")
        tool_name = self._safety_request_text(
            request,
            "tool_name",
            default="",
            max_string=128,
        )
        digest = self._safety_request_text(
            request,
            "digest",
            default="",
            max_string=128,
        )
        risk = self._safety_request_text(
            request,
            "risk",
            default="",
            max_string=32,
        )
        future: asyncio.Future[SafetyApprovalOutcome] = asyncio.get_running_loop().create_future()
        pending = _PendingSafetyApproval(
            request_id,
            action,
            reason,
            agent_id,
            tool_name,
            digest,
            risk,
            future,
        )
        async with self._safety_approval_lock:
            if self._safety_approvals_closed:
                return "cancelled"
            if request_id in self._safety_approval_request_ids:
                raise ValueError(f"duplicate safety approval request_id: {request_id}")
            self._safety_approvals.append(pending)
            self._safety_approval_by_id[request_id] = pending
            self._safety_approval_request_ids.add(request_id)
        self.notify_changed()
        try:
            return await future
        except asyncio.CancelledError:
            async with self._safety_approval_lock:
                if self._safety_approval_by_id.get(request_id) is pending:
                    self._safety_approvals.remove(pending)
                    del self._safety_approval_by_id[request_id]
            self.notify_changed()
            raise

    async def cancel_pending_safety_approvals(self) -> None:
        """Fail closed and release every safety callback waiting on the UI."""
        async with self._safety_approval_lock:
            self._safety_approvals_closed = True
            pending = list(self._safety_approvals)
            self._safety_approvals.clear()
            self._safety_approval_by_id.clear()
            for approval in pending:
                if not approval.future.done():
                    approval.future.set_result("cancelled")
        if pending:
            self.notify_changed()

    async def deny_safety_approvals_for_agents(self, agent_ids: set[str]) -> None:
        async with self._safety_approval_lock:
            denied = [item for item in self._safety_approvals if item.agent_id in agent_ids]
            for item in denied:
                self._safety_approvals.remove(item)
                self._safety_approval_by_id.pop(item.request_id, None)
                if not item.future.done():
                    item.future.set_result("cancelled")
        if denied:
            self.notify_changed()

    async def safety_approval_agent_ids(self) -> set[str]:
        async with self._safety_approval_lock:
            return {item.agent_id for item in self._safety_approvals if item.agent_id}

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
            "pending_approvals": [
                {
                    "request_id": pending_approval.request_id,
                    "action": pending_approval.action,
                    "reason": pending_approval.reason,
                    "agent_id": pending_approval.agent_id,
                    "tool_name": pending_approval.tool_name,
                    "digest": pending_approval.digest,
                    "risk": pending_approval.risk,
                }
                for pending_approval in self._safety_approvals
            ],
            "safety_disabled": self._safety_disabled,
            "instruction": terminal_projection(self.instruction, max_string=2 * 1024),
            "scan_mode": self.scan_mode,
            "max_budget_usd": self.max_budget_usd,
            "max_turns": self.max_turns,
            "scope_mode": self.scope_mode,
            "diff_base": terminal_projection(self.diff_base, max_string=256),
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
            "setup.add_target": self._add_target,
            "setup.set_instruction": self._set_instruction,
            "setup.start": self._start,
            "setup.confirm_mount": self._confirm_mount,
            "agent.send_message": self._send_message,
            "agent.stop": self._stop_agent,
            "viewer.open": self._open_viewer,
            "safety.resolve": self._resolve_safety_approval,
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
            raise ValueError("No model configured. Set STRIX_LLM first.")
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
        # Declining skips the mount, it does not abandon the scan. The prompt is
        # the whole of the input either way; the working directory is only an
        # extra the agent may look at, so the run goes ahead without one.
        self.workspace_mount = mount if approved else None
        await self._begin_scan(self._pending_verify)
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
            stopped_agents = await self.coordinator.cancel_descendants_graceful(agent_id)
        else:
            future = asyncio.run_coroutine_threadsafe(
                self.coordinator.cancel_descendants_graceful(agent_id), self.scan_loop
            )
            stopped_agents = await asyncio.wrap_future(future)
        if not stopped_agents:
            raise RuntimeError(f"Agent '{agent_id}' is no longer active")
        await self.deny_safety_approvals_for_agents(set(stopped_agents))
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
        await self.cancel_pending_safety_approvals()
        if self._on_quit is not None:
            await self._on_quit()
        self.scan_state = "stopped"
        return {"quitting": True}

    async def _resolve_safety_approval(self, payload: dict[str, Any]) -> dict[str, Any]:
        request_id = payload.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("request_id must be a non-empty string")
        approved = payload.get("approved")
        if not isinstance(approved, bool):
            raise TypeError("approved must be a boolean")
        approve_all = payload.get("approve_all", False)
        if not isinstance(approve_all, bool):
            raise TypeError("approve_all must be a boolean")
        # "Approve all" only makes sense as an approval; a denial cannot also
        # green-light everything else.
        dangerous = approve_all and approved
        async with self._safety_approval_lock:
            pending = self._safety_approval_by_id.get(request_id)
            if pending is None:
                raise RuntimeError(f"Safety approval request is stale or unknown: {request_id}")
            if pending.future.done():
                raise RuntimeError(f"Safety approval request was already resolved: {request_id}")
            self._safety_approvals.remove(pending)
            del self._safety_approval_by_id[request_id]
            pending.future.set_result(approved)
            if dangerous:
                self._enter_dangerous_mode_locked()
        if dangerous:
            self.add_message(
                "Safety review disabled — approving every action for the rest of this run.",
                level="warning",
            )
        return {"request_id": request_id, "approved": approved, "approve_all": dangerous}

    def _enter_dangerous_mode_locked(self) -> None:
        """Skip review for the rest of the run. Call while holding the approval lock.

        Disabling the runtime stops new reviews from ever reaching a prompt, and
        approving every queued request releases the ones already waiting here.
        """
        self._safety_disabled = True
        if self._safety_runtime is not None:
            self._safety_runtime.disable()
        for other in list(self._safety_approvals):
            if not other.future.done():
                other.future.set_result(True)
            self._safety_approval_by_id.pop(other.request_id, None)
        self._safety_approvals.clear()

    @staticmethod
    def _required_string(payload: dict[str, Any], name: str) -> str:
        value = payload.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()

    def _require_setup_mutable(self) -> None:
        if not self.setup_mode or self.scan_started or self._start_in_progress:
            raise RuntimeError("Setup can no longer be changed after the scan starts")
