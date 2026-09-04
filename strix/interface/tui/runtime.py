"""Launch and supervise the Bubble Tea TUI."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shutil
import sys
from copy import deepcopy
from pathlib import Path
from typing import TYPE_CHECKING, Any

from strix.config import load_settings, persist_current
from strix.core.agents import AgentCoordinator
from strix.core.hooks import BudgetExceededError
from strix.core.runner import run_strix_scan
from strix.interface.scan_setup import (
    build_targets_info,
    preflight_model_connection,
    prepare_run,
    telemetry_start,
)
from strix.interface.tui.backend import TuiBackendServer, TuiController
from strix.interface.tui.backend.live_view import TuiLiveView
from strix.interface.tui.sidecar import (
    check_return_code,
    child_environment,
    launch_tui_process,
    package_version,
    terminate_process,
    tui_executable,
    tui_source_dir,
    wait_process,
)
from strix.interface.utils import read_workspace_files
from strix.report.state import ReportState, set_global_report_state
from strix.utils.resource_paths import get_strix_resource_path


if TYPE_CHECKING:
    import argparse
    import socket
    import subprocess

logger = logging.getLogger(__name__)


class GoTuiPreActivationError(RuntimeError):
    """A sidecar failure raised before the Go TUI activates."""


class GoTuiRuntime:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.live_view = TuiLiveView()
        self.coordinator = AgentCoordinator()
        self.report_state: ReportState | None = None
        self.scan_config: dict[str, Any] = {}
        self.scan_task: asyncio.Task[None] | None = None
        self.scan_error: BaseException | None = None
        self._last_sync_fingerprint = ""
        self._error_noted_agents: set[str] = set()
        self.model_verified = False
        self._setup_preflight: asyncio.Task[None] | None = None
        self.controller = TuiController(
            args,
            live_view=self.live_view,
            coordinator=self.coordinator,
            on_start=self.start_from_setup,
            on_verify=self.ensure_model_verified,
            on_quit=self.quit,
        )
        self.server = TuiBackendServer(self.controller)

    def init_run_state(self) -> None:
        self.scan_config = {
            "scan_id": self.args.run_name,
            "targets": self.args.targets_info,
            "user_instructions": self.args.instruction or "",
            "run_name": self.args.run_name,
            "diff_scope": self.args.diff_scope,
            "scan_mode": self.args.scan_mode,
            "non_interactive": False,
            "local_sources": self.args.local_sources or [],
            "workspace_files": getattr(self.args, "workspace_files", None) or [],
            "scope_mode": self.args.scope_mode,
            "diff_base": self.args.diff_base,
            "resume_instruction": self.args.user_explicit_instruction or "",
            "workspace_mount": getattr(self.args, "workspace_mount", None) or "",
            "workspace_subdir": getattr(self.args, "workspace_subdir", None) or "",
        }
        self.report_state = ReportState(self.scan_config["run_name"])
        self.report_state.hydrate_from_run_dir()
        self.report_state.set_scan_config(self.scan_config)
        self.report_state.save_run_data()
        set_global_report_state(self.report_state)
        self.live_view.hydrate_from_run_dir(self.report_state.get_run_dir())
        self.controller.set_runtime(
            report_state=self.report_state,
            scan_loop=asyncio.get_running_loop(),
        )
        self.report_state.vulnerability_found_callback = lambda _report: (
            self.controller.notify_changed()
        )
        self.report_state.vulnerability_updated_callback = lambda _report: (
            self.controller.notify_changed()
        )
        self.controller.notify_changed()

    async def check_setup_model(self) -> None:
        """Verify the model route as soon as the start screen is up.

        The same round trip a direct launch makes in prepare_and_start, run in
        the background so the screen paints first and the outcome lands in the
        setup log before the user has finished typing.
        """
        if not (load_settings().llm.model or "").strip():
            return
        try:
            await self._preflight_model()
        except Exception as exc:
            logger.exception("Go TUI setup model preflight failed")
            self.controller.add_message(f"Model connection failed: {exc}", "error")
            return
        self.controller.add_message("Model connection verified")

    async def ensure_model_verified(self) -> None:
        """Hold a setup launch until the model has answered once."""
        preflight = self._setup_preflight
        if preflight is not None and not preflight.done():
            await asyncio.shield(preflight)
        if self.model_verified:
            return
        try:
            await self._preflight_model()
        except Exception as exc:
            logger.exception("Go TUI setup model preflight failed")
            raise RuntimeError(f"Model connection failed: {exc}") from exc

    async def _preflight_model(self) -> None:
        model = (load_settings().llm.model or "").strip()
        self.controller.add_message("Verifying model connection...")
        await preflight_model_connection(model)
        self.model_verified = True

    def _start_preparation(self) -> asyncio.Task[None]:
        """Kick off the work that runs behind the freshly painted TUI."""
        if self.controller.setup_mode:
            self._setup_preflight = asyncio.create_task(self.check_setup_model())
            return self._setup_preflight
        self.controller.begin_preparation()
        return asyncio.create_task(self.prepare_and_start())

    async def start_from_setup(self) -> None:
        candidate = deepcopy(self.args)
        candidate.scan_mode = self.controller.scan_mode
        candidate.instruction = self.controller.instruction
        # Held apart from instruction, which prepare_run prefixes with the
        # diff-scope preamble, so the transcript can show what was typed.
        candidate.user_instruction = self.controller.instruction or None
        candidate.max_budget_usd = self.controller.max_budget_usd
        candidate.max_turns = self.controller.max_turns
        candidate.scope_mode = self.controller.scope_mode
        candidate.diff_base = self.controller.diff_base
        existing_targets = [
            str(target["original"])
            for target in candidate.targets_info
            if isinstance(target, dict) and target.get("original")
        ]
        targets_changed = self.controller.targets != existing_targets
        persist_current()
        # A confirmed target-less launch mounts the working directory for the
        # agent to work in, without making it a scan target.
        candidate.workspace_mount = self.controller.workspace_mount
        if targets_changed:
            # Rebuild the full typed set so path canonicalization and local
            # deduplication match the CLI.
            candidate.target = list(self.controller.targets)
            candidate.target_list = []
            build_targets_info(candidate)
        prepare_run(candidate)
        telemetry_start(candidate)

        vars(self.args).update(vars(candidate))
        self.init_run_state()
        self.start_scan()

    async def prepare_and_start(self) -> None:
        """Prepare a directly-launched scan once the TUI is on screen.

        The model round trip and run preparation run here rather than before
        launch so the interface appears immediately.
        """
        model = (load_settings().llm.model or "").strip()
        try:
            await preflight_model_connection(model)
            persist_current()
            prepare_run(self.args)
            telemetry_start(self.args)
        except Exception as exc:
            logger.exception("Go TUI scan preparation failed")
            self.controller.fail_preparation(str(exc))
            return
        self.controller.scan_state = "running"
        self.init_run_state()
        self.start_scan()

    def start_scan(self) -> None:
        if self.scan_task is None:
            self.scan_task = asyncio.create_task(self._run_scan())

    async def _run_scan(self) -> None:
        image = str(load_settings().runtime.image or "strix-sandbox:latest")
        try:
            await run_strix_scan(
                scan_config=self.scan_config,
                scan_id=self.scan_config["run_name"],
                image=image,
                local_sources=self.args.local_sources or [],
                extra_files=read_workspace_files(getattr(self.args, "workspace_files", None)),
                coordinator=self.coordinator,
                interactive=True,
                max_turns=self.args.max_turns,
                max_budget_usd=self.args.max_budget_usd,
                event_sink=self.capture_event,
                mcp_status_sink=self.capture_mcp_status,
            )
            await self._sync_agent_state()
            if self.controller.scan_state == "running":
                self.controller.scan_state = "stopped"
        except (asyncio.CancelledError, BudgetExceededError):
            report_status = (
                self.report_state.run_record.get("status")
                if self.report_state is not None
                else None
            )
            self.controller.scan_state = "completed" if report_status == "completed" else "stopped"
        except Exception as exc:
            logger.exception("Go TUI scan failed")
            self.scan_error = exc
            self.controller.error = str(exc)
            self.controller.scan_state = "failed"
        finally:
            with contextlib.suppress(Exception):
                await self._sync_agent_state()
            self.controller.notify_changed()

    def capture_event(self, agent_id: str, event: Any) -> None:
        self.live_view.ingest_sdk_event(agent_id, event)
        self.controller.notify_changed()

    def capture_mcp_status(self, roster: list[dict[str, Any]]) -> None:
        """Receive the engine's MCP connection roster and hand it to the controller.

        Runs on the scan's event loop (called from the runner at establishment
        and from a session's on-dead callback), the same loop that drives
        ``capture_event``, so updating the controller and repainting here is
        safe. The controller renders it as the sidebar MCP connections panel."""
        self.controller.set_mcp_connections(roster)

    async def _sync_agent_state(self) -> bool:
        parent_of, statuses, names, errors = await self.coordinator.graph_snapshot()
        changed = False
        for agent_id, status in statuses.items():
            error = errors.get(agent_id)
            changed = (
                self.live_view.upsert_agent(
                    agent_id,
                    name=names.get(agent_id, agent_id),
                    parent_id=parent_of.get(agent_id),
                    status=str(status),
                    error_message=error,
                )
                or changed
            )
            if status in {"failed", "crashed"} and error:
                if agent_id not in self._error_noted_agents:
                    self._error_noted_agents.add(agent_id)
                    self.live_view.record_agent_error(agent_id, error)
                    changed = True
            else:
                self._error_noted_agents.discard(agent_id)

        # The user's opening message waits for the root agent to exist, which is
        # the first thing this sync learns about.
        changed = self.live_view.flush_user_instruction() or changed

        roots = [agent_id for agent_id, parent_id in parent_of.items() if parent_id is None]
        root_id = roots[0] if roots else None
        root_status = statuses.get(root_id) if root_id is not None else None
        report_status = (
            self.report_state.run_record.get("status") if self.report_state is not None else None
        )
        scan_state = self.controller.scan_state
        if root_status in {"failed", "crashed"}:
            scan_state = "failed"
            if root_id is not None and errors.get(root_id):
                self.controller.error = errors[root_id]
        elif scan_state == "failed" and root_status in {"running", "waiting", "budget_paused"}:
            scan_state = "running"
            self.controller.error = None
        elif scan_state != "failed":
            if report_status == "completed":
                scan_state = "completed"
            elif root_status == "stopped":
                scan_state = "stopped"
            elif root_status == "completed":
                scan_state = "failed"
                self.controller.error = "Scan ended without a completed report"
        if scan_state != self.controller.scan_state:
            self.controller.scan_state = scan_state
            changed = True
        return changed

    def _runtime_sync_fingerprint(self) -> str:
        usage: dict[str, Any] = {}
        vulnerabilities: list[object] = []
        if self.report_state is not None:
            usage = dict(self.report_state.get_total_llm_usage())
            vulnerabilities = [
                report.get("id", index) if isinstance(report, dict) else index
                for index, report in enumerate(self.report_state.vulnerability_reports)
            ]
        return json.dumps(
            {
                "scan_state": self.controller.scan_state,
                "usage": usage,
                "vulnerabilities": vulnerabilities,
            },
            default=str,
            sort_keys=True,
            separators=(",", ":"),
        )

    async def sync_state(self) -> None:
        while True:
            if self.scan_task is not None and not self.scan_task.done():
                try:
                    changed = await self._sync_agent_state()
                except Exception as exc:
                    logger.exception("Go TUI agent-state sync failed")
                    self.controller.error = f"Agent-state sync failed: {exc}"
                    changed = True
                fingerprint = self._runtime_sync_fingerprint()
                if fingerprint != self._last_sync_fingerprint:
                    self._last_sync_fingerprint = fingerprint
                    changed = True
                if changed:
                    self.controller.notify_changed()
            await asyncio.sleep(0.5)

    async def quit(self) -> None:
        self.controller.close_viewer()
        self.coordinator.mark_shutting_down()
        scan_task = self.scan_task
        if scan_task is not None:
            if not scan_task.done():
                scan_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await scan_task

    @staticmethod
    def binary_command() -> list[str]:
        source = tui_source_dir()
        # A checkout may also contain a stale wheel/build sidecar. Running the
        # current source is the deterministic development choice.
        if (source / "go.mod").is_file() and shutil.which("go"):
            return ["go", "run", "./cmd/strix-tui"]
        packaged = get_strix_resource_path("bin", tui_executable())
        if packaged.is_file():
            return [str(packaged)]
        raise RuntimeError(
            "Bubble Tea TUI binary not found. Reinstall Strix from an official platform wheel."
        )

    @staticmethod
    async def _cancel_tasks(*tasks: asyncio.Task[None] | None) -> None:
        for task in tasks:
            if task is None:
                continue
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def run(self) -> None:
        # Redirect the process's sys.stdout/sys.stderr while the TUI runs so
        # logging handlers created during the scan never paint over the Go
        # TUI's alt screen. The child still inherits the real terminal fds;
        # only the Python-level bindings change.
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        output_sink = Path(os.devnull).open("a", buffering=1)  # noqa: SIM115
        sys.stdout = output_sink
        sys.stderr = output_sink
        backend_socket: socket.socket | None = None
        sync_task: asyncio.Task[None] | None = None
        prepare_task: asyncio.Task[None] | None = None
        process: asyncio.subprocess.Process | subprocess.Popen[bytes] | None = None
        try:
            env = child_environment()
            env["STRIX_VERSION"] = package_version()
            command = self.binary_command()
            cwd = str(tui_source_dir()) if command[:2] == ["go", "run"] else None
            if cwd is not None:
                # go run compiles the sidecar when the build cache is cold, so
                # tell the terminal why nothing is on screen yet.
                print(
                    "\x1b[2mCompiling the TUI from source (cached after the first run)...\x1b[0m",
                    file=original_stdout,
                    flush=True,
                )
            process, backend_socket = await launch_tui_process(command, env, cwd)
            await self.server.start(backend_socket)
            prepare_task = self._start_preparation()
            sync_task = asyncio.create_task(self.sync_state())
            return_code = await wait_process(process)
            check_return_code(return_code)
        except Exception as exc:
            await terminate_process(process)
            if not self.server.activated:
                raise GoTuiPreActivationError(str(exc)) from exc
            raise
        except BaseException:
            await terminate_process(process)
            raise
        finally:
            try:
                if backend_socket is not None:
                    backend_socket.close()
                await self._cancel_tasks(prepare_task, sync_task)
                await self.quit()
                await self.server.close()
            finally:
                sys.stdout = original_stdout
                sys.stderr = original_stderr
                output_sink.close()
        # Mirror run_tui: surface the captured scan failure once the app has
        # exited cleanly so the CLI reports it instead of exiting 0.
        if self.scan_error is not None:
            raise self.scan_error


async def run_go_tui(args: argparse.Namespace) -> None:
    await GoTuiRuntime(args).run()
