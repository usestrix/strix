"""Stateful, model-free Strix service exposed by the MCP server."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from strix.config import load_settings
from strix.core.inputs import build_root_task, build_scope_context
from strix.core.paths import run_dir_for
from strix.interface.utils import (
    assign_workspace_subdirs,
    build_mount_targets_info,
    collect_local_sources,
    dedupe_local_targets,
    find_oversized_local_targets,
    generate_run_name,
    infer_target_type,
    resolve_diff_scope_context,
    rewrite_localhost_targets,
)
from strix.report.state import ReportState, set_global_report_state
from strix.runtime import session_manager
from strix.skills import get_available_skills, load_skills
from strix.tools.finish.tool import _do_finish
from strix.tools.reporting.tool import _do_create


logger = logging.getLogger(__name__)


class StrixMCPService:
    """Own one agent-driven scan for the lifetime of an MCP process.

    This class deliberately contains no model provider or model call. The MCP
    client (Codex, Claude Code, or another coding agent) supplies all reasoning.
    """

    def __init__(self) -> None:
        self.scan_id: str | None = None
        self.scan_config: dict[str, Any] | None = None
        self.report_state: ReportState | None = None
        self.bundle: dict[str, Any] | None = None

    async def start_scan(  # noqa: PLR0911 - lifecycle validation has distinct failure results.
        self,
        targets: list[str],
        *,
        scan_mode: str = "deep",
        instruction: str = "",
        run_name: str | None = None,
        mounts: list[str] | None = None,
        resume: bool = False,
        scope_mode: str = "auto",
        diff_base: str | None = None,
        non_interactive: bool = False,
    ) -> dict[str, Any]:
        """Create or resume a scan and start its isolated tool sandbox."""
        if self.bundle is not None:
            return {
                "success": False,
                "error": "A scan is already active in this MCP session",
                "scan_id": self.scan_id,
            }
        if scan_mode not in {"quick", "standard", "deep"}:
            return {"success": False, "error": f"Unsupported scan mode: {scan_mode}"}

        if resume:
            if not run_name:
                return {"success": False, "error": "run_name is required when resume=true"}
            state = ReportState(run_name)
            state.hydrate_from_run_dir()
            persisted = state.run_record
            targets_info = persisted.get("targets_info") or []
            if not targets_info:
                return {"success": False, "error": f"Run {run_name!r} has no persisted targets"}
            local_sources = persisted.get("local_sources") or collect_local_sources(targets_info)
            scan_mode = str(persisted.get("scan_mode") or scan_mode)
            scope_mode = str(persisted.get("scope_mode") or scope_mode)
            diff_base = persisted.get("diff_base") or diff_base
            diff_scope = persisted.get("diff_scope") or {"active": False}
            original_instruction = str(persisted.get("instruction") or "")
            instruction = "\n\n".join(x for x in (original_instruction, instruction) if x)
        else:
            if not targets and not mounts:
                return {"success": False, "error": "At least one target or mount is required"}
            try:
                targets_info = await self._prepare_targets(targets, mounts or [], run_name)
            except (OSError, RuntimeError, ValueError) as exc:
                return {"success": False, "error": str(exc)}
            run_name = run_name or generate_run_name(targets_info)
            local_sources = collect_local_sources(targets_info)
            try:
                resolved_scope = resolve_diff_scope_context(
                    local_sources=local_sources,
                    scope_mode=scope_mode,
                    diff_base=diff_base,
                    non_interactive=non_interactive,
                )
            except ValueError as exc:
                return {"success": False, "error": str(exc)}
            diff_scope = resolved_scope.metadata
            if resolved_scope.instruction_block:
                instruction = "\n\n".join(
                    part for part in (resolved_scope.instruction_block, instruction) if part
                )
            state = ReportState(run_name)

        assert run_name is not None
        scan_config = {
            "targets": targets_info,
            "scan_mode": scan_mode,
            "user_instructions": instruction,
            "local_sources": local_sources,
            "scope_mode": scope_mode,
            "diff_base": diff_base,
            "diff_scope": diff_scope,
            "non_interactive": non_interactive,
            "agent_runtime": "mcp",
        }
        state.set_scan_config(scan_config)
        state.save_run_data()
        set_global_report_state(state)

        try:
            bundle = await session_manager.create_or_reuse(
                run_name,
                image=load_settings().runtime.image,
                local_sources=local_sources,
            )
        except Exception as exc:
            state.save_run_data(status="failed")
            logger.exception("Could not create Strix sandbox")
            return {"success": False, "error": f"Could not create Strix sandbox: {exc}"}

        self.scan_id = run_name
        self.scan_config = scan_config
        self.report_state = state
        self.bundle = bundle
        return {
            "success": True,
            "scan_id": run_name,
            "run_dir": str(run_dir_for(run_name).resolve()),
            "task": build_root_task(scan_config),
            "scope": build_scope_context(scan_config),
            "scan_mode": scan_mode,
            "workspace_targets": self._workspace_targets(targets_info),
            "next": (
                "Follow the strix-security skill workflow. Use sandbox_exec for testing, "
                "load_knowledge when a technology or vulnerability class is relevant, file "
                "only verified findings, then call finish_scan."
            ),
        }

    async def _prepare_targets(
        self,
        targets: list[str],
        mounts: list[str],
        run_name: str | None,
    ) -> list[dict[str, Any]]:
        targets_info: list[dict[str, Any]] = []
        for raw_target in targets:
            target_type, details = await asyncio.to_thread(infer_target_type, raw_target)
            original = (
                details.get("target_path", raw_target)
                if target_type == "local_code"
                else raw_target
            )
            targets_info.append({"type": target_type, "details": details, "original": original})
        targets_info.extend(build_mount_targets_info(mounts))
        targets_info = dedupe_local_targets(targets_info)
        assign_workspace_subdirs(targets_info)
        rewrite_localhost_targets(targets_info, "host.docker.internal")

        max_mb = load_settings().runtime.max_local_copy_mb
        oversized = find_oversized_local_targets(targets_info, max_mb * 1024 * 1024)
        if oversized:
            oversized_details = "; ".join(
                f"{path} ({size / (1024 * 1024):.0f} MB)" for path, size in oversized
            )
            raise ValueError(
                f"Local target too large to copy: {oversized_details}. "
                "Use the mounts argument or raise STRIX_MAX_LOCAL_COPY_MB."
            )

        scan_name = run_name or generate_run_name(targets_info)
        for target_info in targets_info:
            if target_info["type"] != "repository":
                continue
            details = target_info["details"]
            details["cloned_repo_path"] = await self._clone_repository(
                details["target_repo"],
                scan_name,
                details.get("workspace_subdir"),
            )
        return targets_info

    async def _clone_repository(self, url: str, run_name: str, subdir: str | None) -> str:
        name = subdir or re.sub(r"[^A-Za-z0-9._-]", "-", Path(url).stem) or "repository"
        destination = Path(tempfile.gettempdir()) / "strix_repos" / run_name / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise ValueError(
                f"Clone destination already exists: {destination}. "
                "Use resume=true or another run_name."
            )
        git = shutil.which("git")
        if git is None:
            raise RuntimeError("Git is required to clone repository targets")
        process = await asyncio.create_subprocess_exec(
            git,
            "clone",
            url,
            str(destination),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _stdout, stderr = await process.communicate()
        if process.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace")[-2000:]
            raise RuntimeError(f"Could not clone {url}: {detail}")
        return str(destination.resolve())

    @staticmethod
    def _workspace_targets(targets_info: list[dict[str, Any]]) -> list[dict[str, str]]:
        mapped: list[dict[str, str]] = []
        for target in targets_info:
            details = target.get("details") or {}
            subdir = details.get("workspace_subdir")
            mapped.append(
                {
                    "type": str(target.get("type", "unknown")),
                    "target": str(target.get("original", "")),
                    "sandbox_path": f"/workspace/{subdir}" if subdir else "",
                }
            )
        return mapped

    async def sandbox_exec(self, argv: list[str], timeout: int = 120) -> dict[str, Any]:
        """Execute one argv-form command inside the Strix security sandbox."""
        if self.bundle is None:
            return {"success": False, "error": "Call start_scan first"}
        if not argv or any(not isinstance(part, str) or not part for part in argv):
            return {"success": False, "error": "argv must contain non-empty strings"}
        timeout = min(max(timeout, 1), 900)
        try:
            result = await self.bundle["session"].exec(*argv, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "error": str(exc)}
        return {
            "success": bool(result.ok()),
            "exit_code": result.exit_code,
            "stdout": self._decode(result.stdout),
            "stderr": self._decode(result.stderr),
        }

    @staticmethod
    def _decode(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value or "")

    def list_knowledge(self) -> dict[str, Any]:
        return {"success": True, "skills": get_available_skills()}

    def load_knowledge(self, name: str) -> dict[str, Any]:
        content = load_skills([name])
        if not content:
            return {"success": False, "error": f"Knowledge module not found: {name}"}
        return {"success": True, "name": name, "content": next(iter(content.values()))}

    async def proxy_call(self, tool: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.bundle is None:
            return {"success": False, "error": "Call start_scan first"}
        context = SimpleNamespace(context={"caido_client": self.bundle["caido_client"]})
        try:
            raw = await tool.on_invoke_tool(context, json.dumps(arguments))
            return json.loads(raw) if isinstance(raw, str) else {"success": True, "result": raw}
        except Exception as exc:
            logger.exception("Proxy tool call failed")
            return {"success": False, "error": str(exc)}

    async def create_finding(self, **finding: Any) -> dict[str, Any]:
        if self.report_state is None:
            return {"success": False, "error": "Call start_scan first"}
        finding["allow_model_dedupe"] = False
        finding.setdefault("agent_id", "coding-agent")
        finding.setdefault("agent_name", "coding-agent")
        result: Any = await _do_create(**finding)
        if not isinstance(result, dict):
            return {"success": False, "error": "Unexpected report result"}
        return result

    def list_findings(self) -> dict[str, Any]:
        if self.report_state is None:
            return {"success": False, "error": "Call start_scan first"}
        return {
            "success": True,
            "count": len(self.report_state.vulnerability_reports),
            "findings": self.report_state.get_existing_vulnerabilities(),
        }

    def status(self) -> dict[str, Any]:
        if self.report_state is None:
            return {"success": True, "active": False}
        return {
            "success": True,
            "active": self.bundle is not None,
            "scan_id": self.scan_id,
            "run_dir": str(self.report_state.get_run_dir().resolve()),
            "status": self.report_state.run_record.get("status"),
            "findings": len(self.report_state.vulnerability_reports),
            "scan_config": self.scan_config,
        }

    async def finish_scan(
        self,
        *,
        executive_summary: str,
        methodology: str,
        technical_analysis: str,
        recommendations: str,
    ) -> dict[str, Any]:
        if self.report_state is None:
            return {"success": False, "error": "Call start_scan first"}
        raw_result: Any = await asyncio.to_thread(
            _do_finish,
            parent_id=None,
            executive_summary=executive_summary,
            methodology=methodology,
            technical_analysis=technical_analysis,
            recommendations=recommendations,
        )
        if not isinstance(raw_result, dict):
            return {"success": False, "error": "Unexpected finish result"}
        result = raw_result
        if result.get("success"):
            await self._cleanup()
            result["run_dir"] = str(self.report_state.get_run_dir().resolve())
        return result

    async def stop_scan(self, status: str = "stopped") -> dict[str, Any]:
        if self.report_state is None:
            return {"success": True, "message": "No active scan"}
        self.report_state.save_run_data(status=status)
        await self._cleanup()
        return {
            "success": True,
            "scan_id": self.scan_id,
            "status": self.report_state.run_record.get("status"),
            "run_dir": str(self.report_state.get_run_dir().resolve()),
        }

    async def _cleanup(self) -> None:
        if self.bundle is not None and self.scan_id is not None:
            await session_manager.cleanup(self.scan_id)
        self.bundle = None
