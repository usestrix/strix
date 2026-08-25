"""Run-scoped safety orchestration and pre-execution enforcement."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import posixpath
import shlex
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

from strix.core.paths import RUNTIME_STATE_DIR_NAME
from strix.safety.audit import SafetyAudit
from strix.safety.evidence import (
    EvidenceBundle,
    compile_evidence,
    compile_network_evidence,
    parse_command,
)
from strix.safety.inspection import DockerInspectionRunner, InspectionRunner
from strix.safety.reviewer import SafetyReviewer
from strix.safety.types import SafetyApprovalCallback, SafetyApprovalRequest, SafetyDecision


logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from strix.config.settings import SafetyMode, SafetySettings
    from strix.safety.evidence import CommandPlan
    from strix.safety.types import WorkspaceEvidenceCollector


InvokeTool = Callable[[Any, str], Awaitable[Any]]

# ETX only: it discards the terminal's line buffer instead of submitting it, so it
# cannot smuggle a command through a session that was approved for something else.
_INTERRUPT_CHARS = frozenset({"\x03"})
_MAX_APPROVAL_ACTION_CHARS = 512
_MAX_EVIDENCE_REFRESHES = 3


@dataclass(frozen=True, slots=True)
class _ExecReview:
    decision: SafetyDecision
    summary: dict[str, Any]
    action_preview: str
    workspace_epoch: int
    workspace_evidence: bool
    evidence_fingerprint: str
    requested_workspace_paths: tuple[str, ...]
    tool_name: str = "exec_command"


class SafetyRuntime:
    """One safety policy shared by every agent in a scan.

    The policy is fixed for the run except that a human can turn review off
    outright with `disable` (the "approve all" choice), after which every tool
    call runs unreviewed for the rest of the scan.
    """

    def __init__(
        self,
        *,
        scan_id: str,
        mode: SafetyMode,
        scope: dict[str, Any],
        user_instruction: str,
        settings: SafetySettings,
        run_dir: Path,
        sandbox_image: str,
        inspection_runner: InspectionRunner | None = None,
        approval_callback: SafetyApprovalCallback | None = None,
    ) -> None:
        self.scan_id = scan_id
        self.mode = mode
        self.scope = scope
        self.user_instruction = user_instruction
        self.settings = settings
        self._approval_callback = approval_callback
        self._workspace_lock = asyncio.Lock()
        self._workspace_epoch = 0
        self._browser_locks: dict[str, asyncio.Lock] = {}
        runner = inspection_runner or DockerInspectionRunner(
            settings=settings,
            fallback_image=sandbox_image,
        )
        self._reviewer = SafetyReviewer(inspection_runner=runner)
        self._audit = SafetyAudit(run_dir / RUNTIME_STATE_DIR_NAME / "safety-audit.jsonl")

    def disable(self) -> None:
        """Drop to dangerous behavior: skip all future pre-execution review.

        Every entry point (`invoke_exec`, `invoke_write_stdin`,
        `invoke_mutating_tool`) checks ``self.mode`` first and passes straight
        through when it is "off", so flipping the mode here makes every later
        tool call run unreviewed — the same behavior as launching in "off" mode.
        A review already past that check when this is called is not interrupted;
        the caller (a human choosing "approve all") releases those by resolving
        their pending approvals as approved.
        """
        self.mode = "off"

    async def invoke_exec(
        self,
        *,
        ctx: Any,
        arguments: dict[str, Any],
        invoke_tool: InvokeTool,
    ) -> Any:
        raw_input = json.dumps(arguments, ensure_ascii=False)
        if self.mode == "off":
            return await invoke_tool(ctx, raw_input)
        arguments = json.loads(raw_input)

        agent_id = str(getattr(ctx, "context", {}).get("agent_id", "unknown"))
        plan = parse_command(str(arguments.get("cmd") or ""))
        evidence_refreshes = 0

        while True:
            review = await self._decide_exec(ctx=ctx, arguments=arguments, plan=plan)
            review = await self._resolve_approval(ctx=ctx, review=review)
            await self._audit.record(
                agent_id=agent_id,
                tool_call_id=str(getattr(ctx, "tool_call_id", "unknown")),
                tool_name="exec_command",
                decision=review.decision,
                summary=review.summary,
            )
            if not review.decision.allowed:
                return self.blocked_result(review.decision)

            browser_lock = (
                self._browser_locks.setdefault(agent_id, asyncio.Lock()) if plan.browser else None
            )
            if browser_lock is not None:
                await browser_lock.acquire()
            try:
                if (plan.read_only or plan.browser) and not review.workspace_evidence:
                    return await self._execute(
                        ctx=ctx,
                        agent_id=agent_id,
                        arguments=arguments,
                        plan=plan,
                        review=review,
                        invoke_tool=invoke_tool,
                    )
                async with self._workspace_lock:
                    evidence_current, fingerprint_changed = await self._evidence_is_current(
                        ctx=ctx,
                        agent_id=agent_id,
                        arguments=arguments,
                        review=review,
                    )
                    if not evidence_current:
                        if fingerprint_changed:
                            evidence_refreshes += 1
                        if evidence_refreshes >= _MAX_EVIDENCE_REFRESHES:
                            churn = SafetyDecision(
                                allowed=False,
                                source="system",
                                reason=(
                                    "The exact reviewed evidence changed repeatedly during "
                                    "automatic re-review; execution stopped to avoid running "
                                    "unreviewed bytes."
                                ),
                                categories=("evidence_churn",),
                                case_id=review.decision.case_id,
                                risk=review.decision.risk,
                            )
                            summary = dict(review.summary)
                            summary["evidence_refresh_attempts"] = evidence_refreshes
                            await self._audit.record(
                                agent_id=agent_id,
                                tool_call_id=str(getattr(ctx, "tool_call_id", "unknown")),
                                tool_name="exec_command",
                                decision=churn,
                                summary=summary,
                            )
                            return self.blocked_result(churn)
                        continue
                    return await self._execute(
                        ctx=ctx,
                        agent_id=agent_id,
                        arguments=arguments,
                        plan=plan,
                        review=review,
                        invoke_tool=invoke_tool,
                        workspace_locked=True,
                    )
            finally:
                if browser_lock is not None:
                    browser_lock.release()

    async def _execute(
        self,
        *,
        ctx: Any,
        agent_id: str,
        arguments: dict[str, Any],
        plan: CommandPlan,
        review: _ExecReview,
        invoke_tool: InvokeTool,
        workspace_locked: bool = False,
    ) -> Any:
        tool_call_id = str(getattr(ctx, "tool_call_id", "unknown"))
        if (
            review.decision.source == "human"
            and review.decision.allowed
            and not await self._agent_is_active(ctx, agent_id)
        ):
            inactive = SafetyDecision(
                allowed=False,
                source="system",
                reason="Approved action was cancelled because the requesting agent stopped.",
                categories=(*review.decision.categories, "agent_inactive"),
                case_id=review.decision.case_id,
                risk=review.decision.risk,
            )
            await self._audit.record(
                agent_id=agent_id,
                tool_call_id=tool_call_id,
                tool_name="exec_command",
                decision=inactive,
                summary=review.summary,
            )
            return self.blocked_result(inactive)
        effective = dict(arguments)
        if plan.browser:
            session = f"strix-{self.scan_id}-{agent_id}"
            effective["cmd"] = f"AGENT_BROWSER_SESSION={shlex.quote(session)} {arguments['cmd']}"
        try:
            result = await invoke_tool(ctx, json.dumps(effective, ensure_ascii=False))
        except Exception:
            await self._audit.record(
                agent_id=agent_id,
                tool_call_id=tool_call_id,
                tool_name="exec_command",
                decision=review.decision,
                summary=review.summary,
                execution_status="failed",
            )
            raise
        finally:
            if workspace_locked:
                self._workspace_epoch += 1
        await self._audit.record(
            agent_id=agent_id,
            tool_call_id=tool_call_id,
            tool_name="exec_command",
            decision=review.decision,
            summary=review.summary,
            execution_status="succeeded",
        )
        return result

    async def invoke_write_stdin(
        self,
        *,
        ctx: Any,
        arguments: dict[str, Any],
        invoke_tool: InvokeTool,
    ) -> Any:
        raw_input = json.dumps(arguments, ensure_ascii=False)
        if self.mode == "off":
            return await invoke_tool(ctx, raw_input)

        chars = arguments.get("chars")
        payload = chars if isinstance(chars, str) else ""
        case_id = f"safety-{uuid4().hex[:12]}"
        if payload and set(payload) <= _INTERRUPT_CHARS:
            decision = SafetyDecision(
                allowed=True,
                source="deterministic",
                reason="Interrupt-only stdin payload.",
                case_id=case_id,
            )
        else:
            decision = SafetyDecision(
                allowed=False,
                source="deterministic",
                reason=(
                    "write_stdin is blocked in safety modes: what a live session does with the "
                    "payload depends on the process reading it and on buffered input, so the "
                    "effective action cannot be compiled before dispatch. Issue the command as "
                    "its own exec_command call."
                ),
                categories=("unreviewable_stdin",),
                case_id=case_id,
            )
        await self._audit.record(
            agent_id=str(getattr(ctx, "context", {}).get("agent_id", "unknown")),
            tool_call_id=str(getattr(ctx, "tool_call_id", "unknown")),
            tool_name="write_stdin",
            decision=decision,
            summary={"payload_digest": self._command_digest(payload)},
        )
        if not decision.allowed:
            return self.blocked_result(decision)
        return await invoke_tool(ctx, raw_input)

    async def _decide_exec(
        self,
        *,
        ctx: Any,
        arguments: dict[str, Any],
        plan: CommandPlan,
    ) -> _ExecReview:
        case_id = f"safety-{uuid4().hex[:12]}"
        workspace_sensitive = bool(plan.script_path or plan.inline_python or plan.input_files)

        async def compile_bundle() -> tuple[int, EvidenceBundle]:
            epoch = self._workspace_epoch
            return epoch, await compile_evidence(
                case_id=case_id,
                ctx=ctx,
                arguments=arguments,
                mode=self.mode,
                scope=self.scope,
                user_instruction=self.user_instruction,
                settings=self.settings,
                workspace_epoch=epoch,
            )

        if workspace_sensitive:
            async with self._workspace_lock:
                workspace_epoch, bundle = await compile_bundle()
        else:
            workspace_epoch, bundle = await compile_bundle()
        requested_paths: list[str] = []

        async def collect_workspace(paths: tuple[str, ...]) -> tuple[str, bool]:
            requested_paths.extend(path for path in paths if path not in requested_paths)
            async with self._workspace_lock:
                return await self._collect_workspace_evidence(
                    ctx=ctx,
                    bundle=bundle,
                    paths=paths,
                )

        try:
            decision = await self._decide_bundle(
                bundle,
                case_id,
                workspace_collector=collect_workspace,
            )
            canonical_action = json.dumps(
                arguments,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            raw_artifacts: object = bundle.packet.get("artifacts", [])
            artifact_digests: list[Any] = []
            if isinstance(raw_artifacts, list):
                typed_artifacts: list[Any] = cast("Any", raw_artifacts)
                artifact_digests.extend(
                    cast("dict[str, Any]", artifact).get("digest")
                    for artifact in typed_artifacts
                    if isinstance(artifact, dict)
                )
            summary: dict[str, Any] = {
                "action_digest": self._command_digest(canonical_action),
                "command_digest": self._command_digest(str(arguments.get("cmd") or "")),
                "executable": bundle.packet.get("pending_action", {}).get("executable"),
                "browser_action": bundle.packet.get("pending_action", {}).get("browser_action"),
                "artifact_digests": artifact_digests,
                "complete": bundle.complete,
                "reviewable_issue_count": len(bundle.reviewable_issues),
            }
            evidence_fingerprint = self._evidence_fingerprint(bundle)
            summary["evidence_fingerprint"] = evidence_fingerprint
            summary["evidence_revalidation_safe"] = self._evidence_revalidation_safe(bundle)
            summary["human_revalidation_safe"] = self._human_revalidation_safe(bundle)
            return _ExecReview(
                decision=decision,
                summary=summary,
                action_preview=canonical_action,
                workspace_epoch=workspace_epoch,
                workspace_evidence=bundle.workspace_evidence,
                evidence_fingerprint=evidence_fingerprint,
                requested_workspace_paths=tuple(requested_paths),
            )
        finally:
            bundle.cleanup()

    async def _evidence_is_current(
        self,
        *,
        ctx: Any,
        agent_id: str,
        arguments: dict[str, Any],
        review: _ExecReview,
    ) -> tuple[bool, bool]:
        if not review.workspace_evidence or (
            self._workspace_epoch == review.workspace_epoch and not review.requested_workspace_paths
        ):
            return True, False
        bundle = await compile_evidence(
            case_id=f"safety-refresh-{uuid4().hex[:12]}",
            ctx=ctx,
            arguments=arguments,
            mode=self.mode,
            scope=self.scope,
            user_instruction=self.user_instruction,
            settings=self.settings,
            workspace_epoch=self._workspace_epoch,
        )
        try:
            if review.requested_workspace_paths:
                await self._collect_workspace_evidence(
                    ctx=ctx,
                    bundle=bundle,
                    paths=review.requested_workspace_paths,
                )
            refreshed = self._evidence_fingerprint(bundle)
        finally:
            bundle.cleanup()
        fingerprint_changed = refreshed != review.evidence_fingerprint
        reusable = bool(review.summary.get("evidence_revalidation_safe", False)) or (
            review.decision.source == "human"
            and bool(review.summary.get("human_revalidation_safe", False))
        )
        current = not fingerprint_changed and reusable
        if fingerprint_changed:
            status = "changed_re_reviewing"
        elif reusable:
            status = "unchanged"
        else:
            status = "unchanged_re_reviewing"
        summary = dict(review.summary)
        summary["evidence_revalidation"] = {
            "status": status,
            "reviewed_fingerprint": review.evidence_fingerprint,
            "refreshed_fingerprint": refreshed,
        }
        await self._audit.record(
            agent_id=agent_id,
            tool_call_id=str(getattr(ctx, "tool_call_id", "unknown")),
            tool_name="exec_command",
            decision=review.decision,
            summary=summary,
            execution_status=("evidence_unchanged" if current else f"evidence_{status}"),
        )
        return current, fingerprint_changed

    @staticmethod
    def _frozen_artifact_source(bundle: EvidenceBundle, artifact: dict[str, Any]) -> str:
        """The text a reviewer needs to see for an already-frozen artifact.

        Script-source artifacts carry only structural metadata in the packet; their
        bytes live on disk under ``evidence_path``. Returning the inline ``source``
        alone therefore hands the reviewer an empty string for exactly the files it
        must read (scripts and their imports), which reads as "the frozen source was
        unavailable" and forces a needless human-approval defer. Fall back to the
        frozen file whenever no inline source is present.
        """
        inline = artifact.get("source")
        if isinstance(inline, str) and inline:
            return inline
        evidence_path = artifact.get("evidence_path")
        if not isinstance(evidence_path, str) or not evidence_path:
            return ""
        candidate = (bundle.root / evidence_path).resolve()
        try:
            if not candidate.is_relative_to(bundle.root.resolve()):
                return ""
            return candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    @staticmethod
    def _evidence_revalidation_safe(bundle: EvidenceBundle) -> bool:
        return bundle.complete

    @staticmethod
    def _human_revalidation_safe(bundle: EvidenceBundle) -> bool:
        unbounded = (
            "truncated",
            "exceeds",
            "unreadable",
            "cannot read",
            "outside",
            "unavailable",
        )
        return not any(
            marker in reason.lower() for reason in bundle.incomplete_reasons for marker in unbounded
        )

    @classmethod
    def _evidence_fingerprint(cls, bundle: EvidenceBundle) -> str:
        def stable(value: Any) -> Any:
            if isinstance(value, dict):
                return {
                    str(key): stable(item)
                    for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
                    if key not in {"case_id", "evidence_path", "workspace_epoch"}
                }
            if isinstance(value, list):
                return [stable(item) for item in value]
            if isinstance(value, tuple):
                return [stable(item) for item in value]
            return value

        payload = {
            "packet": stable(bundle.packet),
            "complete": bundle.complete,
            "incomplete_reasons": bundle.incomplete_reasons,
            "reviewable_issues": bundle.reviewable_issues,
            "deterministic_block": bundle.deterministic_block,
            "deterministic_allow": bundle.deterministic_allow,
            "mutating_request": bundle.mutating_request,
            "workspace_evidence": bundle.workspace_evidence,
        }
        return cls._command_digest(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        )

    async def _collect_workspace_evidence(  # noqa: PLR0912, PLR0915 - bounded collection is explicit.
        self,
        *,
        ctx: Any,
        bundle: EvidenceBundle,
        paths: tuple[str, ...],
    ) -> tuple[str, bool]:
        inner = getattr(ctx, "context", None)
        session = (
            cast("dict[str, Any]", inner).get("sandbox_session")
            if isinstance(inner, dict)
            else None
        )
        if session is None:
            return "Workspace collection failed: sandbox session unavailable.", True

        original_requests = tuple(dict.fromkeys(paths))
        limit = min(64, self.settings.max_dependencies)
        requested_files: list[str] = []
        listing_results: list[dict[str, Any]] = []
        listing_gaps: list[str] = []

        async def collect_directory(path: str, depth: int) -> None:
            if depth > 2 or len(requested_files) >= limit:
                listing_gaps.append(
                    f"requested workspace directory traversal was truncated: {path}"
                )
                return
            try:
                entries = await session.ls(Path(path))
            except Exception as exc:  # noqa: BLE001 - returned as evidence metadata.
                listing_gaps.append(
                    f"cannot list requested workspace directory {path}: {type(exc).__name__}: {exc}"
                )
                listing_results.append(
                    {"path": path, "operation": "list", "error": f"{type(exc).__name__}: {exc}"}
                )
                return
            rendered_entries: list[dict[str, Any]] = []
            for entry in sorted(entries, key=lambda item: str(item.path)):
                raw_kind = getattr(entry, "kind", "other")
                kind = getattr(raw_kind, "value", str(raw_kind))
                rendered_entries.append(
                    {
                        "path": str(entry.path),
                        "kind": kind,
                        "size": int(getattr(entry, "size", 0)),
                    }
                )
                if kind == "file":
                    if int(getattr(entry, "size", 0)) > self.settings.max_artifact_bytes:
                        listing_gaps.append(
                            f"requested workspace file exceeds the per-file evidence limit: "
                            f"{entry.path}"
                        )
                        continue
                    if len(requested_files) < limit:
                        requested_files.append(str(entry.path))
                    else:
                        listing_gaps.append(
                            f"requested workspace directory file limit was reached: {path}"
                        )
                        break
                elif kind == "directory":
                    await collect_directory(str(entry.path), depth + 1)
            listing_results.append({"path": path, "operation": "list", "entries": rendered_entries})

        for raw_path in original_requests:
            candidate = raw_path if raw_path.startswith("/") else f"/workspace/{raw_path}"
            normalized = posixpath.normpath(candidate)
            if raw_path.endswith("/") or normalized == "/workspace":
                if normalized == "/workspace" or normalized.startswith("/workspace/"):
                    await collect_directory(normalized, 0)
                else:
                    listing_gaps.append(
                        f"requested workspace directory is outside /workspace: {raw_path}"
                    )
                continue
            requested_files.append(raw_path)

        requested = tuple(dict.fromkeys(requested_files))
        dropped = requested[limit:]
        if len(requested) > limit:
            requested = requested[:limit]
        artifacts = bundle.packet.setdefault("artifacts", [])
        if not isinstance(artifacts, list):
            return "Workspace collection failed: artifact packet is invalid.", True

        existing = {
            str(item.get("path")): item
            for item in artifacts
            if isinstance(item, dict) and item.get("path")
        }
        results: list[dict[str, Any]] = list(listing_results)
        resolved: set[str] = set()
        total = sum(int(item.get("bytes") or 0) for item in artifacts if isinstance(item, dict))
        collection_gaps = [
            "requested workspace path was not collected because the count limit was exceeded: "
            f"{path}"
            for path in dropped
        ]
        collection_gaps.extend(listing_gaps)
        results.extend({"path": path, "error": "path count limit reached"} for path in dropped)
        preview_remaining = self.settings.inspection_output_bytes // 2
        for raw_path in requested:
            candidate = raw_path if raw_path.startswith("/") else f"/workspace/{raw_path}"
            normalized = posixpath.normpath(candidate)
            if normalized != "/workspace" and not normalized.startswith("/workspace/"):
                results.append({"path": raw_path, "error": "outside /workspace"})
                collection_gaps.append(
                    f"requested workspace path is outside /workspace: {raw_path}"
                )
                continue
            if normalized in existing:
                artifact = existing[normalized]
                resolved.add(normalized)
                frozen_source = self._frozen_artifact_source(bundle, artifact)
                preview = frozen_source[:preview_remaining]
                results.append(
                    {
                        "path": normalized,
                        "digest": artifact.get("digest"),
                        "bytes": artifact.get("bytes"),
                        "status": "already frozen",
                        "source": preview,
                        "preview_truncated": len(frozen_source) > len(preview),
                    }
                )
                preview_remaining = max(0, preview_remaining - len(preview))
                continue
            remaining = self.settings.max_total_artifact_bytes - total
            if remaining <= 0:
                results.append({"path": normalized, "error": "total byte limit reached"})
                collection_gaps.append(
                    f"requested workspace file exceeds the total evidence limit: {normalized}"
                )
                continue
            read_limit = min(self.settings.max_artifact_bytes, remaining)
            try:
                stream = await session.read(Path(normalized))
                try:
                    data = stream.read(read_limit + 1)
                finally:
                    close = getattr(stream, "close", None)
                    if callable(close):
                        close()
                body = data.encode() if isinstance(data, str) else bytes(data)
            except Exception as exc:  # noqa: BLE001 - returned as bounded evidence metadata.
                results.append({"path": normalized, "error": f"{type(exc).__name__}: {exc}"})
                collection_gaps.append(
                    f"cannot read requested workspace file {normalized}: "
                    f"{type(exc).__name__}: {exc}"
                )
                continue
            truncated = len(body) > read_limit
            body = body[:read_limit]
            total += len(body)
            digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
            evidence_name = (
                f"requested-{len(results):03d}-{hashlib.sha256(normalized.encode()).hexdigest()[:12]}-"
                f"{PurePosixPath(normalized).name}"
            )
            (bundle.root / "artifacts" / evidence_name).write_bytes(body)
            artifact = {
                "path": normalized,
                "role": "requested_input",
                "digest": digest,
                "bytes": len(body),
                "truncated": truncated,
                "source": body.decode("utf-8", errors="replace"),
                "evidence_path": f"artifacts/{evidence_name}",
            }
            artifacts.append(artifact)
            existing[normalized] = artifact
            if not truncated:
                resolved.add(normalized)
            else:
                collection_gaps.append(f"requested workspace file is truncated: {normalized}")
            results.append(
                {
                    "path": normalized,
                    "digest": digest,
                    "bytes": len(body),
                    "truncated": truncated,
                    "source": body[:preview_remaining].decode("utf-8", errors="replace"),
                    "preview_truncated": len(body) > preview_remaining,
                }
            )
            preview_remaining = max(0, preview_remaining - min(len(body), preview_remaining))

        if resolved:
            resolvable_prefixes = (
                "input file is missing:",
                "cannot read input file",
                "cannot read script entrypoint:",
            )
            requested_script = any(
                path.endswith((".py", ".sh", ".bash", ".js", ".mjs")) for path in resolved
            )
            generic_script_gaps = (
                "compound command executes a script that cannot be frozen",
                "inline shell source executes a workspace-dependent command",
            )
            bundle.incomplete_reasons = [
                reason
                for reason in bundle.incomplete_reasons
                if not (
                    reason.startswith(resolvable_prefixes)
                    and any(path in reason for path in resolved)
                )
                and not (requested_script and reason.startswith(generic_script_gaps))
            ]
            for path in sorted(resolved):
                if path.endswith((".py", ".sh", ".bash", ".js", ".mjs")):
                    issue = f"requested script requires semantic inspection: {path}"
                    if issue not in bundle.reviewable_issues:
                        bundle.reviewable_issues.append(issue)
        bundle.incomplete_reasons.extend(
            gap for gap in collection_gaps if gap not in bundle.incomplete_reasons
        )
        bundle.complete = not bundle.incomplete_reasons
        bundle.workspace_evidence = True
        bundle.packet["completeness"] = {
            "status": (
                "incomplete"
                if bundle.incomplete_reasons
                else "reviewable"
                if bundle.reviewable_issues
                else "complete"
            ),
            "reasons": [*bundle.incomplete_reasons, *bundle.reviewable_issues],
            "hard_gaps": bundle.incomplete_reasons,
            "reviewable_issues": bundle.reviewable_issues,
        }
        packet_json = json.dumps(bundle.packet, ensure_ascii=False, indent=2, default=str)
        if len(packet_json) > self.settings.max_input_chars:
            gap = "augmented safety packet exceeds configured input limit"
            if gap not in bundle.incomplete_reasons:
                bundle.incomplete_reasons.append(gap)
            bundle.complete = False
            bundle.packet["completeness"]["status"] = "incomplete"
            bundle.packet["completeness"]["reasons"] = [
                *bundle.incomplete_reasons,
                *bundle.reviewable_issues,
            ]
            bundle.packet["completeness"]["hard_gaps"] = bundle.incomplete_reasons
            packet_json = json.dumps(bundle.packet, ensure_ascii=False, indent=2, default=str)
        (bundle.root / "case.json").write_text(
            packet_json,
            encoding="utf-8",
        )
        return json.dumps({"workspace_artifacts": results}, ensure_ascii=False), False

    async def _decide_bundle(
        self,
        bundle: EvidenceBundle,
        case_id: str,
        *,
        workspace_collector: WorkspaceEvidenceCollector | None = None,
    ) -> SafetyDecision:
        if bundle.deterministic_block:
            return SafetyDecision(
                allowed=False,
                source="deterministic",
                reason=bundle.deterministic_block,
                categories=("policy_block",),
                case_id=case_id,
            )
        if not bundle.complete:
            if self.mode == "guarded" and self._approval_callback is not None:
                return await self._reviewer.review(
                    bundle,
                    human_approval_available=True,
                    workspace_collector=workspace_collector,
                )
            return SafetyDecision(
                allowed=False,
                source="deterministic",
                reason="Safety evidence is incomplete: " + "; ".join(bundle.incomplete_reasons),
                categories=("incomplete_evidence",),
                case_id=case_id,
            )
        if bundle.reviewable_issues:
            return await self._reviewer.review(
                bundle,
                human_approval_available=(
                    self.mode == "guarded" and self._approval_callback is not None
                ),
                workspace_collector=workspace_collector,
            )
        if bundle.deterministic_allow:
            return SafetyDecision(
                allowed=True,
                source="deterministic",
                reason=bundle.deterministic_allow,
                case_id=case_id,
            )
        return await self._reviewer.review(
            bundle,
            human_approval_available=(
                self.mode == "guarded" and self._approval_callback is not None
            ),
            workspace_collector=workspace_collector,
        )

    async def _resolve_approval(  # noqa: PLR0911 - fail-closed outcomes stay explicit.
        self, *, ctx: Any, review: _ExecReview
    ) -> _ExecReview:
        decision = review.decision
        if not decision.deferred:
            return review
        if decision.source != "reviewer" or decision.allowed:
            return replace(
                review,
                decision=SafetyDecision(
                    allowed=False,
                    source="review_error",
                    reason="Only a blocking reviewer ambiguity may request human approval.",
                    categories=("invalid_approval_request",),
                    case_id=decision.case_id,
                    risk=decision.risk,
                ),
            )
        callback = self._approval_callback if self.mode == "guarded" else None
        if callback is None:
            return replace(
                review,
                decision=replace(
                    decision,
                    deferred=False,
                    reason=(
                        "The reviewer deferred, but no human approval channel is available: "
                        f"{decision.reason}"
                    ),
                    categories=decision.categories or ("approval_unavailable",),
                ),
            )

        agent_id = str(getattr(ctx, "context", {}).get("agent_id", "unknown"))
        tool_call_id = str(getattr(ctx, "tool_call_id", "unknown"))
        risk = decision.risk
        if decision.case_id is None or risk is None:
            return replace(
                review,
                decision=SafetyDecision(
                    allowed=False,
                    source="review_error",
                    reason="Deferred safety review omitted required approval metadata.",
                    categories=("approval_metadata_missing",),
                    case_id=decision.case_id,
                ),
            )
        if agent_id == "unknown":
            return replace(
                review,
                decision=SafetyDecision(
                    allowed=False,
                    source="review_error",
                    reason="Deferred safety review has no owning agent.",
                    categories=("approval_agent_missing",),
                    case_id=decision.case_id,
                    risk=risk,
                ),
            )
        if len(review.action_preview) > _MAX_APPROVAL_ACTION_CHARS:
            return replace(
                review,
                decision=SafetyDecision(
                    allowed=False,
                    source="review_error",
                    reason=(
                        "The exact action is too large to display safely for human approval. "
                        "Split it into smaller tool calls."
                    ),
                    categories=("approval_action_too_large",),
                    case_id=decision.case_id,
                    risk=risk,
                ),
            )
        request = SafetyApprovalRequest(
            request_id=decision.case_id,
            case_id=decision.case_id,
            tool_call_id=tool_call_id,
            agent_id=agent_id,
            tool_name=review.tool_name,
            action=review.action_preview,
            digest=str(review.summary["action_digest"]),
            reason=decision.reason,
            categories=decision.categories,
            risk=risk,
        )
        requested_summary = dict(review.summary)
        requested_summary["approval"] = {
            "status": "requested",
            "reviewer_risk": risk,
        }
        await self._audit.record(
            agent_id=agent_id,
            tool_call_id=tool_call_id,
            tool_name=review.tool_name,
            decision=decision,
            summary=requested_summary,
        )
        try:
            outcome = await callback(request)
        except Exception as exc:
            logger.exception("human approval failed for %s", decision.case_id)
            resolved = SafetyDecision(
                allowed=False,
                source="review_error",
                reason=f"Human approval failed closed: {type(exc).__name__}: {exc}",
                categories=("approval_error",),
                case_id=decision.case_id,
                risk=risk,
            )
            status = "error"
        else:
            if outcome == "cancelled":
                resolved = SafetyDecision(
                    allowed=False,
                    source="system",
                    reason=(
                        "Human approval was cancelled because the requesting run or agent stopped."
                    ),
                    categories=(*decision.categories, "approval_cancelled"),
                    case_id=decision.case_id,
                    risk=risk,
                )
                resolved_summary = dict(review.summary)
                resolved_summary["approval"] = {
                    "status": "cancelled",
                    "reviewer_risk": risk,
                }
                return replace(review, decision=resolved, summary=resolved_summary)
            approved = outcome is True
            if approved and not await self._agent_is_active(ctx, agent_id):
                approved = False
                categories = (*decision.categories, "agent_inactive")
                reason = (
                    "Human approval was ignored because the requesting agent is no longer active. "
                    f"Reviewer: {decision.reason}"
                )
            else:
                categories = decision.categories
                reason = (
                    f"Human {'approved' if approved is True else 'denied'} deferred action. "
                    f"Reviewer: {decision.reason}"
                )
            resolved = SafetyDecision(
                allowed=approved is True,
                source="human",
                reason=reason,
                categories=categories,
                case_id=decision.case_id,
                risk=risk,
            )
            status = "approved" if approved is True else "denied"
        resolved_summary = dict(review.summary)
        resolved_summary["approval"] = {
            "status": status,
            "reviewer_risk": risk,
        }
        return replace(review, decision=resolved, summary=resolved_summary)

    @staticmethod
    async def _agent_is_active(ctx: Any, agent_id: str) -> bool:
        # A real scan always carries a coordinator, so the liveness gate below is
        # strict in production. When one is absent — only in unit tests that drive the
        # runtime without a graph — assume active rather than block, since there is no
        # liveness signal to consult. An actual snapshot failure still fails closed.
        inner = getattr(ctx, "context", None)
        if not isinstance(inner, dict):
            return True
        coordinator = cast("dict[str, Any]", inner).get("coordinator")
        graph_snapshot = getattr(coordinator, "graph_snapshot", None)
        if not callable(graph_snapshot):
            return True
        try:
            snapshot = await cast(
                "Callable[[], Awaitable[tuple[Any, dict[str, str], Any, Any]]]",
                graph_snapshot,
            )()
        except Exception:
            logger.exception("could not verify agent status after human approval")
            return False
        statuses = snapshot[1]
        return statuses.get(agent_id) in {"running", "waiting", "budget_paused"}

    async def invoke_mutating_tool(
        self,
        *,
        ctx: Any,
        tool_name: str,
        raw_input: str,
        invoke_tool: InvokeTool,
    ) -> Any:
        if self.mode == "off":
            return await invoke_tool(ctx, raw_input)
        case_id = f"safety-{uuid4().hex[:12]}"
        if tool_name == "repeat_request":
            # The effective request is deterministic and immutable, so it is
            # compiled and reviewed like any other network action rather than
            # blocked outright.
            return await self._review_repeat_request(
                ctx=ctx, raw_input=raw_input, invoke_tool=invoke_tool, case_id=case_id
            )
        async with self._workspace_lock:
            # Guarded workspaces are isolated copies; patches remain local to the run.
            try:
                return await invoke_tool(ctx, raw_input)
            finally:
                self._workspace_epoch += 1

    async def _review_repeat_request(
        self,
        *,
        ctx: Any,
        raw_input: str,
        invoke_tool: InvokeTool,
        case_id: str,
    ) -> Any:
        agent_id = str(getattr(ctx, "context", {}).get("agent_id", "unknown"))
        tool_call_id = str(getattr(ctx, "tool_call_id", "unknown"))
        try:
            arguments = json.loads(raw_input)
        except (json.JSONDecodeError, TypeError):
            arguments = None
        request_id = arguments.get("request_id") if isinstance(arguments, dict) else None
        raw_mods = arguments.get("modifications") if isinstance(arguments, dict) else None
        modifications = raw_mods if isinstance(raw_mods, dict) else {}

        if not isinstance(request_id, str) or not request_id:
            return await self._block_network(
                agent_id,
                tool_call_id,
                case_id,
                "repeat_request did not name a request_id to resolve for review.",
            )

        effective = await self._resolve_repeat_request(ctx, request_id, modifications)
        if effective is None:
            return await self._block_network(
                agent_id,
                tool_call_id,
                case_id,
                "The captured request could not be resolved for review — the request id is "
                "unknown or the proxy is unavailable.",
            )

        bundle = compile_network_evidence(
            case_id=case_id,
            tool_name="repeat_request",
            request_id=request_id,
            modifications=modifications,
            effective=effective,
            mode=self.mode,
            scope=self.scope,
            user_instruction=self.user_instruction,
            settings=self.settings,
            agent_id=agent_id,
            tool_call_id=tool_call_id,
        )
        try:
            decision = await self._decide_bundle(bundle, case_id)
            method = str(effective.get("method") or "").upper()
            url = str(effective.get("url") or "")
            canonical = json.dumps(
                {
                    "method": method,
                    "url": url,
                    "headers": effective.get("headers") or {},
                    "body": effective.get("body") or "",
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            summary: dict[str, Any] = {
                "action_digest": self._command_digest(canonical),
                "request_id_digest": self._command_digest(str(request_id)),
                "http_method": method,
                "mutating_request": bundle.mutating_request,
                "complete": bundle.complete,
            }
            review = _ExecReview(
                decision=decision,
                summary=summary,
                action_preview=self._network_action_preview(method, url),
                workspace_epoch=0,
                workspace_evidence=False,
                evidence_fingerprint="",
                requested_workspace_paths=(),
                tool_name="repeat_request",
            )
        finally:
            bundle.cleanup()

        review = await self._resolve_approval(ctx=ctx, review=review)
        await self._audit.record(
            agent_id=agent_id,
            tool_call_id=tool_call_id,
            tool_name="repeat_request",
            decision=review.decision,
            summary=review.summary,
        )
        if not review.decision.allowed:
            return self.blocked_result(review.decision)
        if review.decision.source == "human" and not await self._agent_is_active(ctx, agent_id):
            inactive = SafetyDecision(
                allowed=False,
                source="system",
                reason="Approved action was cancelled because the requesting agent stopped.",
                categories=(*review.decision.categories, "agent_inactive"),
                case_id=review.decision.case_id,
                risk=review.decision.risk,
            )
            await self._audit.record(
                agent_id=agent_id,
                tool_call_id=tool_call_id,
                tool_name="repeat_request",
                decision=inactive,
                summary=review.summary,
            )
            return self.blocked_result(inactive)
        # The tool re-resolves through the same resolver, so the request that is
        # sent is byte-for-byte the one that was reviewed.
        try:
            result = await invoke_tool(ctx, raw_input)
        except Exception:
            await self._audit.record(
                agent_id=agent_id,
                tool_call_id=tool_call_id,
                tool_name="repeat_request",
                decision=review.decision,
                summary=review.summary,
                execution_status="failed",
            )
            raise
        await self._audit.record(
            agent_id=agent_id,
            tool_call_id=tool_call_id,
            tool_name="repeat_request",
            decision=review.decision,
            summary=review.summary,
            execution_status="succeeded",
        )
        return result

    async def _resolve_repeat_request(
        self, ctx: Any, request_id: str, modifications: dict[str, Any]
    ) -> dict[str, Any] | None:
        # Lazy import keeps the safety package's import graph off the proxy/caido
        # stack; the resolver is shared so the reviewed and sent bytes match.
        from strix.tools.proxy.tools import (  # noqa: PLC0415
            resolve_effective_request_for_ctx,
        )

        try:
            return await resolve_effective_request_for_ctx(ctx, request_id, modifications)
        except Exception:
            logger.exception("could not resolve repeat_request for safety review")
            return None

    async def _block_network(
        self, agent_id: str, tool_call_id: str, case_id: str, reason: str
    ) -> str:
        decision = SafetyDecision(
            allowed=False,
            source="deterministic",
            reason=reason,
            categories=("unresolved_network_mutation",),
            case_id=case_id,
        )
        await self._audit.record(
            agent_id=agent_id,
            tool_call_id=tool_call_id,
            tool_name="repeat_request",
            decision=decision,
            summary={"complete": False},
        )
        return self.blocked_result(decision)

    @staticmethod
    def _network_action_preview(method: str, url: str) -> str:
        preview = f"{method} {url}".strip()
        if len(preview) > _MAX_APPROVAL_ACTION_CHARS:
            preview = preview[:_MAX_APPROVAL_ACTION_CHARS]
        return preview

    @staticmethod
    def blocked_result(decision: SafetyDecision) -> str:
        return json.dumps(
            {
                "success": False,
                "status": "blocked",
                "error": "Action blocked by safety policy",
                "safety": {
                    "case_id": decision.case_id,
                    "source": decision.source,
                    "reason": decision.reason,
                    "categories": list(decision.categories),
                    "risk": decision.risk,
                },
            },
            ensure_ascii=False,
        )

    @staticmethod
    def _command_digest(command: str) -> str:
        return hashlib.sha256(command.encode()).hexdigest()


def safety_runtime_from_context(ctx: Any) -> SafetyRuntime | None:
    inner = getattr(ctx, "context", None)
    if not isinstance(inner, dict):
        return None
    runtime = cast("dict[str, Any]", inner).get("safety_runtime")
    return runtime if isinstance(runtime, SafetyRuntime) else None
