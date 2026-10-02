"""Repository fix preparation engine."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import subprocess
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from strix.fix.contracts import (
    CheckResult,
    FileManifestEntry,
    FixCandidateV1,
    FixPreparationAttempt,
    FixPreparationRequestV1,
    FixPreparationResultV1,
    PreparationState,
    RepairOutcome,
    RepairStatus,
    VerificationDecision,
    VerifierResult,
)


class PreparationCancelledError(RuntimeError):
    pass


ManifestBuilder = Callable[[Path], Awaitable[tuple[list[FileManifestEntry], str, str | None]]]
CancellationCheck = Callable[[], bool]


@dataclass(slots=True)
class PreparationContext:
    request: FixPreparationRequestV1
    workspace: Path
    candidate: FixCandidateV1
    attempt: int = 0
    feedback: list[FixPreparationAttempt] = field(default_factory=list[FixPreparationAttempt])


RepairAgent = Callable[
    [PreparationContext, list[CheckResult]],
    Awaitable[RepairOutcome],
]
IndependentVerifier = Callable[
    [PreparationContext, list[CheckResult]],
    Awaitable[VerifierResult],
]
SourceVerifier = Callable[[PreparationContext], Awaitable[bool]]
EvidenceReader = Callable[[], Awaitable[list[CheckResult]]]


async def build_git_manifest(
    workspace: Path,
) -> tuple[list[FileManifestEntry], str, str | None]:
    process = await asyncio.create_subprocess_exec(
        "git",
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "-z",
        cwd=workspace,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    output, error = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(error.decode(errors="replace"))

    entries: list[FileManifestEntry] = []
    changed_files: list[str] = []
    records = [record for record in output.decode(errors="replace").split("\0") if record]
    workspace_resolved = workspace.resolve()
    index = 0
    while index < len(records):
        record = records[index]
        status = record[:2]
        path_text = record[3:]
        if "R" in status or "C" in status:
            index += 1
        path = workspace / path_text
        changed_files.append(path_text)
        operation: Literal["add", "modify", "delete"]
        if status == "??" or "A" in status:
            operation = "add"
        elif "D" in status:
            operation = "delete"
        else:
            operation = "modify"
        resolved = path.resolve()
        contained = resolved.is_relative_to(workspace_resolved)
        if operation == "add" and contained and resolved.is_dir():
            for child in sorted(resolved.rglob("*")):
                child_resolved = child.resolve()
                if (
                    not child_resolved.is_file()
                    or not child_resolved.is_relative_to(workspace_resolved)
                    or ".git" in child.relative_to(resolved).parts
                ):
                    continue
                entries.append(
                    FileManifestEntry(
                        path=child_resolved.relative_to(workspace_resolved).as_posix(),
                        operation="add",
                        resulting_sha256=hashlib.sha256(child_resolved.read_bytes()).hexdigest(),
                    )
                )
            index += 1
            continue
        resulting = (
            hashlib.sha256(resolved.read_bytes()).hexdigest()
            if contained and resolved.is_file()
            else None
        )
        original: str | None = None
        if operation != "add":
            original_process = await asyncio.create_subprocess_exec(
                "git",
                "show",
                f"HEAD:{path_text}",
                cwd=workspace,
                stdout=asyncio.subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            original_bytes, _ = await original_process.communicate()
            if original_process.returncode == 0:
                original = hashlib.sha256(original_bytes).hexdigest()
        entries.append(
            FileManifestEntry(
                path=path_text,
                operation=operation,
                original_sha256=original,
                resulting_sha256=resulting,
            )
        )
        index += 1

    summary = "\n".join(f"{entry.operation}: {entry.path}" for entry in entries)
    return entries, summary, None


async def build_git_patch(workspace: Path, manifest: list[FileManifestEntry]) -> bytes:
    """Include new files in the exact diff the reviewer and artifact consumer receive."""
    chunks: list[bytes] = []
    commands = [["git", "diff", "--binary", "HEAD", "--"]]
    for entry in manifest:
        if entry.operation == "add" and not await _tracked_in_index(workspace, entry.path):
            commands.append(  # noqa: PERF401 - requires sequential async index lookup
                ["git", "diff", "--no-index", "--binary", "--", "/dev/null", entry.path]
            )
    for argv in commands:
        process = await asyncio.create_subprocess_exec(
            *argv, cwd=workspace, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        output, error = await process.communicate()
        if process.returncode not in {0, 1}:
            raise RuntimeError(error.decode(errors="replace"))
        chunks.append(output)
    return b"".join(chunks)


async def _tracked_in_index(workspace: Path, path: str) -> bool:
    process = await asyncio.create_subprocess_exec(
        "git",
        "ls-files",
        "--error-unmatch",
        "--",
        path,
        cwd=workspace,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return await process.wait() == 0


async def workspace_digest(workspace: Path) -> str:
    manifest, _, _ = await build_git_manifest(workspace)
    payload = json.dumps(
        [entry.model_dump(mode="json") for entry in manifest],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


async def _verify_source(context: PreparationContext) -> bool:
    identity = context.candidate.source_identity
    if identity is None:
        return False
    if identity.kind == "commit":
        process = await asyncio.create_subprocess_exec(
            "git",
            "rev-parse",
            "HEAD",
            cwd=context.workspace,
            stdout=asyncio.subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        output, _ = await process.communicate()
        if process.returncode != 0 or output.decode().strip().lower() != identity.value:
            return False
    status_process = await asyncio.create_subprocess_exec(
        "git",
        "status",
        "--porcelain=v1",
        "-z",
        cwd=context.workspace,
        stdout=asyncio.subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    status_output, _ = await status_process.communicate()
    return status_process.returncode == 0 and not status_output.strip(b"\x00")


async def prepare_fix(  # noqa: PLR0911, PLR0912
    request: FixPreparationRequestV1,
    workspace: Path,
    *,
    repair: RepairAgent,
    verify: IndependentVerifier | None = None,
    manifest_builder: ManifestBuilder = build_git_manifest,
    source_verifier: SourceVerifier = _verify_source,
    evidence_reader: EvidenceReader | None = None,
    cancelled: CancellationCheck = lambda: False,
) -> FixPreparationResultV1:
    """One native agent owns implementation and testing; export successful work only."""
    started = time.monotonic()
    context = PreparationContext(request=request, workspace=workspace, candidate=request.candidate)
    completion: RepairOutcome | None = None
    verifier: VerifierResult | None = None
    attempt_history: list[FixPreparationAttempt] = []

    async def finish(state: PreparationState, reason: str) -> FixPreparationResultV1:
        manifest: list[FileManifestEntry] = []
        summary, artifact = "", None
        if state is PreparationState.READY:
            manifest, summary, artifact = await manifest_builder(workspace)
        return FixPreparationResultV1(
            state=state,
            stop_reason=reason,
            source_identity=context.candidate.source_identity,
            candidate=context.candidate,
            candidate_digest=context.candidate.digest(),
            completion=completion,
            validation_mode="agent_review" if verifier else "single_agent",
            gaps=list(completion.gaps) if completion else [],
            prepared_source_digest=(
                verifier.source_digest
                if verifier and state is PreparationState.READY
                else completion.source_digest
                if completion and state is PreparationState.READY
                else None
            ),
            final_file_manifest=manifest,
            changed_files=[entry.path for entry in manifest],
            diff_summary=summary,
            artifact_ref=artifact,
            checks=await evidence_reader()
            if evidence_reader
            else (completion.command_results if completion else []),
            verifier=verifier,
            attempt_history=attempt_history,
            attempts=1 if completion else 0,
            elapsed_seconds=time.monotonic() - started,
        )

    try:
        async with asyncio.timeout(request.timeout_seconds):
            if cancelled():
                raise PreparationCancelledError  # noqa: TRY301
            if context.candidate.blocker:
                return await finish(PreparationState.BLOCKED, context.candidate.blocker.reason)
            if not await source_verifier(context):
                return await finish(PreparationState.STALE, "The finding source no longer matches.")
            completion = await repair(context, [])
            if cancelled():
                raise PreparationCancelledError  # noqa: TRY301
            if completion.status is not RepairStatus.COMPLETE:
                return await finish(PreparationState.BLOCKED, completion.summary)
            manifest, _, _ = await build_git_manifest(workspace)
            if not manifest:
                return await finish(PreparationState.BLOCKED, "The agent produced no patch.")
            if completion.source_digest != await workspace_digest(workspace):
                return await finish(PreparationState.BLOCKED, "Source changed after completion.")
            if verify is None:
                return await finish(
                    PreparationState.BLOCKED,
                    "Independent verification is required before delivery.",
                )
            before_review = await workspace_digest(workspace)
            attempt = FixPreparationAttempt(
                attempt=1,
                repair=completion,
                checks=await evidence_reader()
                if evidence_reader
                else list(completion.command_results),
                workspace_digest=before_review,
            )
            attempt_history.append(attempt)
            context.feedback.append(attempt)
            verifier = await verify(context, attempt.checks)
            attempt.verifier = verifier
            if cancelled():
                raise PreparationCancelledError  # noqa: TRY301
            after_review = await workspace_digest(workspace)
            if after_review != before_review:
                return await finish(
                    PreparationState.BLOCKED,
                    "The deliverable changed during independent verification.",
                )
            if verifier.decision is not VerificationDecision.VERIFIED:
                return await finish(PreparationState.BLOCKED, verifier.summary)
            if verifier.source_digest != after_review:
                return await finish(
                    PreparationState.BLOCKED,
                    "Independent verification did not approve the final source snapshot.",
                )
            return await finish(
                PreparationState.READY,
                "Independent verification approved the draft PR.",
            )
    except PreparationCancelledError:
        return await finish(PreparationState.FAILED, "Fix preparation was cancelled.")
    except TimeoutError:
        return await finish(PreparationState.FAILED, "Fix preparation exceeded its time limit.")
    except Exception as error:
        logging.getLogger(__name__).exception("Fix preparation failed")
        return await finish(PreparationState.FAILED, f"Fix stopped after {type(error).__name__}.")
