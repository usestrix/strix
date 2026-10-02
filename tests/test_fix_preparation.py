# mypy: allow-untyped-defs, allow-untyped-calls, disable-error-code="union-attr"

"""Tests for fix candidate anchoring and repository preparation."""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import sys
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from strix.fix.contracts import (
    CandidateLocation,
    CheckResult,
    CheckStatus,
    CommandSpec,
    FixCandidateV1,
    FixEdit,
    FixPreparationRequestV1,
    PreparationState,
    RepairOutcome,
    RepairStatus,
    ReproductionSpec,
    SourceIdentity,
    SourceIdentityKind,
    VerificationDecision,
    VerifierResult,
    candidate_from_legacy_report,
)
from strix.fix.locations import AnchorStatus, anchor_location
from strix.fix.prepare import (
    PreparationContext,
    build_git_manifest,
    build_git_patch,
    prepare_fix,
    workspace_digest,
)


if TYPE_CHECKING:
    from pathlib import Path


def _git(workspace: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["/usr/bin/git", *args],
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _workspace(tmp_path: Path) -> tuple[Path, str]:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    _git(workspace, "init")
    _git(workspace, "config", "user.email", "test@example.com")
    _git(workspace, "config", "user.name", "Test")
    (workspace / "app.py").write_text("def result():\n    return 'unsafe'\n", encoding="utf-8")
    (workspace / "test_existing.py").write_text(
        "import unittest\nfrom app import result\nclass Existing(unittest.TestCase):\n"
        "    def test_result_type(self): self.assertIsInstance(result(), str)\n"
    )
    _git(workspace, "add", "app.py", "test_existing.py")
    _git(workspace, "commit", "-m", "initial")
    return workspace, _git(workspace, "rev-parse", "HEAD")


def _candidate(
    commit: str,
    *,
    reproduction: ReproductionSpec | None = None,
) -> FixCandidateV1:
    if reproduction is None:
        reproduction = ReproductionSpec(
            instructions="Confirm that result returns safe.",
            command=CommandSpec(
                name="security reproduction",
                argv=[
                    sys.executable,
                    "-c",
                    "from app import result; assert result() == 'safe'",
                ],
            ),
        )
    return FixCandidateV1(
        source_identity=SourceIdentity(kind=SourceIdentityKind.COMMIT, value=commit),
        security_invariant="Return a safe value.",
        finding_locations=[
            CandidateLocation(
                file="app.py",
                start_line=1,
                end_line=2,
                snippet="def result():\n    return 'unsafe'",
            )
        ],
        draft_edits=[
            FixEdit(
                file="app.py",
                start_line=2,
                end_line=2,
                before="    return 'unsafe'",
                after="    return 'safe'",
            )
        ],
        reproduction=reproduction,
    )


def _request(candidate: FixCandidateV1, *, attempts: int = 2) -> FixPreparationRequestV1:
    return FixPreparationRequestV1(
        scan_id="scan-1",
        finding_id="finding-1",
        candidate=candidate,
        checks=[
            CommandSpec(
                name="compile",
                argv=[
                    sys.executable,
                    "-c",
                    "compile(open('app.py', encoding='utf-8').read(), 'app.py', 'exec')",
                ],
            )
        ],
        max_repair_attempts=attempts,
        max_agent_turns=8,
        network_allowed=True,
    )


async def test_explicit_candidate_blocker_does_not_start_agents(tmp_path: Path) -> None:
    workspace, _commit = _workspace(tmp_path)
    candidate = FixCandidateV1.model_validate(
        {
            "security_invariant": "Guard access",
            "blocker": {"reason": "Affected source is unavailable."},
        }
    )
    repair = AsyncMock()
    result = await prepare_fix(_request(candidate), workspace, repair=repair)
    assert result.state is PreparationState.BLOCKED
    assert result.stop_reason == candidate.blocker.reason
    assert result.attempts == 0
    repair.assert_not_awaited()


async def _noop_repair(
    context: PreparationContext,
    _checks: list[CheckResult],
) -> RepairOutcome:
    path = context.workspace / "app.py"
    if path.exists():
        path.write_text(
            path.read_text(encoding="utf-8").replace("'unsafe'", "'safe'"),
            encoding="utf-8",
        )
    (context.workspace / "test_app.py").write_text(
        "import unittest\nfrom app import result\nclass SecurityTest(unittest.TestCase):\n"
        "    def test_safe(self): self.assertEqual(result(), 'safe')\n"
    )
    commands = [
        CommandSpec(
            name="regression",
            argv=[sys.executable, "-m", "unittest", "test_app"],
            purpose="regression",
        ),
        CommandSpec(
            name="existing suite",
            argv=[sys.executable, "-m", "unittest", "test_existing"],
            purpose="unit",
        ),
        *context.request.checks,
    ]
    digest = await workspace_digest(context.workspace)
    results = [await _fixture_command(context.workspace, command) for command in commands]
    return RepairOutcome(
        status=RepairStatus.COMPLETE,
        summary="Fixed and tested.",
        command_results=results,
        source_digest=digest,
        turns_used=1,
    )


async def _fixture_command(workspace: Path, command: CommandSpec) -> CheckResult:
    """Run this module's synthetic fixture tests, without a production command wrapper."""
    process = await asyncio.create_subprocess_exec(
        command.argv[0],
        "-B",
        *command.argv[1:],
        cwd=workspace,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await process.communicate()
    return CheckResult(
        name=command.name,
        argv=command.argv,
        status=CheckStatus.PASSED if process.returncode == 0 else CheckStatus.FAILED,
        exit_code=process.returncode,
        duration_seconds=0,
        output=output.decode(),
    )


def test_candidate_from_legacy_report_preserves_draft_and_checks() -> None:
    candidate = candidate_from_legacy_report(
        {
            "remediation_steps": "Reject unsafe input.",
            "poc_description": "Call the vulnerable function.",
            "fix_verification": "Reasoned about the patched branch.",
            "code_locations": [
                {
                    "file": "src/app.py",
                    "start_line": 9,
                    "end_line": 9,
                    "snippet": "sink(value)",
                    "fix_before": "sink(value)",
                    "fix_after": "sink(clean(value))",
                }
            ],
        }
    )

    assert candidate is not None
    assert candidate.security_invariant == "Reject unsafe input."
    assert candidate.draft_edits[0].after == "sink(clean(value))"
    assert candidate.reported_checks[0].executed is False
    assert candidate.known_gaps == ["The reporting-agent verification is not independent."]


def test_anchor_location_rewrites_invented_line_numbers(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("first\nsecond\ntarget\nlast\n", encoding="utf-8")
    location = CandidateLocation(
        file="app.py",
        start_line=99,
        end_line=99,
        snippet="target",
    )

    result = anchor_location(tmp_path, location)

    assert result.status is AnchorStatus.UNIQUE
    assert result.location.start_line == 3
    assert result.location.end_line == 3


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("first\nlast\n", AnchorStatus.MISSING),
        ("target\nmiddle\ntarget\n", AnchorStatus.AMBIGUOUS),
    ],
)
def test_anchor_location_rejects_non_unique_source(
    tmp_path: Path,
    content: str,
    expected: AnchorStatus,
) -> None:
    (tmp_path / "app.py").write_text(content, encoding="utf-8")
    edit = FixEdit(
        file="app.py",
        start_line=1,
        end_line=1,
        before="target",
        after="safe",
    )

    assert anchor_location(tmp_path, edit).status is expected


def test_anchor_location_detects_stale_file_digest(tmp_path: Path) -> None:
    original = "target\n"
    (tmp_path / "app.py").write_text("changed\n", encoding="utf-8")
    edit = FixEdit(
        file="app.py",
        start_line=1,
        end_line=1,
        before="target",
        after="safe",
        original_sha256=hashlib.sha256(original.encode()).hexdigest(),
    )

    assert anchor_location(tmp_path, edit).status is AnchorStatus.STALE


@pytest.mark.asyncio
async def test_prepare_fix_rejects_wrong_source_commit(tmp_path: Path) -> None:
    workspace, _commit = _workspace(tmp_path)

    result = await prepare_fix(
        _request(_candidate("0" * 40)),
        workspace,
        repair=_noop_repair,
    )

    assert result.state is PreparationState.STALE
    assert result.stop_reason == "The finding source no longer matches."


@pytest.mark.asyncio
async def test_prepare_fix_rejects_dirty_workspace(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
    (workspace / "stray.txt").write_text("unrelated\n", encoding="utf-8")

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
    )

    assert result.state is PreparationState.STALE


@pytest.mark.asyncio
async def test_build_git_manifest_lists_files_inside_new_directory(tmp_path: Path) -> None:
    workspace, _commit = _workspace(tmp_path)
    package = workspace / "pkg"
    package.mkdir()
    (package / "mod.py").write_text("x = 1\n", encoding="utf-8")

    entries, _summary, _artifact = await build_git_manifest(workspace)

    paths = {entry.path for entry in entries}
    assert "pkg/mod.py" in paths
    entry = next(entry for entry in entries if entry.path == "pkg/mod.py")
    assert entry.operation == "add"
    assert entry.resulting_sha256 is not None


@pytest.mark.asyncio
async def test_manifest_patch_includes_untracked_companion_file(tmp_path: Path) -> None:
    workspace, _ = _workspace(tmp_path)
    (workspace / "companion.py").write_text("guard = True\n")
    manifest, _, _ = await build_git_manifest(workspace)
    patch = await build_git_patch(workspace, manifest)
    assert b"b/companion.py" in patch
    assert b"+guard = True" in patch
    _git(workspace, "diff", "--check")


def test_candidate_keeps_full_finding_without_inventing_reproduction() -> None:
    candidate = candidate_from_legacy_report(
        {
            "title": "Authorization bypass",
            "technical_analysis": "Critical exploit context.",
            "remediation_steps": "Enforce authorization.",
            "code_locations": [
                {
                    "file": "app.py",
                    "start_line": 1,
                    "end_line": 1,
                    "fix_before": "unsafe",
                    "fix_after": "safe",
                }
            ],
        }
    )
    assert candidate and candidate.finding
    assert candidate.finding.description == "Critical exploit context."
    assert candidate.reproduction is None


@pytest.mark.asyncio
async def test_unreviewed_completion_never_exports_a_patch(tmp_path):
    workspace, commit = _workspace(tmp_path)
    export = AsyncMock()
    result = await prepare_fix(
        _request(_candidate(commit)), workspace, repair=_noop_repair, manifest_builder=export
    )
    assert result.state is PreparationState.BLOCKED
    assert "Independent verification is required" in result.stop_reason
    assert not result.final_file_manifest
    assert result.artifact_ref is None
    export.assert_not_awaited()
    assert result.validation_mode == "single_agent"
    assert result.completion.status == RepairStatus.COMPLETE
    assert result.verifier is None
    assert result.checks == result.completion.command_results
    assert "Ran 1 test" in result.checks[0].output


@pytest.mark.asyncio
async def test_cancellation_during_review_never_exports_a_patch(tmp_path):
    workspace, commit = _workspace(tmp_path)
    stopped = False

    async def verify(context, _checks):
        nonlocal stopped
        stopped = True
        return VerifierResult(
            decision=VerificationDecision.VERIFIED,
            summary="Approved.",
            source_digest=await workspace_digest(context.workspace),
        )

    export = AsyncMock()
    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=verify,
        cancelled=lambda: stopped,
        manifest_builder=export,
    )
    assert result.state is PreparationState.FAILED
    assert "cancelled" in result.stop_reason
    export.assert_not_awaited()


@pytest.mark.asyncio
async def test_ready_requires_independent_verifier_approval(tmp_path):
    workspace, commit = _workspace(tmp_path)

    async def verify(context, checks):
        assert checks
        return VerifierResult(
            decision=VerificationDecision.VERIFIED,
            summary="Attack variants are blocked and legitimate behavior is preserved.",
            review_basis="execution",
            source_digest=await workspace_digest(context.workspace),
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=verify,
    )

    assert result.state is PreparationState.READY
    assert result.validation_mode == "agent_review"
    assert result.verifier.decision is VerificationDecision.VERIFIED
    assert result.attempt_history[0].verifier == result.verifier


@pytest.mark.asyncio
async def test_rejected_independent_verification_blocks_delivery(tmp_path):
    workspace, commit = _workspace(tmp_path)

    async def verify(_context, _checks):
        return VerifierResult(
            decision=VerificationDecision.REJECTED,
            summary="A sibling path still exposes arbitrary repository files.",
            gaps=["The security invariant is bypassable."],
            review_basis="code_review",
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=verify,
    )

    assert result.state is PreparationState.BLOCKED
    assert result.verifier.decision is VerificationDecision.REJECTED
    assert not result.final_file_manifest


@pytest.mark.asyncio
async def test_verifier_cannot_mutate_the_deliverable(tmp_path):
    workspace, commit = _workspace(tmp_path)

    async def verify(context, _checks):
        (context.workspace / "app.py").write_text("review mutation\n", encoding="utf-8")
        return VerifierResult(
            decision=VerificationDecision.VERIFIED,
            summary="Approved after changing the patch.",
            review_basis="code_review",
            source_digest=await workspace_digest(context.workspace),
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=verify,
    )

    assert result.state is PreparationState.BLOCKED
    assert "changed during independent verification" in result.stop_reason
    assert not result.final_file_manifest


@pytest.mark.asyncio
@pytest.mark.parametrize("stop", ["blocked", "exception", "cancel"])
async def test_failed_fix_never_exports_partial_work(tmp_path, stop):
    workspace, commit = _workspace(tmp_path)

    async def agent(context, checks):
        outcome = await _noop_repair(context, checks)
        if stop == "exception":
            raise RuntimeError("test interruption")
        return outcome.model_copy(update={"status": RepairStatus.BLOCKED})

    export = AsyncMock()
    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=agent,
        manifest_builder=export,
        cancelled=lambda: stop == "cancel",
    )
    assert result.state is not PreparationState.READY
    assert not result.final_file_manifest
    assert result.artifact_ref is None
    export.assert_not_awaited()


@pytest.mark.asyncio
async def test_completed_agent_cannot_deliver_changed_checkpoint(tmp_path):
    workspace, commit = _workspace(tmp_path)

    async def agent(context, checks):
        outcome = await _noop_repair(context, checks)
        (workspace / "app.py").write_text("changed after completion")
        return outcome

    result = await prepare_fix(_request(_candidate(commit)), workspace, repair=agent)
    assert result.state is PreparationState.BLOCKED
    assert not result.final_file_manifest


def test_new_command_metadata_does_not_change_existing_finding_digest(tmp_path: Path) -> None:
    _root, commit = _workspace(tmp_path)
    candidate = _candidate(commit)
    payload = candidate.model_dump(mode="json")
    payload.pop("finding")
    payload.pop("blocker")
    payload["reproduction"]["command"].pop("purpose")
    previous = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert candidate.digest() == previous


@pytest.mark.asyncio
async def test_completion_limitations_are_preserved_at_top_level(tmp_path):
    workspace, commit = _workspace(tmp_path)

    async def agent(context, checks):
        completion = await _noop_repair(context, checks)
        return completion.model_copy(update={"gaps": ["External integration was not exercised."]})

    async def verify(context, _checks):
        return VerifierResult(
            decision=VerificationDecision.VERIFIED,
            summary="Approved with the recorded limitation.",
            source_digest=await workspace_digest(context.workspace),
        )

    result = await prepare_fix(_request(_candidate(commit)), workspace, repair=agent, verify=verify)
    assert result.state is PreparationState.READY
    assert result.gaps == result.completion.gaps == ["External integration was not exercised."]
