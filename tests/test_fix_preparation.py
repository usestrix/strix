"""Tests for fix candidate anchoring and repository preparation."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from strix.fix.contracts import (
    CandidateLocation,
    CheckResult,
    CheckStatus,
    CommandSpec,
    FileManifestEntry,
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
    _network_isolation_prefix,
    build_git_manifest,
    prepare_fix,
    run_command,
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
    _git(workspace, "add", "app.py")
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


def _request(candidate: FixCandidateV1, *, attempts: int = 4) -> FixPreparationRequestV1:
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
    )


async def _noop_repair(
    _context: PreparationContext,
    _checks: list[CheckResult],
) -> RepairOutcome:
    return RepairOutcome(
        status=RepairStatus.COMPLETE,
        summary="The draft is ready for independent evaluation.",
    )


async def _verified(
    _context: PreparationContext,
    _checks: list[CheckResult],
    _reproduction: CheckResult | None,
) -> VerifierResult:
    return VerifierResult(
        decision=VerificationDecision.VERIFIED,
        summary="The invariant is closed.",
        security_invariant_closed=True,
        reproduction_executed=True,
        reproduction_summary="The vulnerable input is rejected.",
        sibling_paths_reviewed=["app.py"],
        preserved_behaviors=["The module compiles."],
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
async def test_prepare_fix_returns_ready_with_manifest(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
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

    result = await prepare_fix(
        _request(_candidate(commit, reproduction=reproduction)),
        workspace,
        repair=_noop_repair,
        verify=_verified,
    )

    assert result.state is PreparationState.READY
    assert result.changed_files == ["app.py"]
    assert result.final_file_manifest[0].operation == "modify"
    assert result.security_reproduction is not None
    assert result.security_reproduction.status is CheckStatus.PASSED
    assert (workspace / "app.py").read_text(encoding="utf-8").endswith("return 'safe'\n")


@pytest.mark.asyncio
async def test_prepare_fix_allows_verified_multi_file_repairs(
    tmp_path: Path,
) -> None:
    workspace, commit = _workspace(tmp_path)

    async def widening_repair(
        _context: PreparationContext,
        _checks: list[CheckResult],
    ) -> RepairOutcome:
        (workspace / "hardening.py").write_text("HELPER = True\n", encoding="utf-8")
        return RepairOutcome(
            status=RepairStatus.COMPLETE,
            summary="Added the companion hardening module.",
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=widening_repair,
        verify=_verified,
    )

    assert result.state is PreparationState.READY
    assert {entry.path for entry in result.final_file_manifest} == {
        "app.py",
        "hardening.py",
    }
    assert result.candidate.digest() == result.candidate_digest


@pytest.mark.asyncio
async def test_prepare_fix_retries_failed_checks(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
    compile_calls = 0

    async def runner(_workspace: Path, command: CommandSpec) -> CheckResult:
        nonlocal compile_calls
        if command.name == "compile":
            compile_calls += 1
        failed = command.name == "compile" and compile_calls == 1
        return CheckResult(
            name=command.name,
            argv=command.argv,
            status=CheckStatus.FAILED if failed else CheckStatus.PASSED,
            exit_code=1 if failed else 0,
            duration_seconds=0,
            required=command.required,
        )

    repair_calls = 0

    async def repair(
        _context: PreparationContext,
        _checks: list[CheckResult],
    ) -> RepairOutcome:
        nonlocal repair_calls
        repair_calls += 1
        if repair_calls == 2:
            (workspace / "app.py").write_text(
                "def result():\n    return 'safe'\n# retry\n",
                encoding="utf-8",
            )
        return RepairOutcome(
            status=RepairStatus.COMPLETE,
            summary="Repair cycle complete.",
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=repair,
        verify=_verified,
        command_runner=runner,
    )

    assert result.state is PreparationState.READY
    assert result.attempts == 2
    assert compile_calls == 2
    assert len(result.attempt_history) == 2


@pytest.mark.asyncio
async def test_prepare_fix_stops_at_repair_limit(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
    repair_calls = 0

    async def repair(
        _context: PreparationContext,
        _checks: list[CheckResult],
    ) -> RepairOutcome:
        nonlocal repair_calls
        repair_calls += 1
        with (workspace / "app.py").open("a", encoding="utf-8") as handle:
            handle.write(f"# attempt {repair_calls}\n")
        return RepairOutcome(
            status=RepairStatus.COMPLETE,
            summary="Repair cycle complete.",
        )

    async def runner(_workspace: Path, command: CommandSpec) -> CheckResult:
        return CheckResult(
            name=command.name,
            argv=command.argv,
            status=CheckStatus.FAILED,
            exit_code=1,
            duration_seconds=0,
            required=command.required,
        )

    result = await prepare_fix(
        _request(_candidate(commit), attempts=4),
        workspace,
        repair=repair,
        verify=_verified,
        command_runner=runner,
    )

    assert result.state is PreparationState.NEEDS_REVIEW
    assert result.attempts == 4
    assert len(result.attempt_history) == 4
    assert "cycle limit" in result.stop_reason


@pytest.mark.asyncio
async def test_prepare_fix_feeds_verifier_rejection_into_next_repair(
    tmp_path: Path,
) -> None:
    workspace, commit = _workspace(tmp_path)
    repair_calls = 0
    verifier_calls = 0

    async def repair(
        context: PreparationContext,
        _checks: list[CheckResult],
    ) -> RepairOutcome:
        nonlocal repair_calls
        repair_calls += 1
        if repair_calls == 2:
            assert context.feedback[0].verifier.gaps == ["Harden the sibling path."]
            (workspace / "sibling.py").write_text("SAFE = True\n", encoding="utf-8")
        return RepairOutcome(
            status=RepairStatus.COMPLETE,
            summary="Repair cycle complete.",
        )

    async def verify(
        _context: PreparationContext,
        _checks: list[CheckResult],
        _reproduction: CheckResult | None,
    ) -> VerifierResult:
        nonlocal verifier_calls
        verifier_calls += 1
        if verifier_calls == 1:
            return VerifierResult(
                decision=VerificationDecision.REJECTED,
                summary="A sibling path remains vulnerable.",
                gaps=["Harden the sibling path."],
            )
        return await _verified(_context, _checks, _reproduction)

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=repair,
        verify=verify,
    )

    assert result.state is PreparationState.READY
    assert result.attempts == 2
    assert result.attempt_history[0].verifier.decision is VerificationDecision.REJECTED
    assert result.attempt_history[1].verifier.decision is VerificationDecision.VERIFIED


@pytest.mark.asyncio
async def test_prepare_fix_stops_after_repeated_repository_state(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)

    async def rejected(
        _context: PreparationContext,
        _checks: list[CheckResult],
        _reproduction: CheckResult | None,
    ) -> VerifierResult:
        return VerifierResult(
            decision=VerificationDecision.REJECTED,
            summary="The fix remains incomplete.",
            gaps=["Change the implementation."],
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=rejected,
    )

    assert result.state is PreparationState.NEEDS_REVIEW
    assert result.attempts == 2
    assert "no repository progress" in result.stop_reason


@pytest.mark.asyncio
async def test_prepare_fix_evaluates_budget_exhausted_patch(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)

    async def exhausted(
        _context: PreparationContext,
        _checks: list[CheckResult],
    ) -> RepairOutcome:
        return RepairOutcome(
            status=RepairStatus.BUDGET_EXHAUSTED,
            summary="The repair agent reached its turn limit.",
            turns_used=40,
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=exhausted,
        verify=_verified,
    )

    assert result.state is PreparationState.READY
    assert result.attempt_history[0].repair.status is RepairStatus.BUDGET_EXHAUSTED
    assert result.attempt_history[0].repair.turns_used == 40


@pytest.mark.asyncio
async def test_prepare_fix_preserves_explicit_blocked_outcome(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)

    async def blocked(
        _context: PreparationContext,
        _checks: list[CheckResult],
    ) -> RepairOutcome:
        return RepairOutcome(
            status=RepairStatus.BLOCKED,
            summary="The repair requires an unavailable generated source file.",
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=blocked,
        verify=_verified,
    )

    assert result.state is PreparationState.BLOCKED
    assert result.stop_reason == "The repair requires an unavailable generated source file."
    assert result.attempts == 1


@pytest.mark.asyncio
async def test_prepare_fix_runs_repair_proposed_reproduction(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
    candidate = _candidate(commit).model_copy(update={"reproduction": None})

    async def repair(
        _context: PreparationContext,
        _checks: list[CheckResult],
    ) -> RepairOutcome:
        return RepairOutcome(
            status=RepairStatus.COMPLETE,
            summary="The patch and reproduction are ready.",
            reproduction_command=CommandSpec(
                name="repair-proposed security reproduction",
                argv=[
                    sys.executable,
                    "-c",
                    "from app import result; assert result() == 'safe'",
                ],
            ),
        )

    result = await prepare_fix(
        _request(candidate),
        workspace,
        repair=repair,
        verify=_verified,
    )

    assert result.state is PreparationState.READY
    assert result.security_reproduction is not None
    assert result.security_reproduction.name == "repair-proposed security reproduction"


@pytest.mark.asyncio
async def test_prepare_fix_requires_independent_verifier_approval(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)

    async def rejected(
        _context: PreparationContext,
        _checks: list[CheckResult],
        _reproduction: CheckResult | None,
    ) -> VerifierResult:
        return VerifierResult(
            decision=VerificationDecision.REJECTED,
            summary="A sibling path remains vulnerable.",
            gaps=["Review the sibling handler."],
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=rejected,
    )

    assert result.state is PreparationState.NEEDS_REVIEW
    assert result.verifier is not None
    assert result.verifier.decision is VerificationDecision.REJECTED


@pytest.mark.asyncio
async def test_prepare_fix_requires_closed_security_invariant(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)

    async def incomplete(
        _context: PreparationContext,
        _checks: list[CheckResult],
        _reproduction: CheckResult | None,
    ) -> VerifierResult:
        return VerifierResult(
            decision=VerificationDecision.VERIFIED,
            summary="The local edit works, but the invariant is not closed.",
            reproduction_executed=True,
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=incomplete,
    )

    assert result.state is PreparationState.NEEDS_REVIEW


@pytest.mark.asyncio
async def test_prepare_fix_requires_a_source_change(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)

    async def empty_manifest(
        _workspace: Path,
    ) -> tuple[list[FileManifestEntry], str, str | None]:
        return [], "No changes.", None

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=_verified,
        manifest_builder=empty_manifest,
    )

    assert result.state is PreparationState.NEEDS_REVIEW
    assert "source change" in result.stop_reason


@pytest.mark.asyncio
async def test_prepare_fix_rejects_wrong_source_commit(tmp_path: Path) -> None:
    workspace, _commit = _workspace(tmp_path)
    candidate = _candidate("0" * 40)

    result = await prepare_fix(
        _request(candidate),
        workspace,
        repair=_noop_repair,
        verify=_verified,
    )

    assert result.state is PreparationState.STALE
    assert "source identity" in result.stop_reason


def test_anchor_location_rejects_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("target\n", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "link.txt").symlink_to(outside)
    location = CandidateLocation(
        file="link.txt",
        start_line=1,
        end_line=1,
        snippet="target",
    )

    assert anchor_location(root, location).status is AnchorStatus.MISSING


def test_anchor_location_treats_unreadable_file_as_missing(tmp_path: Path) -> None:
    (tmp_path / "blob.bin").write_bytes(b"\x89PNG\r\n\x1a\n\x00\xff\xfe")
    location = CandidateLocation(
        file="blob.bin",
        start_line=1,
        end_line=1,
        snippet="blob",
    )

    assert anchor_location(tmp_path, location).status is AnchorStatus.MISSING


@pytest.mark.asyncio
async def test_prepare_fix_rejects_edit_escaping_workspace(tmp_path: Path) -> None:
    workspace, _commit = _workspace(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("target\n", encoding="utf-8")
    (workspace / "link.txt").symlink_to(outside)
    _git(workspace, "add", "link.txt")
    _git(workspace, "commit", "-m", "add link")
    commit = _git(workspace, "rev-parse", "HEAD")
    candidate = FixCandidateV1(
        source_identity=SourceIdentity(kind=SourceIdentityKind.COMMIT, value=commit),
        security_invariant="Replace target.",
        draft_edits=[
            FixEdit(
                file="link.txt",
                start_line=1,
                end_line=1,
                before="target",
                after="safe",
            )
        ],
    )

    result = await prepare_fix(
        _request(candidate),
        workspace,
        repair=_noop_repair,
        verify=_verified,
    )

    assert result.state is PreparationState.NEEDS_REVIEW
    assert outside.read_text(encoding="utf-8") == "target\n"


@pytest.mark.asyncio
async def test_prepare_fix_rejects_dirty_workspace(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
    (workspace / "stray.txt").write_text("unrelated\n", encoding="utf-8")

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=_verified,
    )

    assert result.state is PreparationState.STALE
    assert "source identity" in result.stop_reason


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
async def test_run_command_drops_ambient_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_AMBIENT_TOKEN", "hunter2")
    command = CommandSpec(
        name="env probe",
        argv=[
            sys.executable,
            "-c",
            "import os; print(os.environ.get('STRIX_AMBIENT_TOKEN', '<absent>'))",
        ],
    )

    sealed = await run_command(tmp_path, command, network_allowed=True)
    assert sealed.status is CheckStatus.PASSED
    assert "<absent>" in sealed.output

    granted = await run_command(
        tmp_path,
        command,
        credentials_allowed=["STRIX_AMBIENT_TOKEN"],
        network_allowed=True,
    )
    assert granted.status is CheckStatus.PASSED
    assert "hunter2" in granted.output


@pytest.mark.asyncio
async def test_run_command_blocks_egress_when_network_not_allowed(tmp_path: Path) -> None:
    command = CommandSpec(
        name="egress probe",
        argv=[
            sys.executable,
            "-c",
            (
                "import socket, sys; s = socket.socket(); s.settimeout(3); "
                "sys.exit(0 if s.connect_ex(('1.1.1.1', 53)) == 0 else 1)"
            ),
        ],
    )

    result = await run_command(tmp_path, command)

    if _network_isolation_prefix() is None:
        assert result.status is CheckStatus.UNAVAILABLE
        assert "not run" in result.output
    else:
        assert result.status is CheckStatus.FAILED
