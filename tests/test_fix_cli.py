"""Exercise the public OSS entry point with real tools and scripted inference."""

from __future__ import annotations

import importlib
import json
import os
import stat
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest
from agents import RunConfig
from agents.sandbox import SandboxRunConfig

from strix.fix import (
    FixPreparationAttempt,
    FixPreparationRequestV1,
    FixPreparationResultV1,
    PreparationState,
    RepairOutcome,
    RepairStatus,
    VerificationDecision,
    VerifierResult,
)
from strix.fix import runtime as fix_runtime
from strix.interface import fix_cli
from strix.runtime import session_manager
from tests.test_fix_completion import ScriptedModel, finish, patch, shell, suite_commands
from tests.test_fix_reliability import LocalSandbox, existing_suite
from tests.test_fix_runtime import _git, _request, _workspace


def test_cli_role_budget_overrides(tmp_path: Path) -> None:
    request = _request("a" * 40)
    request.max_agent_turns = 500
    path = tmp_path / "request.json"
    path.write_text(request.model_dump_json())
    args = fix_cli._parser().parse_args(
        [
            "--request",
            str(path),
            "--repo",
            str(tmp_path),
            "--max-repair-turns",
            "400",
            "--max-review-turns",
            "250",
        ]
    )
    loaded = fix_cli._load_request(args)
    assert (loaded.repair_turn_limit, loaded.review_turn_limit) == (300, 250)


@pytest.mark.parametrize("allow_network", [False, True])
@pytest.mark.parametrize("input_kind", ["finding", "request"])
def test_cli_network_access_requires_opt_in(
    tmp_path: Path, allow_network: bool, input_kind: str
) -> None:
    request = _request("a" * 40)
    assert request.network_allowed is False
    path = tmp_path / "input.json"
    path.write_text(
        request.model_dump_json()
        if input_kind == "request"
        else json.dumps({"fix_candidate": request.candidate.model_dump(mode="json")})
    )
    argv = [f"--{input_kind}", str(path), "--repo", str(tmp_path)]
    if allow_network:
        argv.append("--allow-network")
    assert (
        fix_cli._load_request(fix_cli._parser().parse_args(argv)).network_allowed is allow_network
    )


def test_cli_preserves_explicit_request_network_policy(tmp_path: Path) -> None:
    request = _request("a" * 40)
    request.network_allowed = True
    path = tmp_path / "request.json"
    path.write_text(request.model_dump_json())
    args = fix_cli._parser().parse_args(["--request", str(path), "--repo", str(tmp_path)])
    assert fix_cli._load_request(args).network_allowed is True


def _local_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    model: ScriptedModel,
    *,
    allow_network: bool = False,
) -> None:
    root = tmp_path / "execution" / "source"
    original_environment = fix_runtime._RuntimeEnvironment

    async def sandbox(_sandbox_id: str, *, network_allowed: bool) -> LocalSandbox:
        assert network_allowed is allow_network
        return LocalSandbox(root.parent)

    async def noop(*_args: Any) -> None:
        pass

    monkeypatch.setattr(fix_cli, "_preflight", noop)
    monkeypatch.setattr(fix_runtime, "_create_command_sandbox", sandbox)
    monkeypatch.setattr(session_manager, "cleanup", noop)
    monkeypatch.setattr(
        fix_runtime,
        "_RuntimeEnvironment",
        lambda **kwargs: original_environment(**kwargs, sandbox_workspace=str(root)),
    )
    monkeypatch.setattr(
        fix_runtime,
        "_run_config",
        lambda env: RunConfig(
            model=model, sandbox=SandboxRunConfig(session=env.session), tracing_disabled=True
        ),
    )


@pytest.mark.parametrize("blocked", [False, True])
@pytest.mark.parametrize("allow_network", [False, True])
def test_cli_runs_shared_workflow_and_preserves_original_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, blocked: bool, allow_network: bool
) -> None:
    workspace, _ = _workspace(tmp_path)
    commit = existing_suite(workspace)
    request = _request(commit)
    finding = {"id": "vuln-1", "fix_candidate": request.candidate.model_dump(mode="json")}
    findings_path = tmp_path / "vulnerabilities.json"
    findings_path.write_text(json.dumps([finding]))
    review = (
        [shell("exit 1"), finish("blocked", "Required tests need a customer database.")]
        if blocked
        else [*suite_commands(), finish("done", "Existing and regression tests passed.")]
    )
    model = ScriptedModel(
        [*patch(), *(review if blocked else [*suite_commands(), finish("done", "tests passed")])],
        review=[] if blocked else review,
    )
    _local_runtime(monkeypatch, tmp_path, model, allow_network=allow_network)
    output = tmp_path / "result.json"

    code = fix_cli.run_fix(
        [
            "--finding",
            str(findings_path),
            "--finding-id",
            "vuln-1",
            "--repo",
            str(workspace),
            "--output",
            str(output),
            *(["--allow-network"] if allow_network else []),
        ]
    )

    assert code == (2 if blocked else 0)
    result = json.loads(output.read_text())
    assert result["state"] == ("blocked" if blocked else "ready")
    assert bool(result["changed_files"]) is not blocked
    assert output.with_suffix(".patch").exists() is not blocked
    assert ("customer database" if blocked else "tests passed") in output.with_suffix(
        ".md"
    ).read_text()
    if not blocked:
        assert (
            "## Review\n\nExisting and regression tests passed."
            in output.with_suffix(".md").read_text()
        )
        with zipfile.ZipFile(output.with_suffix(".zip")) as artifact:
            assert "files/tests/test_security.py" in artifact.namelist()
            assert "tool-results.jsonl" in artifact.namelist()
    assert _git(workspace, "status", "--porcelain") == ""
    assert _git(workspace, "rev-parse", "HEAD") == commit
    assert "unsafe" in (workspace / "app.py").read_text()
    assert not (workspace / "tests/test_security.py").exists()


def test_stale_request_delivers_explanation_without_running_agents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _ = _workspace(tmp_path)
    request = _request("a" * 40)
    request_path = tmp_path / "request.json"
    request_path.write_text(request.model_dump_json())
    model = ScriptedModel([], [])
    _local_runtime(monkeypatch, tmp_path, model)
    output = tmp_path / "result.json"

    assert (
        fix_cli.run_fix(
            [
                "--request",
                str(request_path),
                "--repo",
                str(workspace),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert json.loads(output.read_text())["state"] == "stale"
    assert not model.inputs["repair"]
    assert not output.with_suffix(".patch").exists()


def test_dirty_checkout_is_preserved_and_never_sent_to_agents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, commit = _workspace(tmp_path)
    (workspace / "app.py").write_text("user work in progress")
    request_path = tmp_path / "request.json"
    request_path.write_text(_request(commit).model_dump_json())
    model = ScriptedModel([], [])
    _local_runtime(monkeypatch, tmp_path, model)

    assert (
        fix_cli.run_fix(
            [
                "--request",
                str(request_path),
                "--repo",
                str(workspace),
                "--output",
                str(tmp_path / "result.json"),
            ]
        )
        == 1
    )
    assert (workspace / "app.py").read_text() == "user work in progress"
    assert not model.inputs["repair"]


def test_finding_selection_is_required_before_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "findings.json"
    path.write_text('[{"id": "one"}, {"id": "two"}]')
    monkeypatch.setattr(fix_cli, "_preflight", lambda: pytest.fail("must not start execution"))
    assert fix_cli.run_fix(["--finding", str(path), "--repo", str(tmp_path)]) == 1


def test_fix_help_is_dispatched_without_scan_setup(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    main = importlib.import_module("strix.interface.main")

    monkeypatch.setattr(sys, "argv", ["strix", "fix", "--help"])
    monkeypatch.setattr(main, "parse_arguments", lambda: pytest.fail("scan parser must not run"))
    with pytest.raises(SystemExit, match="0"):
        main.main()
    assert "--finding" in capsys.readouterr().out


def test_legacy_empty_credential_field_is_accepted_but_forwarding_is_rejected() -> None:
    request = _request("a" * 40).model_dump()
    assert "credentials_allowed" not in request
    FixPreparationRequestV1.model_validate({**request, "credentials_allowed": []})
    with pytest.raises(ValueError, match="credentials_allowed"):
        FixPreparationRequestV1.model_validate({**request, "credentials_allowed": ["ANY_HOST_KEY"]})


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_cli_outputs_and_in_progress_archive_are_private_in_shared_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _ = _workspace(tmp_path)
    commit = existing_suite(workspace)
    request_path = tmp_path / "request.json"
    request_path.write_text(_request(commit).model_dump_json())
    shared = tmp_path / "shared-output"
    shared.mkdir()
    shared.chmod(0o777)
    output = shared / "result.json"
    model = ScriptedModel([*patch(), *suite_commands(), finish("done")])
    _local_runtime(monkeypatch, tmp_path, model)
    original_writestr = zipfile.ZipFile.writestr
    writes_checked: list[str] = []

    def private_writestr(archive: Any, name: str, data: Any, *args: Any, **kwargs: Any) -> Any:
        # Check the open archive before source/log bytes enter it, not just after close.
        assert stat.S_IMODE(os.fstat(archive.fp.fileno()).st_mode) == 0o600
        writes_checked.append(name)
        return original_writestr(archive, name, data, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "writestr", private_writestr)
    previous = os.umask(0)
    try:
        assert (
            fix_cli.run_fix(
                [
                    "--request",
                    str(request_path),
                    "--repo",
                    str(workspace),
                    "--output",
                    str(output),
                ]
            )
            == 0
        )
    finally:
        os.umask(previous)
    assert "changes.patch" in writes_checked
    assert "agent-sessions.json" in writes_checked
    assert stat.S_IMODE(shared.stat().st_mode) == 0o777
    assert {p.name for p in shared.iterdir()} == {
        "result.json",
        "result.md",
        "result.patch",
        "result.zip",
    }
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in shared.iterdir())


def test_default_outputs_allow_repeated_runs_from_inside_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _ = _workspace(tmp_path)
    commit = existing_suite(workspace)
    request_path = tmp_path / "request.json"
    request_path.write_text(_request(commit).model_dump_json())
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.chdir(workspace)

    for attempt in range(2):
        model = ScriptedModel([*patch(), *suite_commands(), finish("done")])
        with monkeypatch.context() as runtime_patch:
            _local_runtime(runtime_patch, tmp_path / f"attempt-{attempt}", model)
            assert fix_cli.run_fix(["--request", str(request_path), "--repo", "."]) == 0
        assert _git(workspace, "status", "--porcelain") == ""

    assert len(list((home / ".strix/fixes").glob("fix-*/result.json"))) == 2
    assert not (workspace / "strix_runs").exists()


def test_default_output_cannot_resolve_inside_source_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    with pytest.raises(ValueError, match="set --output outside"):
        fix_cli._default_output(tmp_path)
    assert not (tmp_path / ".strix").exists()


def test_summary_includes_followups_from_repair_and_reviewer() -> None:
    request = _request("a" * 40)
    attempt = FixPreparationAttempt(
        attempt=1,
        repair=RepairOutcome(
            status=RepairStatus.COMPLETE,
            summary="Patched.",
            notes=["re-run the nightly suite"],
        ),
        workspace_digest="b" * 64,
    )
    result = FixPreparationResultV1(
        state=PreparationState.READY,
        stop_reason="Reviewed and approved.",
        source_identity=request.candidate.source_identity,
        candidate=request.candidate,
        candidate_digest=request.candidate.digest(),
        completion=attempt.repair,
        attempt_history=[attempt],
        verifier=VerifierResult(
            decision=VerificationDecision.VERIFIED,
            summary="Approved.",
            notes=["rotate the leaked token"],
        ),
    )
    summary = fix_cli._summary(result)
    assert "## Fix\n\nPatched." in summary
    assert "## Review\n\nApproved." in summary
    assert "re-run the nightly suite" in summary
    assert "rotate the leaked token" in summary


def test_summary_keeps_nested_completion_limitations_for_stored_results():
    candidate = _request("a" * 40).candidate
    result = FixPreparationResultV1(
        state=PreparationState.READY,
        stop_reason="Completed",
        source_identity=candidate.source_identity,
        candidate=candidate,
        candidate_digest=candidate.digest(),
        completion=RepairOutcome(
            status=RepairStatus.COMPLETE,
            summary="Implemented and tested",
            gaps=["External integration was not exercised."],
        ),
    )
    text = fix_cli._summary(result)
    assert "External integration was not exercised." in text
    result.gaps = list(result.completion.gaps)
    assert fix_cli._summary(result).count("External integration was not exercised.") == 1
