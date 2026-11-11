"""``strix fix``: patch findings of an earlier scan, and one local branch per patch."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any

from strix.core import runner
from strix.core.agents import AgentCoordinator
from strix.fix import FixOutcome, FixRequest
from strix.fix.branches import _host_repository, create_fix_branches
from strix.interface.main import _take_fix_command
from tests.test_fix_controller import (
    _approve,
    _controller,
    _file_report,
    _git,
    _write_fix,
)
from tests.test_fix_controller import repo as repo  # noqa: PLC0414 - shared fixture
from tests.test_fix_controller import state as state  # noqa: PLC0414 - shared fixture
from tests.test_runner_root_prompt import _patch_engine_scaffold


if TYPE_CHECKING:
    from pathlib import Path

    import pytest

    from strix.report.state import ReportState


def test_fix_command_becomes_a_headless_resume(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "strix_runs" / "shop-1a2b").mkdir(parents=True)
    (tmp_path / "strix_runs" / "shop-1a2b" / "run.json").write_text("{}")
    monkeypatch.setattr(
        sys, "argv", ["strix", "fix", "shop-1a2b", "vuln-0002", "--max-budget", "5"]
    )

    assert _take_fix_command() == ["vuln-0002"]
    assert sys.argv == ["strix", "-n", "--resume", "shop-1a2b", "--max-budget", "5"]


def test_fix_command_for_an_unknown_run_is_a_fatal_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["strix", "fix", "never-ran"])

    try:
        _take_fix_command()
    except SystemExit as stop:
        assert stop.code == 1
    else:
        raise AssertionError("an unknown run must stop the command")
    assert "never-ran" in capsys.readouterr().err


async def test_named_finding_is_fixed_without_high_confidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    report = _file_report(state, confidence="medium")
    fix_controller, _, calls = await _controller(
        monkeypatch, tmp_path, repo, [_write_fix, _approve]
    )

    assert fix_controller.schedule(report) is False
    outcomes = await fix_controller.fix_saved(["vuln-0001"])

    assert outcomes["vuln-0001"].approved
    assert report["fix"]["repository"] == str(repo)
    assert len(calls) == 2


async def test_fix_all_skips_findings_that_have_a_patch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    _file_report(state, fix={"patch_file": "fixes/vuln-0001.patch"})
    fix_controller, _, calls = await _controller(monkeypatch, tmp_path, repo, [])

    assert await fix_controller.fix_saved([]) == {}
    assert calls == []


async def test_unknown_finding_is_an_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    _file_report(state)
    fix_controller, _, _ = await _controller(monkeypatch, tmp_path, repo, [])

    try:
        await fix_controller.fix_saved(["vuln-0009"])
    except ValueError as error:
        assert "vuln-0009" in str(error)
    else:
        raise AssertionError("an unknown finding must not be ignored")


async def test_approved_patch_becomes_a_branch_and_the_checkout_is_untouched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    report = _file_report(state)
    fix_controller, _, _ = await _controller(monkeypatch, tmp_path, repo, [_write_fix, _approve])
    fix_controller.schedule(report)
    await fix_controller.wait()
    head = _git(repo, "rev-parse", "HEAD").strip()
    sources: list[dict[str, Any]] = [{"source_path": str(repo), "workspace_subdir": "shop"}]
    report["fix"]["repository"] = "/workspace/shop"

    branches = create_fix_branches([report], run_dir=state.get_run_dir(), local_sources=sources)

    branch = branches["vuln-0001"]
    assert branch == f"strix/fix-vuln-0001-{report['fix']['digest'][:8]}"
    assert report["fix"]["branch"] == branch
    assert _git(repo, "rev-parse", f"{branch}^").strip() == head
    assert _git(repo, "diff", "--name-only", head, branch).split() == report["fix"]["files"]
    assert "owns(user, order_id)" in _git(repo, "show", f"{branch}:app/orders.py")
    assert _git(repo, "log", "-1", "--format=%an <%ae>", branch).strip() == (
        "Strix <fixes@strix.ai>"
    )
    # The user's checkout, index, and current branch are as they were.
    assert _git(repo, "rev-parse", "HEAD").strip() == head
    assert _git(repo, "status", "--porcelain") == ""
    assert not (repo / "app" / "authz.py").exists()
    # A second pass has nothing left to do.
    assert create_fix_branches([report], run_dir=state.get_run_dir(), local_sources=sources) == {}
    # The same patch prepared again reuses the branch.
    commit = _git(repo, "rev-parse", branch)
    del report["fix"]["branch"]
    again = create_fix_branches([report], run_dir=state.get_run_dir(), local_sources=sources)
    assert again == {"vuln-0001": branch}
    assert _git(repo, "rev-parse", branch) == commit


async def test_patch_that_does_not_fit_the_scanned_commit_gets_no_branch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    # The scan read an uncommitted edit, so the patch is against files git never saw.
    (repo / "app" / "orders.py").write_text("def get(order_id):\n    return fetch(order_id)\n")
    report = _file_report(state)
    fix_controller, _, _ = await _controller(monkeypatch, tmp_path, repo, [_write_fix, _approve])
    fix_controller.schedule(report)
    await fix_controller.wait()
    report["fix"]["repository"] = "/workspace/shop"

    branches = create_fix_branches(
        [report],
        run_dir=state.get_run_dir(),
        local_sources=[{"source_path": str(repo), "workspace_subdir": "shop"}],
    )

    assert branches == {}
    assert "branch" not in report["fix"]
    assert (state.get_run_dir() / report["fix"]["patch_file"]).is_file()
    assert _git(repo, "branch", "--list", "strix/*") == ""


def test_patch_is_matched_to_the_scanned_directory() -> None:
    sources = [
        {"source_path": "/home/me/shop", "workspace_subdir": "shop"},
        {"source_path": "/home/me/api", "workspace_subdir": "api"},
    ]

    assert str(_host_repository({"repository": "/workspace/api"}, sources)) == "/home/me/api"
    assert _host_repository({"repository": "/workspace/other"}, sources) is None
    assert _host_repository({}, sources) is None


def test_fixing_a_finished_scan_keeps_its_status_and_final_report(state: ReportState) -> None:
    state.run_record.update({"status": "completed", "end_time": "2026-01-01T00:00:00Z"})
    state.run_record["scan_results"] = {"executive_summary": "done"}

    state.set_scan_config({"targets": []}, reopen=False)
    state.cleanup(status="stopped")

    assert state.run_record["status"] == "completed"
    assert state.run_record["end_time"] == "2026-01-01T00:00:00Z"
    assert state.run_record["scan_results"] == {"executive_summary": "done"}


async def test_fix_run_starts_no_scan_agent_and_keeps_the_scan_finished(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_engine_scaffold(monkeypatch, tmp_path, {"authorized_targets": []})
    finished = AgentCoordinator()
    await finished.register("root", "Root Agent", parent_id=None)
    await finished.set_status("root", "completed")
    (tmp_path / "agents.json").write_text(json.dumps(await finished.snapshot()))
    (tmp_path / "agents.db").touch()

    built: dict[str, Any] = {}

    class _Controller:
        def __init__(self, **kwargs: Any) -> None:
            built.update(kwargs)

        async def fix_saved(self, report_ids: list[str]) -> dict[str, FixOutcome]:
            built["asked"] = report_ids
            return {"vuln-0002": FixOutcome(approved=True, reason="", attempts=1)}

        async def close(self) -> None:
            built["closed"] = True

    async def no_scan_agent(**_: Any) -> None:
        raise AssertionError("strix fix must not run the scan agent")

    monkeypatch.setattr(runner, "FixController", _Controller)
    monkeypatch.setattr(runner, "run_agent_loop", no_scan_agent)
    monkeypatch.setattr(runner, "respawn_subagents", no_scan_agent)
    coordinator = AgentCoordinator()
    request = FixRequest(findings=["vuln-0002"])

    await runner.run_strix_scan(
        # The scan was started with fixes off; the command asks for them anyway.
        scan_config={
            "targets": [{"type": "local_code", "details": {"workspace_subdir": "shop"}}],
            "auto_fix": False,
        },
        scan_id="shop-1a2b",
        image="img",
        coordinator=coordinator,
        fix_request=request,
    )

    assert built["asked"] == ["vuln-0002"]
    assert built["root_id"] == "root"
    assert built["tell_root"] is False
    assert built["closed"] is True
    assert request.outcomes["vuln-0002"].approved
    assert coordinator.statuses["root"] == "completed"


async def test_fix_run_needs_an_earlier_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_engine_scaffold(monkeypatch, tmp_path, {"authorized_targets": []})

    try:
        await runner.run_strix_scan(
            scan_config={"targets": []},
            scan_id="never-ran",
            image="img",
            coordinator=AgentCoordinator(),
            fix_request=FixRequest(),
        )
    except RuntimeError as error:
        assert "never-ran" in str(error)
    else:
        raise AssertionError("a run with no saved scan state cannot be fixed")
