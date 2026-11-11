"""Tests for the scan-time fix controller.

The controller's sandbox commands run for real, against a git repository in a
temporary directory, so the delivered patch is the one git produces. Only the
model is replaced: each scripted agent edits the worktree copy, or does not,
and reports the verdict it was told to report.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from strix.core.agents import AgentCoordinator
from strix.fix import FixController, controller, fix_eligible
from strix.report.state import ReportState, set_global_report_state


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


class _LocalSandbox:
    """Runs sandbox commands on the test machine."""

    async def exec(self, *command: str, **_: Any) -> Any:
        proc = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        code = proc.returncode or 0
        return SimpleNamespace(stdout=stdout, stderr=stderr, exit_code=code, ok=lambda: code == 0)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), *args],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "workspace" / "shop"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "orders.py").write_text("def get(order_id):\n    return load(order_id)\n")
    (repo / ".gitignore").write_text("node_modules/\n")
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "dep.js").write_text("// installed\n")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "base")
    return repo


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReportState]:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(controller, "_FIX_ROOT", str(tmp_path / "fix"))
    state = ReportState(run_name="test-run")
    set_global_report_state(state)
    yield state
    set_global_report_state(None)


def _file_report(state: ReportState, **overrides: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "id": "vuln-0001",
        "title": "IDOR in orders",
        "severity": "high",
        "confidence": "high",
        "timestamp": "2026-11-10T00:00:00+00:00",
        "code_locations": [{"file": "app/orders.py", "start_line": 1, "end_line": 2}],
        **overrides,
    }
    state.vulnerability_reports.append(report)
    return report


def _finish(
    *, success: bool, summary: str = "", open_items: list[str] | None = None
) -> dict[str, Any]:
    return {
        "success": True,
        "agent_completed": True,
        "task_succeeded": success,
        "summary": summary,
        "open_items": open_items or [],
    }


async def _controller(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    repo: Path,
    steps: list[Callable[[Path], dict[str, Any]]],
) -> tuple[FixController, AgentCoordinator, list[dict[str, Any]]]:
    """A controller whose agents play ``steps`` in order; returns the calls they got."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    calls: list[dict[str, Any]] = []
    script = iter(steps)

    async def fake_loop(**kwargs: Any) -> Any:
        tree = Path(controller._FIX_ROOT) / "vuln-0001" / "tree"
        calls.append(
            {
                "name": kwargs["agent"].name,
                "input": kwargs["initial_input"],
                "instructions": kwargs["agent"].instructions,
                "max_turns": kwargs["max_turns"],
                "context": kwargs["context"],
            }
        )
        output = next(script)(tree)
        await coordinator.set_status(kwargs["agent_id"], "completed")
        return SimpleNamespace(final_output=json.dumps(output))

    monkeypatch.setattr(controller, "run_agent_loop", fake_loop)
    fix_controller = FixController(
        sandbox_session=_LocalSandbox(),
        coordinator=coordinator,
        run_config=None,
        agents_db_path=tmp_path / "agents.db",
        sessions_to_close=[],
        root_id="root",
        repo_roots=[str(repo)],
        build_agent=lambda name, instructions: SimpleNamespace(
            name=name, instructions=instructions
        ),
        base_context={"coordinator": coordinator},
    )
    return fix_controller, coordinator, calls


def _write_fix(tree: Path) -> dict[str, Any]:
    (tree / "app" / "orders.py").write_text(
        "from app.authz import owns\n\n"
        "def get(order_id, user):\n    owns(user, order_id)\n    return load(order_id)\n"
    )
    (tree / "app" / "authz.py").write_text("def owns(user, order_id):\n    ...\n")
    (tree / "tests").mkdir(exist_ok=True)
    (tree / "tests" / "test_orders.py").write_text("def test_other_user_is_refused():\n    ...\n")
    (tree / "node_modules" / "left-pad.js").write_text("// installed by the fix agent\n")
    (tree / "tests" / "__pycache__").mkdir()
    (tree / "tests" / "__pycache__" / "test_orders.pyc").write_bytes(b"\x00")
    return _finish(success=True, summary="Added an ownership check.")


def _approve(tree: Path) -> dict[str, Any]:
    # Running the tests leaves caches behind; that is not an edit.
    (tree / ".pytest_cache").mkdir(exist_ok=True)
    (tree / ".pytest_cache" / "lastfailed").write_text("{}")
    return _finish(success=True, summary="Blocks the attack; the test fails on the old code.")


def _reject(_: Path) -> dict[str, Any]:
    return _finish(
        success=False,
        summary="The export route still returns other users' orders.",
        open_items=["GET /orders/export is unguarded"],
    )


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, True),
        ({"confidence": "medium"}, False),
        ({"code_locations": []}, False),
        ({"code_locations": None}, False),
        ({"dependency_metadata": {"package": "lodash"}}, False),
    ],
)
def test_only_confirmed_source_findings_are_eligible(
    overrides: dict[str, Any], expected: bool
) -> None:
    report = {
        "id": "vuln-0001",
        "confidence": "high",
        "code_locations": [{"file": "app/orders.py"}],
        **overrides,
    }
    assert fix_eligible(report) is expected


async def test_approved_fix_delivers_every_changed_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    report = _file_report(state)
    delivered: list[tuple[dict[str, Any], dict[str, Any]]] = []
    state.vulnerability_fix_callback = lambda r, fix: delivered.append((r, fix))
    fix_controller, coordinator, calls = await _controller(
        monkeypatch, tmp_path, repo, [_write_fix, _approve]
    )

    assert fix_controller.schedule(report) is True
    assert fix_controller.schedule(report) is False
    [outcome] = await fix_controller.wait()

    assert outcome.approved
    assert outcome.attempts == 1
    assert [call["name"] for call in calls] == ["Fix agent", "Fix reviewer"]
    assert [call["max_turns"] for call in calls] == [300, 250]
    assert all(call["context"]["fix_agent"] for call in calls)

    # The helper module and the test the agent never described are in the patch;
    # the ignored dependency folder is not.
    fix = report["fix"]
    assert fix["files"] == ["app/authz.py", "app/orders.py", "tests/test_orders.py"]
    assert fix["base_commit"] == _git(repo, "rev-parse", "HEAD").strip()
    assert fix["attempts"] == 1
    assert "patch" not in fix
    patch_file = state.get_run_dir() / fix["patch_file"]
    [(_, delivered_fix)] = delivered
    assert delivered_fix["patch"] == patch_file.read_text()

    # The patch applies to the customer's checkout, which the fix never touched.
    assert _git(repo, "status", "--porcelain") == ""
    _git(repo, "apply", "--index", str(patch_file))
    assert (repo / "app" / "authz.py").exists()
    assert "owns(user, order_id)" in (repo / "app" / "orders.py").read_text()

    assert not (Path(controller._FIX_ROOT) / "vuln-0001").exists()
    assert await coordinator.active_agents_except("root") == []
    [message] = [m for m in await _mailbox(coordinator) if m.get("type") == "fix_result"]
    assert "a reviewed patch is saved" in message["content"]


async def _mailbox(coordinator: AgentCoordinator) -> list[dict[str, Any]]:
    return list(coordinator.runtimes["root"].mailbox)


async def test_rejected_fix_gets_one_more_attempt_with_the_reasons(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    report = _file_report(state)

    def second_fix(tree: Path) -> dict[str, Any]:
        (tree / "app" / "export.py").write_text("def export(user):\n    ...\n")
        return _finish(success=True, summary="Guarded the export route too.")

    fix_controller, _, calls = await _controller(
        monkeypatch, tmp_path, repo, [_write_fix, _reject, second_fix, _approve]
    )
    fix_controller.schedule(report)
    [outcome] = await fix_controller.wait()

    assert outcome.approved
    assert outcome.attempts == 2
    assert "GET /orders/export is unguarded" in calls[2]["input"]
    assert "app/export.py" in report["fix"]["files"]
    assert "app/authz.py" in report["fix"]["files"]


async def test_second_rejection_delivers_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    report = _file_report(state)

    def touch(tree: Path) -> dict[str, Any]:
        (tree / "app" / "more.py").write_text("x = 1\n")
        return _finish(success=True)

    fix_controller, _, calls = await _controller(
        monkeypatch, tmp_path, repo, [_write_fix, _reject, touch, _reject]
    )
    fix_controller.schedule(report)
    [outcome] = await fix_controller.wait()

    assert not outcome.approved
    assert outcome.attempts == 2
    assert len(calls) == 4
    assert "export route" in outcome.reason
    assert "fix" not in report
    assert not (state.get_run_dir() / "fixes").exists()


async def test_fix_that_changes_no_file_is_not_reviewed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    report = _file_report(state)
    fix_controller, _, calls = await _controller(
        monkeypatch, tmp_path, repo, [lambda _: _finish(success=True, summary="Done.")]
    )
    fix_controller.schedule(report)
    [outcome] = await fix_controller.wait()

    assert not outcome.approved
    assert outcome.reason == "The fix agent changed no file."
    assert len(calls) == 1
    assert "fix" not in report


async def test_fix_agent_that_gives_up_is_not_reviewed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    report = _file_report(state)

    def blocked(tree: Path) -> dict[str, Any]:
        (tree / "app" / "orders.py").write_text("half a fix\n")
        return _finish(success=False, summary="The test suite cannot run here.")

    fix_controller, _, calls = await _controller(monkeypatch, tmp_path, repo, [blocked])
    fix_controller.schedule(report)
    [outcome] = await fix_controller.wait()

    assert not outcome.approved
    assert outcome.reason == "The test suite cannot run here."
    assert len(calls) == 1
    assert "fix" not in report


async def test_reviewer_that_edits_the_patch_voids_its_approval(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    report = _file_report(state)

    def edit_and_approve(tree: Path) -> dict[str, Any]:
        (tree / "app" / "authz.py").write_text("def owns(user, order_id):\n    return True\n")
        return _finish(success=True, summary="Looks good.")

    fix_controller, _, _ = await _controller(
        monkeypatch, tmp_path, repo, [_write_fix, edit_and_approve]
    )
    fix_controller.schedule(report)
    [outcome] = await fix_controller.wait()

    assert not outcome.approved
    assert outcome.reason == "The patch changed during review."
    assert "fix" not in report


async def test_reviewer_is_told_where_the_patch_and_the_unpatched_code_are(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    report = _file_report(state)
    seen: dict[str, str] = {}

    def read_patch(tree: Path) -> dict[str, Any]:
        seen["patch"] = (tree.parent / "fix.patch").read_text()
        return _finish(success=True)

    fix_controller, _, calls = await _controller(
        monkeypatch, tmp_path, repo, [_write_fix, read_patch]
    )
    fix_controller.schedule(report)
    await fix_controller.wait()

    review = calls[1]["instructions"]
    assert str(Path(controller._FIX_ROOT) / "vuln-0001" / "fix.patch") in review
    assert str(repo) in review
    assert "Do not edit the repository" in review
    assert "must fail on the unpatched code" in review
    assert "adds a new CI pipeline file" in review
    assert "Do not add a new CI pipeline file" in calls[0]["instructions"]
    assert "Added an ownership check." in calls[1]["input"]
    assert seen["patch"] == (state.get_run_dir() / report["fix"]["patch_file"]).read_text()


async def test_finding_outside_the_scanned_repositories_is_skipped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    report = _file_report(state, code_locations=[{"file": "other/service.py"}])
    fix_controller, _, calls = await _controller(monkeypatch, tmp_path, repo, [])
    fix_controller.schedule(report)
    [outcome] = await fix_controller.wait()

    assert not outcome.approved
    assert calls == []


async def test_finding_deleted_during_the_fix_delivers_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    report = _file_report(state)

    def delete_then_approve(_: Path) -> dict[str, Any]:
        state.vulnerability_reports.clear()
        return _finish(success=True)

    fix_controller, _, _ = await _controller(
        monkeypatch, tmp_path, repo, [_write_fix, delete_then_approve]
    )
    fix_controller.schedule(report)
    [outcome] = await fix_controller.wait()

    assert not outcome.approved
    assert outcome.reason == "The finding no longer exists."


async def test_scan_end_stops_fix_work_and_removes_the_copy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, repo: Path, state: ReportState
) -> None:
    report = _file_report(state)
    started = asyncio.Event()

    async def hang(**_: Any) -> Any:
        started.set()
        await asyncio.Event().wait()

    fix_controller, _, _ = await _controller(monkeypatch, tmp_path, repo, [])
    monkeypatch.setattr(controller, "run_agent_loop", hang)
    fix_controller.schedule(report)
    await started.wait()
    assert fix_controller.pending() == ["vuln-0001"]

    await fix_controller.close()

    assert fix_controller.pending() == []
    assert not (tmp_path / "fix" / "vuln-0001").exists()
    assert "fix" not in report
