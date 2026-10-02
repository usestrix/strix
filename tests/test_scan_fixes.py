# mypy: allow-untyped-defs, allow-untyped-calls, disable-error-code="method-assign,var-annotated"

"""Persisted findings launch native Fix children in isolated worktrees."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from agents import RunConfig
from agents.sandbox import SandboxRunConfig
from agents.tool_context import ToolContext

from strix.core.agents import AgentCoordinator
from strix.core.execution import spawn_child_agent
from strix.core.hooks import ReportUsageHooks
from strix.fix import (
    FindingContext,
    FixPreparationResultV1,
    PreparationState,
)
from strix.fix import scan as scan_module
from strix.fix.scan import ScanFixes
from strix.fix.session import WorktreeSession
from strix.report.state import ReportState
from tests.test_fix_completion import ScriptedModel, finish, patch, suite_commands
from tests.test_fix_reliability import LocalSandbox, existing_suite
from tests.test_fix_runtime import _git, _request, _workspace


def setup(tmp_path, *, interactive=False):
    source, _ = _workspace(tmp_path)
    commit = existing_suite(source)
    parent = LocalSandbox(tmp_path / "sandbox")
    coordinator = AgentCoordinator()
    candidate = _request(commit).candidate
    candidate.finding = FindingContext(validation_status="confirmed", title="Unsafe result")
    report = {
        "id": "finding",
        "validation_status": "confirmed",
        "fix_candidate": candidate.model_dump(mode="json"),
    }
    reports = [report]
    fixes = ScanFixes(
        session=parent,
        coordinator=coordinator,
        scan_id="scan",
        state_dir=tmp_path / "state",
        local_sources=[{"source_path": str(source)}],
        hooks=ReportUsageHooks(model="test", max_turns=1000),
        report_state=SimpleNamespace(get_existing_vulnerabilities=lambda: reports),
    )
    fixes.base = str(tmp_path / "sandbox" / "fixes")
    sessions = []

    async def native(**kwargs):
        return await spawn_child_agent(
            coordinator=coordinator,
            agents_db_path=tmp_path / "agents.db",
            sessions_to_close=sessions,
            **{"interactive": interactive, **kwargs},
        )

    async def spawn(**kwargs):
        finding_id = kwargs.pop("fix_finding_id")
        return await fixes.spawn(finding_id, native, **kwargs)

    fixes._native_spawn = native

    context = ToolContext(
        tool_name="create_agent",
        tool_call_id="spawn-test",
        tool_arguments="{}",
        context={
            "coordinator": coordinator,
            "agent_id": "reporter",
            "parent_id": "root",
            "spawn_child_agent": spawn,
        },
    )
    return fixes, report, source, parent, reports, context, sessions


async def delegate(context, finding_id="finding", **options):
    try:
        return await context.context["spawn_child_agent"](
            fix_finding_id=finding_id,
            parent_ctx=context.context,
            name="Fix agent",
            task="Fix the saved issue and test it.",
            skills=[],
            parent_history=[],
            **options,
        )
    except ValueError as error:
        return {"success": False, "error": str(error)}


@pytest.mark.asyncio
async def test_native_parallel_fixes_deliver_patches_and_preserve_scan_source(
    tmp_path, monkeypatch
):
    fixes, report, source, parent, reports, context, sessions = setup(tmp_path)
    models, stages = {}, []
    reports.append({**report, "id": "another-finding"})

    def config(env):
        model = models.setdefault(
            env.execution_id,
            ScriptedModel([*patch(), *suite_commands(), finish("done"), finish("done")]),
        )
        return RunConfig(
            model=model, sandbox=SandboxRunConfig(session=env.session), tracing_disabled=True
        )

    async def sink(stage, report, result, artifact):
        stages.append((stage, report["id"], result, artifact))
        return True

    monkeypatch.setattr(scan_module, "_run_config", config)
    fixes.sink = sink
    first, second = await asyncio.gather(delegate(context), delegate(context, "another-finding"))
    assert first["success"] and second["success"], (first, second)
    duplicate = await delegate(context)
    assert duplicate["agent_id"] == first["agent_id"]
    branches, errors = await fixes.wait()
    assert branches == errors == []
    assert _git(source, "branch", "--list", "strix/fix-*") == ""
    assert len(models) == 2
    assert all(record["status"] == "done" for record in fixes.records.values()), fixes.records
    assert all(Path(record["artifact"]).exists() for record in fixes.records.values())
    assert all(
        fixes.coordinator.parent_of[result["agent_id"]] == "reporter" for result in [first, second]
    )
    assert len([s for s in stages if s[0] == "finished" and s[2].state == "ready"]) == 2
    assert _git(source, "status", "--porcelain") == ""
    assert "unsafe" in (source / "app.py").read_text()
    assert parent.state.manifest.root == str(tmp_path / "sandbox")
    assert not list((tmp_path / "sandbox/fixes/worktrees").glob("*/app.py"))
    assert not list((tmp_path / "state/fixes").glob("*/source"))
    for session in sessions:
        session.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("interactive", [False, True])
async def test_ready_fix_creates_local_branch_without_changing_checkout(
    tmp_path, monkeypatch, interactive
):
    fixes, _, source, _, _, context, sessions = setup(tmp_path, interactive=interactive)
    original_head = _git(source, "rev-parse", "HEAD")
    original_branch = _git(source, "branch", "--show-current")
    monkeypatch.setattr(
        scan_module,
        "_run_config",
        lambda env: RunConfig(
            model=ScriptedModel([*patch(), *suite_commands(), finish("done"), finish("done")]),
            sandbox=SandboxRunConfig(session=env.session),
            tracing_disabled=True,
        ),
    )

    assert (await delegate(context))["success"]
    branches, errors = await asyncio.wait_for(fixes.wait(), timeout=20)

    assert not errors
    assert len(branches) == 1
    branch = branches[0]["branch"]
    assert branch.startswith("strix/fix-unsafe-result-finding-")
    assert fixes.records["finding"]["branch"] == branch
    assert _git(source, "branch", "--show-current") == original_branch
    assert _git(source, "rev-parse", "HEAD") == original_head
    assert _git(source, "rev-parse", f"{branch}^") == original_head
    assert _git(source, "status", "--porcelain") == ""
    assert "return 'safe'" in _git(source, "show", f"{branch}:app.py")
    assert "test_safe" in _git(source, "show", f"{branch}:tests/test_security.py")
    repeated, repeated_errors = await fixes.wait()
    assert repeated_errors == []
    assert repeated == branches
    assert _git(source, "show-ref", "--verify", f"refs/heads/{branch}")
    for session in sessions:
        session.close()


@pytest.mark.asyncio
async def test_delegation_errors_reach_reporting_agent_before_any_model_call(tmp_path):
    fixes, report, _, _, _, context, _ = setup(tmp_path)
    missing = await delegate(context, "unknown")
    assert not missing["success"] and "Save the vulnerability" in missing["error"]
    report["validation_status"] = "unconfirmed"
    assert "confirmed" in (await delegate(context))["error"]
    report["validation_status"] = "confirmed"
    fixes.records["finding"] = {"turns": 300}
    assert "300-turn" in (await delegate(context))["error"]
    fixes.records.clear()
    fixes.sink = AsyncMock(side_effect=RuntimeError("Missing callback configuration"))
    with pytest.raises(RuntimeError, match="Missing callback configuration"):
        await delegate(context)
    assert not fixes.tasks


@pytest.mark.asyncio
async def test_blocked_native_child_has_no_patch(tmp_path, monkeypatch):
    fixes, _, _, _, _, context, sessions = setup(tmp_path)
    monkeypatch.setattr(
        scan_module,
        "_run_config",
        lambda env: RunConfig(
            model=ScriptedModel([*patch(), finish("blocked", "Required database is unavailable")]),
            sandbox=SandboxRunConfig(session=env.session),
            tracing_disabled=True,
        ),
    )
    assert (await delegate(context))["success"]
    branches, errors = await fixes.wait()
    assert branches == []
    assert len(errors) == 1
    assert errors[0]["finding_id"] == "finding"
    assert "Required database is unavailable" in errors[0]["error"]
    assert fixes.records["finding"]["status"] == "stopped"
    assert not list((tmp_path / "state/fixes").glob("*/prepared-fix.zip"))
    for session in sessions:
        session.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("withdrawn", [False, True])
async def test_cancelled_verification_is_reported_without_publishing_a_branch(
    tmp_path, monkeypatch, withdrawn
):
    fixes, _, source, _, reports, context, sessions = setup(tmp_path, interactive=True)
    reviewing = asyncio.Event()

    async def verify(*_args):
        reviewing.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(scan_module, "finish_native_fix", verify)
    monkeypatch.setattr(
        scan_module,
        "_run_config",
        lambda env: RunConfig(
            model=ScriptedModel([finish("blocked")]),
            sandbox=SandboxRunConfig(session=env.session),
            tracing_disabled=True,
        ),
    )
    assert (await delegate(context))["success"]
    await asyncio.wait_for(reviewing.wait(), timeout=5)
    if withdrawn:
        reports.clear()
    await fixes.close()
    branches, errors = await fixes.wait()
    assert branches == []
    if withdrawn:
        assert errors == []
    else:
        assert "interrupted" in errors[0]["error"]
    assert fixes.records["finding"]["status"] == "stopped"
    assert _git(source, "branch", "--list", "strix/fix-*") == ""
    assert not list((tmp_path / "state/fixes").glob("*/prepared-fix.zip"))
    for session in sessions:
        session.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["running", "stopped", "failed", "done"])
async def test_wait_omits_withdrawn_records_but_keeps_current_fix_errors(tmp_path, status):
    fixes, _, source, _, _, _, _ = setup(tmp_path)
    digest = fixes._finding("finding")[1].digest()
    fixes.records = {
        "finding": {"digest": digest, "status": "stopped", "reason": "Tests failed"},
        "withdrawn": {
            "digest": digest,
            "status": status,
            "artifact": str(tmp_path / "withdrawn.zip"),
            "reason": "The finding was withdrawn",
        },
    }

    branches, errors = await fixes.wait()

    assert branches == []
    assert errors == [{"finding_id": "finding", "title": "finding", "error": "Tests failed"}]
    assert _git(source, "branch", "--list", "strix/fix-*") == ""


@pytest.mark.asyncio
async def test_dispatch_failure_is_reported_before_an_agent_exists(tmp_path, monkeypatch):
    fixes, _, _, _, _, context, _ = setup(tmp_path)
    fixes._parent_ctx = context.context
    monkeypatch.setattr(fixes, "spawn", AsyncMock(side_effect=RuntimeError("Source unavailable")))
    await fixes._dispatch("finding")
    branches, errors = await fixes.wait()
    assert branches == []
    assert errors[0]["error"] == "Source unavailable"


@pytest.mark.asyncio
async def test_revised_candidate_does_not_publish_stale_ready_artifact(tmp_path, monkeypatch):
    fixes, report, source, _, _, _, _ = setup(tmp_path)
    original_digest = fixes._finding("finding")[1].digest()
    artifact = tmp_path / "state/fixes/stale/prepared-fix.zip"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"unused")
    fixes.records["finding"] = {
        "digest": original_digest,
        "status": "done",
        "artifact": str(artifact),
    }
    report["fix_candidate"]["security_invariant"] = "Revised attack"
    # Check publication of the old artifact without starting the new attempt.
    monkeypatch.setattr(fixes, "_reconcile", AsyncMock())

    branches, errors = await fixes.wait()

    assert branches == []
    assert errors == []
    assert _git(source, "branch", "--list", "strix/fix-*") == ""


@pytest.mark.asyncio
async def test_local_branch_failure_is_persisted_and_returned(tmp_path):
    fixes, _, _, _, _, _, _ = setup(tmp_path)
    digest = fixes._finding("finding")[1].digest()
    artifact = tmp_path / "state/fixes/broken/prepared-fix.zip"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"not a zip")
    fixes.records["finding"] = {
        "digest": digest,
        "status": "done",
        "artifact": str(artifact),
    }

    branches, errors = await fixes.wait()

    assert branches == []
    assert len(errors) == 1
    assert errors[0]["finding_id"] == "finding"
    assert fixes.records["finding"]["branch_error"] == errors[0]["error"]


@pytest.mark.asyncio
async def test_finding_revision_invalidates_active_completion(tmp_path):
    fixes, report, _, _, _, _, _ = setup(tmp_path)
    digest = fixes._finding("finding")[1].digest()
    assert fixes._current("finding", digest)
    report["fix_candidate"]["security_invariant"] = "Revised attack"
    assert not fixes._current("finding", digest)
    fixes.report_state.get_existing_vulnerabilities().clear()
    assert not fixes._current("finding", digest)


@pytest.mark.asyncio
async def test_superseded_fix_agent_is_marked_stopped_before_cancellation(tmp_path):
    fixes, _, _, _, _, _, _ = setup(tmp_path)
    await fixes.coordinator.register("old-fix", "Fix", "reporter", skills=["fix_task"])
    await fixes.coordinator.mark_running("old-fix")
    task = asyncio.create_task(asyncio.Event().wait())
    fixes.records["finding"] = {"agent_id": "old-fix", "status": "running"}
    fixes.tasks["finding"] = task

    await fixes._cancel_active("finding")

    assert fixes.coordinator.statuses["old-fix"] == "stopped"
    assert task.cancelled()


@pytest.mark.parametrize("change", ["revised", "withdrawn", "unconfirmed"])
async def test_finding_changed_before_delivery_discards_reviewed_patch(
    tmp_path, monkeypatch, change
):
    fixes, report, _, _, reports, context, _ = setup(tmp_path)
    callback: Any = None

    async def spawn(**kwargs):
        nonlocal callback
        callback = kwargs["on_complete"]
        fixes.coordinator.runtimes["fix"] = SimpleNamespace(
            task=asyncio.create_task(asyncio.sleep(0))
        )
        return {"success": True, "agent_id": "fix"}

    async def finish_preparation(request, _env, _hooks, _result, _session, artifact):
        artifact.write_bytes(b"reviewed patch")
        if change == "revised":
            report["fix_candidate"]["security_invariant"] = "Revised attack"
        elif change == "withdrawn":
            reports.clear()
        else:
            report["validation_status"] = "unconfirmed"
        return FixPreparationResultV1(
            state=PreparationState.READY,
            stop_reason="Approved.",
            source_identity=request.candidate.source_identity,
            candidate=request.candidate,
            candidate_digest=request.candidate.digest(),
            artifact_ref=str(artifact),
        )

    monkeypatch.setattr(scan_module, "finish_native_fix", finish_preparation)
    monkeypatch.setattr(scan_module, "_run_config", lambda _env: RunConfig(tracing_disabled=True))
    fixes.sink = AsyncMock(return_value=True)
    await fixes.spawn(
        "finding", spawn, parent_ctx=context.context, name="Fix", task="Repair", skills=[]
    )
    with pytest.raises(ValueError, match="changed or was withdrawn"):
        await callback(None, None)
    assert fixes.records["finding"]["status"] == "stopped"
    assert "artifact" not in fixes.records["finding"]
    assert not list((tmp_path / "state/fixes").glob("*/prepared-fix.zip"))
    assert all(call.args[2:] == (None, None) for call in fixes.sink.await_args_list)


@pytest.mark.asyncio
async def test_worktree_process_cleanup_never_terminates_parent_sessions(tmp_path):
    parent = LocalSandbox(tmp_path)
    parent.exec = AsyncMock()
    parent.pty_terminate_all = AsyncMock()
    child = WorktreeSession(parent, str(tmp_path / "fix"), "fix-one")
    await child.pty_terminate_all()
    parent.pty_terminate_all.assert_not_called()
    assert parent.exec.call_args.args[3] == "fix-one"
    with pytest.raises(ValueError, match="another agent"):
        await child.pty_write_stdin(session_id=123, chars="kill")


@pytest.mark.asyncio
async def test_native_child_keeps_cumulative_turn_cap_and_does_not_export_partial_patch(
    tmp_path, monkeypatch
):
    fixes, _, _, _, _, context, sessions = setup(tmp_path)
    fixes.records["finding"] = {"digest": "older-candidate", "turns": 299, "status": "done"}
    model = ScriptedModel([*patch(), finish("done"), finish("done")])
    monkeypatch.setattr(
        scan_module,
        "_run_config",
        lambda env: RunConfig(
            model=model,
            sandbox=SandboxRunConfig(session=env.session),
            tracing_disabled=True,
        ),
    )
    assert (await delegate(context))["success"]
    await fixes.wait()
    assert fixes.records["finding"]["turns"] == 300
    assert fixes.records["finding"]["status"] == "stopped"
    assert not list((tmp_path / "state/fixes").glob("*/prepared-fix.zip"))
    for session in sessions:
        session.close()


@pytest.mark.asyncio
async def test_seven_saved_findings_start_seven_native_children_without_model_handoff(
    tmp_path, monkeypatch
):
    fixes, report, source, _, _, context, sessions = setup(tmp_path)
    state = ReportState("native-handoff")
    state._run_dir = tmp_path / "report"
    fixes.report_state = state
    monkeypatch.setattr(
        scan_module,
        "_run_config",
        lambda env: RunConfig(
            model=ScriptedModel([*patch(), *suite_commands(), finish("done"), finish("done")]),
            sandbox=SandboxRunConfig(session=env.session),
            tracing_disabled=True,
        ),
    )
    stages = []

    async def sink(stage, report, _result, _artifact):
        stages.append((stage, report["id"]))
        return True

    fixes.sink = sink
    fixes.start(fixes._native_spawn, context.context)
    ids = [
        state.add_vulnerability_report(
            title=f"Unsafe result {i}",
            severity="high",
            agent_id="reporter",
            validation_status="confirmed",
            fix_candidate=report["fix_candidate"],
        )
        for i in range(7)
    ]
    # Replayed/no-op notifications must not create extra jobs.
    for saved in state.get_existing_vulnerabilities():
        fixes.notify(saved)
    await fixes.wait()
    assert set(fixes.records) == set(ids)
    assert all(r["status"] == "done" for r in fixes.records.values()), fixes.records
    assert len([s for s in stages if s[0] == "started"]) == 7
    assert _git(source, "status", "--porcelain") == ""
    for session in sessions:
        session.close()


@pytest.mark.asyncio
async def test_worker_thread_persistence_starts_exactly_one_native_child(tmp_path, monkeypatch):
    fixes, report, _, _, _, context, sessions = setup(tmp_path)
    state = ReportState("threaded-handoff")
    state._run_dir = tmp_path / "report"
    fixes.report_state = state
    monkeypatch.setattr(
        scan_module,
        "_run_config",
        lambda env: RunConfig(
            model=ScriptedModel([*patch(), *suite_commands(), finish("done"), finish("done")]),
            sandbox=SandboxRunConfig(session=env.session),
            tracing_disabled=True,
        ),
    )
    stages = []

    async def sink(stage, saved, _result, _artifact):
        stages.append((stage, saved["id"]))
        return True

    fixes.sink = sink
    fixes.start(fixes._native_spawn, context.context)
    finding_id = await asyncio.to_thread(
        state.add_vulnerability_report,
        title="Unsafe threaded result",
        severity="high",
        agent_id="reporter",
        validation_status="confirmed",
        fix_candidate=report["fix_candidate"],
    )
    for saved in state.get_existing_vulnerabilities():
        fixes.notify(saved)
    await fixes.wait()
    assert fixes.records[finding_id]["status"] == "done"
    assert [stage for stage in stages if stage == ("started", finding_id)] == [
        ("started", finding_id)
    ]
    for session in sessions:
        session.close()


@pytest.mark.asyncio
async def test_wait_reconciles_persisted_candidate_after_missed_notification(tmp_path, monkeypatch):
    fixes, report, _, _, _, context, sessions = setup(tmp_path)
    state = ReportState("missed-handoff")
    state._run_dir = tmp_path / "report"
    fixes.report_state = state
    monkeypatch.setattr(
        scan_module,
        "_run_config",
        lambda env: RunConfig(
            model=ScriptedModel([*patch(), *suite_commands(), finish("done"), finish("done")]),
            sandbox=SandboxRunConfig(session=env.session),
            tracing_disabled=True,
        ),
    )
    fixes.start(fixes._native_spawn, context.context)
    state.finding_persisted_callback = None
    finding_id = state.add_vulnerability_report(
        title="Unsafe missed result",
        severity="high",
        agent_id="reporter",
        validation_status="confirmed",
        fix_candidate=report["fix_candidate"],
    )
    assert finding_id not in fixes.records
    await fixes.wait()
    assert fixes.records[finding_id]["status"] == "done"
    for session in sessions:
        session.close()


@pytest.mark.asyncio
async def test_persistence_failure_does_not_launch(tmp_path):
    fixes, report, _, _, _, context, _ = setup(tmp_path)
    state = ReportState("failed-persistence")
    state._run_dir = tmp_path / "report"
    fixes.report_state = state
    fixes.start(fixes._native_spawn, context.context)
    state.vulnerability_found_callback = Mock(side_effect=RuntimeError("Database rejected finding"))
    with pytest.raises(RuntimeError, match="Database rejected"):
        state.add_vulnerability_report(
            title="Unsafe", severity="high", fix_candidate=report["fix_candidate"]
        )
    assert not fixes.dispatches and not fixes.tasks


@pytest.mark.asyncio
async def test_explicit_retry_gets_new_agent_with_remaining_turns(tmp_path, monkeypatch):
    fixes, _, _, _, _, context, sessions = setup(tmp_path)
    monkeypatch.setattr(
        scan_module,
        "_run_config",
        lambda env: RunConfig(
            model=ScriptedModel([finish("blocked")]),
            sandbox=SandboxRunConfig(session=env.session),
            tracing_disabled=True,
        ),
    )
    first = await delegate(context)
    await fixes.tasks["finding"]
    again = await delegate(context)
    assert not again["success"]
    second = await delegate(context, retry=True)
    await fixes.wait()
    assert second["agent_id"] != first["agent_id"]
    assert fixes.records["finding"]["turns"] == 2
    for session in sessions:
        session.close()
