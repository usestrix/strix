from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from strix.config import apply_config_override, loader
from strix.config.settings import DEFAULT_MAX_TURNS
from strix.interface.tui.backend.controller import TuiController


def args() -> argparse.Namespace:
    return argparse.Namespace(
        needs_setup=True,
        targets_info=[],
        instruction=None,
        scan_mode="deep",
        max_budget_usd=None,
        max_turns=DEFAULT_MAX_TURNS,
        scope_mode="auto",
        diff_base=None,
        local_sources=[],
        diff_scope={"active": False},
        user_explicit_instruction=None,
        run_name=None,
    )


@pytest.fixture(autouse=True)
def isolated_config(tmp_path: Path) -> None:
    for key in (
        "STRIX_LLM",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "LLM_API_KEY",
        "LLM_API_BASE",
        "AZURE_API_KEY",
        "AZURE_API_BASE",
        "AZURE_API_VERSION",
    ):
        os.environ.pop(key, None)
    apply_config_override(tmp_path / "config.json")


@pytest.mark.asyncio
async def test_setup_state_is_serializable() -> None:
    controller = TuiController(args())
    await controller.handle("setup.add_target", {"target": "https://example.com"})
    await controller.handle("setup.set_instruction", {"instruction": "focus on auth"})
    snapshot = controller.snapshot()
    assert snapshot["targets"] == ["https://example.com"]
    assert snapshot["instruction"] == "focus on auth"
    assert snapshot["scan_state"] == "setup"
    assert snapshot["scan_mode"] == "deep"
    assert snapshot["max_budget_usd"] is None
    assert snapshot["max_turns"] == 500
    assert snapshot["scope_mode"] == "auto"
    assert snapshot["diff_base"] is None


@pytest.mark.asyncio
async def test_setup_instruction_starts_from_cli_and_can_be_cleared() -> None:
    setup_args = args()
    setup_args.instruction = "  CLI instruction  "
    controller = TuiController(setup_args)

    assert controller.snapshot()["instruction"] == "CLI instruction"

    result = await controller.handle("setup.set_instruction", {"instruction": ""})

    assert result == {"instruction": ""}
    assert controller.snapshot()["instruction"] == ""


@pytest.mark.asyncio
async def test_setup_controls_reject_changes_after_start() -> None:
    controller = TuiController(args())
    controller.setup_mode = False
    controller.scan_started = True

    with pytest.raises(RuntimeError, match="can no longer be changed"):
        await controller.handle("setup.add_target", {"target": "https://example.com"})


@pytest.mark.asyncio
async def test_large_target_list_reports_truncated_snapshot_count() -> None:
    controller = TuiController(args())

    for index in range(20):
        await controller.handle("setup.add_target", {"target": f"https://target-{index}.example"})
    added = await controller.handle("setup.add_target", {"target": "https://last.example"})
    snapshot = controller.snapshot()

    assert added == {"target": "https://last.example", "total": 21}
    assert snapshot["target_count"] == 21
    # The snapshot only carries a bounded prefix of the list.
    assert len(snapshot["targets"]) == 16


def test_state_populates_model_warning_for_non_frontier_model() -> None:
    os.environ["STRIX_LLM"] = "openai/gpt-3.5-turbo"
    loader._cached = None

    warning = TuiController(args()).snapshot()["model_warning"]

    assert "openai/gpt-3.5-turbo" in warning
    assert "not a recommended frontier model" in warning


def test_setup_restores_prepared_cli_targets() -> None:
    setup_args = args()
    setup_args.targets_info = [
        {"type": "web", "details": {}, "original": "https://example.com"},
        {"type": "local_code", "details": {}, "original": "/workspace/source"},
    ]

    controller = TuiController(setup_args)

    assert controller.snapshot()["targets"] == ["https://example.com", "/workspace/source"]


@pytest.mark.asyncio
async def test_start_validates_model_before_callback() -> None:
    started = False

    async def start(_verify: bool = True) -> None:
        nonlocal started
        started = True

    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.add_target", {"target": "https://example.com"})
    with pytest.raises(ValueError, match="No model configured"):
        await controller.handle("setup.start", {})
    assert started is False


@pytest.mark.asyncio
async def test_start_launches_with_a_configured_model() -> None:
    started = False

    async def start(_verify: bool = True) -> None:
        nonlocal started
        started = True

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.add_target", {"target": "https://example.com"})

    result = await controller.handle("setup.start", {})

    assert result == {"started": True}
    assert started is True


@pytest.mark.asyncio
async def test_start_without_target_requires_mount_consent() -> None:
    started = False

    async def start(_verify: bool = True) -> None:
        nonlocal started
        started = True

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)

    # Mounting the working directory is never silent.
    with pytest.raises(ValueError, match="No target set"):
        await controller.handle("setup.start", {"verify": False})
    assert started is False
    assert controller.targets == []
    assert controller.workspace_mount is None


@pytest.mark.asyncio
async def test_target_less_start_enters_live_view_and_waits_for_the_mount() -> None:
    """Nothing is prepared until the live-view confirmation is answered."""
    started = False

    async def start(_verify: bool = True) -> None:
        nonlocal started
        started = True

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)

    result = await controller.handle("setup.start", {"verify": False, "mount_working_dir": True})

    assert result == {"started": True}
    # The live view is up so the prompt can be shown there, but the scan has not
    # been prepared and nothing is mounted yet.
    assert started is False
    assert controller.setup_mode is False
    assert controller.scan_state == "preparing"
    assert controller.pending_workspace_mount == str(Path.cwd())
    assert controller.workspace_mount is None
    assert controller.snapshot()["pending_mount"] == str(Path.cwd())


@pytest.mark.asyncio
async def test_confirming_the_mount_starts_the_scan_without_a_target() -> None:
    started = False
    seen_verify: bool | None = None

    async def start(verify: bool = True) -> None:
        nonlocal started, seen_verify
        started = True
        seen_verify = verify

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.start", {"verify": False, "mount_working_dir": True})

    result = await controller.handle("setup.confirm_mount", {"approved": True})

    assert result == {"approved": True}
    assert started is True
    # Launched optimistically, and mounted as a workspace: the scan genuinely
    # has no target, so the instruction is the only source of truth.
    assert seen_verify is False
    assert controller.workspace_mount == str(Path.cwd())
    assert controller.targets == []
    assert controller.scan_state == "running"
    assert controller.snapshot()["pending_mount"] == ""


@pytest.mark.asyncio
async def test_declining_the_mount_runs_without_one() -> None:
    started: list[bool] = []

    async def start(verify: bool = True) -> None:
        started.append(verify)

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.start", {"verify": False, "mount_working_dir": True})

    result = await controller.handle("setup.confirm_mount", {"approved": False})

    assert result == {"approved": False}
    # Declining skips the directory; it does not abandon the scan.
    assert started == [False]
    assert controller.workspace_mount is None
    assert controller.pending_workspace_mount is None
    assert controller.setup_mode is False
    assert controller.scan_started is True
    assert controller.scan_state == "running"


@pytest.mark.asyncio
async def test_approving_the_mount_runs_with_it() -> None:
    started: list[bool] = []

    async def start(verify: bool = True) -> None:
        started.append(verify)

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.start", {"verify": False, "mount_working_dir": True})

    result = await controller.handle("setup.confirm_mount", {"approved": True})

    assert result == {"approved": True}
    assert started == [False]
    assert controller.workspace_mount == str(Path.cwd())
    assert controller.scan_state == "running"


@pytest.mark.asyncio
async def test_confirm_mount_requires_a_pending_request() -> None:
    controller = TuiController(args())

    with pytest.raises(RuntimeError, match="No mount confirmation is pending"):
        await controller.handle("setup.confirm_mount", {"approved": True})


def test_snapshot_exposes_working_directory() -> None:
    controller = TuiController(args())

    assert controller.snapshot()["working_dir"] == str(Path.cwd())
    assert controller.snapshot()["pending_mount"] == ""


@pytest.mark.asyncio
async def test_start_forwards_verify_flag_by_default() -> None:
    seen_verify: bool | None = None

    async def start(verify: bool = True) -> None:
        nonlocal seen_verify
        seen_verify = verify

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.add_target", {"target": "https://example.com"})

    # A named target keeps the upfront model check.
    await controller.handle("setup.start", {})

    assert seen_verify is True


@pytest.mark.asyncio
async def test_start_rejects_concurrent_and_repeated_submissions() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def start(_verify: bool = True) -> None:
        entered.set()
        await release.wait()

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.add_target", {"target": "https://example.com"})

    first_start = asyncio.create_task(controller.handle("setup.start", {}))
    await entered.wait()
    with pytest.raises(RuntimeError, match="already starting or running"):
        await controller.handle("setup.start", {})
    release.set()
    await first_start
    with pytest.raises(RuntimeError, match="already starting or running"):
        await controller.handle("setup.start", {})


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["completed", "failed", "crashed", "stopped"])
async def test_stop_rejects_terminal_agents(status: str) -> None:
    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def cancel_descendants_graceful(self, agent_id: str) -> list[str]:
            self.calls.append(agent_id)
            return [agent_id]

    coordinator = Coordinator()
    controller = TuiController(args(), coordinator=coordinator)
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("agent-1", name="Agent", status=status)

    with pytest.raises(RuntimeError, match=f"cannot be stopped while {status}"):
        await controller.handle("agent.stop", {"agent_id": "agent-1"})

    assert coordinator.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["running", "waiting", "budget_paused"])
async def test_stop_allows_active_agents(status: str) -> None:
    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def cancel_descendants_graceful(self, agent_id: str) -> list[str]:
            self.calls.append(agent_id)
            return [agent_id]

    coordinator = Coordinator()
    controller = TuiController(args(), coordinator=coordinator)
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("agent-1", name="Agent", status=status)

    result = await controller.handle("agent.stop", {"agent_id": "agent-1"})

    assert result == {"stopped": True}
    assert coordinator.calls == ["agent-1"]


@pytest.mark.asyncio
async def test_stopping_agent_denies_pending_approvals_for_its_subtree() -> None:
    class Coordinator:
        async def cancel_descendants_graceful(self, agent_id: str) -> list[str]:
            return ["agent-child", agent_id]

    controller = TuiController(args(), coordinator=Coordinator())
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("agent-1", name="Agent", status="running")
    approvals = [
        asyncio.create_task(
            controller.safety_approval_callback(
                {
                    "request_id": f"approval-{agent_id}",
                    "agent_id": agent_id,
                    "action": "Run action",
                    "reason": "Ambiguous effect",
                }
            )
        )
        for agent_id in ("agent-1", "agent-child")
    ]
    await asyncio.sleep(0)

    await controller.handle("agent.stop", {"agent_id": "agent-1"})

    assert await asyncio.gather(*approvals) == ["cancelled", "cancelled"]
    assert controller.snapshot()["pending_approvals"] == []


@pytest.mark.asyncio
async def test_stop_handles_coordinator_rejection_after_stale_active_projection() -> None:
    class Coordinator:
        async def cancel_descendants_graceful(self, _agent_id: str) -> list[str]:
            return []

    controller = TuiController(args(), coordinator=Coordinator())
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("agent-1", name="Agent", status="running")

    with pytest.raises(RuntimeError, match="no longer active"):
        await controller.handle("agent.stop", {"agent_id": "agent-1"})


@pytest.mark.asyncio
async def test_unknown_command_is_rejected() -> None:
    controller = TuiController(args())
    with pytest.raises(ValueError, match="Unknown command"):
        await controller.handle("nope", {})


@pytest.mark.asyncio
async def test_safety_approvals_are_all_visible_and_resolve_independently() -> None:
    controller = TuiController(args())
    first = asyncio.create_task(
        controller.safety_approval_callback(
            {
                "request_id": "approval-1",
                "agent_id": "agent-1",
                "action": "Run exploit",
                "reason": "Mutates state",
            }
        )
    )
    second = asyncio.create_task(
        controller.safety_approval_callback(
            SimpleNamespace(
                request_id="approval-2",
                agent_id="agent-2",
                action="Write a file",
                reason="Changes the workspace",
            )
        )
    )
    await asyncio.sleep(0)

    assert controller.snapshot()["pending_approvals"] == [
        {
            "request_id": "approval-1",
            "action": "Run exploit",
            "reason": "Mutates state",
            "agent_id": "agent-1",
            "tool_name": "",
            "digest": "",
            "risk": "",
        },
        {
            "request_id": "approval-2",
            "action": "Write a file",
            "reason": "Changes the workspace",
            "agent_id": "agent-2",
            "tool_name": "",
            "digest": "",
            "risk": "",
        },
    ]
    with pytest.raises(ValueError, match="duplicate safety approval request_id"):
        await controller.safety_approval_callback(
            {
                "request_id": "approval-1",
                "agent_id": "agent-1",
                "action": "Duplicate",
                "reason": "Duplicate",
            }
        )
    assert await controller.handle(
        "safety.resolve", {"request_id": "approval-2", "approved": False}
    ) == {"request_id": "approval-2", "approved": False, "approve_all": False}
    assert await second is False
    assert [item["request_id"] for item in controller.snapshot()["pending_approvals"]] == [
        "approval-1"
    ]

    assert await controller.handle(
        "safety.resolve", {"request_id": "approval-1", "approved": True}
    ) == {"request_id": "approval-1", "approved": True, "approve_all": False}
    assert await first is True
    with pytest.raises(RuntimeError, match="stale or unknown"):
        await controller.handle("safety.resolve", {"request_id": "approval-2", "approved": False})
    assert controller.snapshot()["pending_approvals"] == []


class _RecordingRuntime:
    def __init__(self) -> None:
        self.mode = "guarded"

    def disable(self) -> None:
        self.mode = "off"


@pytest.mark.asyncio
async def test_approve_all_disables_review_and_releases_the_queue() -> None:
    controller = TuiController(args())
    runtime = _RecordingRuntime()
    controller.register_safety_runtime(runtime)
    first = asyncio.create_task(
        controller.safety_approval_callback(
            {"request_id": "a-1", "agent_id": "agent-1", "action": "Run", "reason": "x"}
        )
    )
    second = asyncio.create_task(
        controller.safety_approval_callback(
            {"request_id": "a-2", "agent_id": "agent-2", "action": "Write", "reason": "y"}
        )
    )
    await asyncio.sleep(0)
    assert len(controller.snapshot()["pending_approvals"]) == 2

    result = await controller.handle(
        "safety.resolve", {"request_id": "a-1", "approved": True, "approve_all": True}
    )

    assert result == {"request_id": "a-1", "approved": True, "approve_all": True}
    # The chosen call is approved and every other queued call is released as approved.
    assert await first is True
    assert await second is True
    # Review is switched off for the rest of the run and the queue is cleared.
    assert runtime.mode == "off"
    assert controller.snapshot()["pending_approvals"] == []
    # A review already past the runtime's mode check is auto-approved, not queued.
    later = await controller.safety_approval_callback(
        {"request_id": "a-3", "agent_id": "agent-1", "action": "Later", "reason": "z"}
    )
    assert later is True
    assert controller.snapshot()["pending_approvals"] == []


@pytest.mark.asyncio
async def test_approve_all_is_ignored_when_the_answer_is_deny() -> None:
    controller = TuiController(args())
    runtime = _RecordingRuntime()
    controller.register_safety_runtime(runtime)
    pending = asyncio.create_task(
        controller.safety_approval_callback(
            {"request_id": "a-1", "agent_id": "agent-1", "action": "Run", "reason": "x"}
        )
    )
    await asyncio.sleep(0)

    result = await controller.handle(
        "safety.resolve", {"request_id": "a-1", "approved": False, "approve_all": True}
    )

    assert result == {"request_id": "a-1", "approved": False, "approve_all": False}
    assert await pending is False
    # A denial must never flip the run into dangerous mode.
    assert runtime.mode == "guarded"


@pytest.mark.asyncio
async def test_safety_approval_validates_response_and_sanitizes_display() -> None:
    controller = TuiController(args())
    pending = asyncio.create_task(
        controller.safety_approval_callback(
            {
                "request_id": "approval-safe",
                "agent_id": "agent-safe",
                "action": "run\x1b]52;c;Y2xpcA==\x07 command\x85",
                "reason": "needs\x1b[31m review\x1b[0m\x7f",
            }
        )
    )
    await asyncio.sleep(0)

    assert controller.snapshot()["pending_approvals"] == [
        {
            "request_id": "approval-safe",
            "action": "run command",
            "reason": "needs review",
            "agent_id": "agent-safe",
            "tool_name": "",
            "digest": "",
            "risk": "",
        }
    ]
    with pytest.raises(TypeError, match="approved must be a boolean"):
        await controller.handle(
            "safety.resolve", {"request_id": "approval-safe", "approved": "yes"}
        )
    with pytest.raises(ValueError, match="request_id must be a non-empty string"):
        await controller.handle("safety.resolve", {"request_id": "", "approved": False})

    await controller.handle("safety.resolve", {"request_id": "approval-safe", "approved": False})
    assert await pending is False

    assert (
        await controller.safety_approval_callback(
            {"request_id": "approval-long", "action": "x" * 513, "reason": "Too long"}
        )
        is False
    )
    assert controller.snapshot()["pending_approvals"] == []

    with pytest.raises(ValueError, match="agent_id must be a non-empty string"):
        await controller.safety_approval_callback(
            {"request_id": "approval-ownerless", "action": "Action", "reason": "Reason"}
        )


@pytest.mark.asyncio
async def test_cancelled_safety_request_is_removed_and_reveals_next() -> None:
    controller = TuiController(args())
    first = asyncio.create_task(
        controller.safety_approval_callback(
            {
                "request_id": "approval-1",
                "agent_id": "agent-1",
                "action": "First",
                "reason": "First reason",
            }
        )
    )
    second = asyncio.create_task(
        controller.safety_approval_callback(
            {
                "request_id": "approval-2",
                "agent_id": "agent-2",
                "action": "Second",
                "reason": "Second reason",
            }
        )
    )
    await asyncio.sleep(0)

    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first

    assert controller.snapshot()["pending_approvals"][0]["request_id"] == "approval-2"
    await controller.handle("safety.resolve", {"request_id": "approval-2", "approved": False})
    assert await second is False


@pytest.mark.asyncio
async def test_quit_denies_all_pending_and_future_safety_approvals() -> None:
    controller = TuiController(args())
    requests = [
        asyncio.create_task(
            controller.safety_approval_callback(
                {
                    "request_id": f"approval-{index}",
                    "agent_id": f"agent-{index}",
                    "action": "Action",
                    "reason": "Reason",
                }
            )
        )
        for index in range(2)
    ]
    await asyncio.sleep(0)

    await controller.handle("app.quit", {})

    assert await asyncio.gather(*requests) == ["cancelled", "cancelled"]
    assert controller.snapshot()["pending_approvals"] == []
    assert (
        await controller.safety_approval_callback(
            {
                "request_id": "approval-late",
                "agent_id": "agent-late",
                "action": "Late",
                "reason": "Late reason",
            }
        )
        == "cancelled"
    )


def test_messages_are_sanitized_and_agents_are_collection_only() -> None:
    controller = TuiController(args())
    controller.add_message("replace\x1b]52;c;Y2xpcA==\x07 key\x85")
    for index in range(40):
        controller.live_view.upsert_agent(f"agent-{index}", name=f"Agent {index}")

    snapshot = controller.snapshot()

    assert "agents" not in snapshot
    assert [message["text"] for message in snapshot["messages"]] == ["replace key"]
    assert len(controller.collection("agents")) == 40


@pytest.mark.asyncio
async def test_existing_viewer_is_reopened_and_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[str] = []

    class ViewerServer:
        shutdown_called = False
        close_called = False

        def shutdown(self) -> None:
            self.shutdown_called = True

        def server_close(self) -> None:
            self.close_called = True

    controller = TuiController(args())
    controller.viewer_status = "running"
    controller.viewer_url = "http://127.0.0.1:1234/?token=test"
    server = ViewerServer()
    controller._viewer_httpd = server
    monkeypatch.setattr("strix.interface.tui.backend.controller.webbrowser.open", opened.append)

    result = await controller.handle("viewer.open", {})
    controller.close_viewer()

    assert result == {"status": "running", "url": controller.viewer_url}
    assert opened == [controller.viewer_url]
    assert server.shutdown_called is True
    assert server.close_called is True
