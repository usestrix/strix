"""Action approval judging, independent waits, and tool execution boundaries."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, Mock, patch
from uuid import UUID

import pytest
from agents.sandbox.capabilities.tools.apply_patch_tool import SandboxApplyPatchTool
from agents.sandbox.capabilities.tools.shell_tool import ExecCommandTool, WriteStdinTool
from agents.sandbox.workspace_paths import WorkspacePathPolicy
from agents.tool import FunctionTool, invoke_function_tool
from agents.tool_context import ToolContext
from openai.types.responses import ResponseOutputMessage, ResponseOutputText
from pydantic import ValidationError

from strix.agents import factory
from strix.agents.factory import _wrap_exec_command, _wrap_write_stdin
from strix.config.settings import ActionApprovalSettings, LlmSettings, Settings
from strix.core import action_approvals, inputs, runner
from strix.core.action_approvals import ActionApprovalGuard, LlmJudge
from strix.core.agents import AgentCoordinator
from strix.tools.mcp.agent_tools import call_mcp
from strix.tools.proxy import caido_api
from strix.tools.proxy import tools as proxy_tools
from strix.tools.proxy.tools import repeat_request
from tests.test_runner_root_prompt import _patch_engine_scaffold


if TYPE_CHECKING:
    from pathlib import Path


def _verdict(risky: bool = True) -> tuple[bool, str, str | None]:
    return risky, "deletes_data" if risky else "safe", None


def _ctx(guard: ActionApprovalGuard, agent_id: str = "agent") -> ToolContext[Any]:
    coordinator = AgentCoordinator()
    coordinator.action_approvals = guard
    coordinator.names[agent_id] = "Validation agent"
    coordinator.metadata[agent_id] = {"task": "Check the authorized application"}
    coordinator.statuses[agent_id] = "running"
    return ToolContext(
        context={
            "coordinator": coordinator,
            "agent_id": agent_id,
            "task": "Fallback task",
            "scan_targets": ["example.com"],
        },
        tool_name="exec_command",
        tool_call_id="call-1",
        tool_arguments="{}",
    )


def _settings(**overrides: Any) -> ActionApprovalSettings:
    return ActionApprovalSettings(
        **{
            "enabled": True,
            "mode": "auto",
            **overrides,
        }
    )


async def _pending(guard: ActionApprovalGuard, count: int = 1) -> list[dict[str, Any]]:
    async with asyncio.timeout(2):
        while len(guard.pending()) < count:
            await asyncio.sleep(0)
    return guard.pending()


def _patch_tool(tmp_path: Path, chat_completions: bool) -> Any:
    session = Mock()
    session._workspace_path_policy.return_value = WorkspacePathPolicy(root=tmp_path)
    session.normalize_path.side_effect = lambda path: tmp_path / path
    session.read = AsyncMock(side_effect=lambda path, **_kw: path.open("rb"))
    session.mkdir = AsyncMock(
        side_effect=lambda path, **_kw: path.mkdir(exist_ok=True, parents=True)
    )
    session.write = AsyncMock(side_effect=lambda path, data, **_kw: path.write_bytes(data.read()))
    session.rm = AsyncMock(side_effect=lambda path, **_kw: path.unlink())
    toolset = SimpleNamespace(apply_patch=SandboxApplyPatchTool(session=session))
    factory._configure_filesystem_tools(toolset, chat_completions=chat_completions)
    return toolset.apply_patch


@pytest.mark.asyncio
@pytest.mark.parametrize("chat_completions", [False, True])
@pytest.mark.parametrize("decision", ["safe", "block", "disabled", "approve"])
@pytest.mark.parametrize("operation_json", [False, True])
async def test_real_sdk_patch_approval_boundary(
    tmp_path: Path, chat_completions: bool, decision: str, operation_json: bool
) -> None:
    target = tmp_path / "evidence.txt"
    target.write_text("keep this evidence\n")
    payload = (
        json.dumps({"type": "delete_file", "path": "evidence.txt"})
        if operation_json
        else "*** Begin Patch\n*** Delete File: evidence.txt\n*** End Patch"
    )
    tool = _patch_tool(tmp_path, chat_completions)
    guard = ActionApprovalGuard(
        _settings(
            mode="ask" if decision == "approve" else "auto",
            enabled=decision != "disabled",
        )
    )
    with patch.object(
        LlmJudge, "evaluate", return_value=_verdict(decision in {"block", "approve"})
    ) as judge:
        task = asyncio.create_task(
            tool.on_invoke_tool(
                _ctx(guard), json.dumps({"patch": payload}) if chat_completions else payload
            )
        )
        if decision == "approve":
            request = (await _pending(guard))[0]
            assert request["summary"] == payload
            assert target.read_text() == "keep this evidence\n"
            guard.resolve(request["approval_id"], approved=True)
        result = await task
        if decision == "block":
            assert "Blocked by action approvals" in result
            assert target.read_text() == "keep this evidence\n"
        else:
            assert "Deleted evidence.txt" in result
            assert not target.exists()
        if decision == "disabled":
            judge.assert_not_awaited()
        else:
            assert judge.call_args.args[0]["arguments"] == {
                "input": payload,
            }


@pytest.mark.asyncio
@pytest.mark.parametrize("chat_completions", [False, True])
async def test_real_sdk_large_patch_reaches_judge_and_execution_unchanged(
    tmp_path: Path, chat_completions: bool
) -> None:
    payload = "*** Begin Patch\n*** Add File: large.txt\n+" + "x" * 6000 + "\n*** End Patch"
    tool = _patch_tool(tmp_path, chat_completions)
    guard = ActionApprovalGuard(_settings())
    with patch.object(LlmJudge, "evaluate", return_value=_verdict(risky=False)) as judge:
        result = await tool.on_invoke_tool(
            _ctx(guard), json.dumps({"patch": payload}) if chat_completions else payload
        )
    assert "Created large.txt" in result
    assert (tmp_path / "large.txt").read_text() == "x" * 6000
    assert judge.call_args.args[0]["arguments"] == {
        "input": payload,
    }
    assert action_approvals._summary("apply_patch", judge.call_args.args[0]["arguments"]) == payload


@pytest.mark.asyncio
@pytest.mark.parametrize("chat_completions", [False, True])
@pytest.mark.parametrize("payload", ["", "not a patch"])
async def test_real_sdk_patch_invalid_input_never_writes(
    tmp_path: Path, chat_completions: bool, payload: str
) -> None:
    tool = _patch_tool(tmp_path, chat_completions)
    guard = ActionApprovalGuard(_settings())
    with patch.object(LlmJudge, "evaluate", return_value=_verdict(risky=False)):
        if chat_completions:
            result = await tool.on_invoke_tool(_ctx(guard), json.dumps({"patch": payload}))
            assert "must" in result
        else:
            with pytest.raises(ValueError):
                await tool.on_invoke_tool(_ctx(guard), payload)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.asyncio
async def test_function_patch_approval_wait_preserves_execution_timeout() -> None:
    async def invoke(_ctx: Any, _raw_input: str) -> str:
        await asyncio.sleep(0.05)
        return "not reached"

    tool = FunctionTool(
        name="apply_patch",
        description="test",
        params_json_schema={},
        on_invoke_tool=invoke,
        timeout_seconds=0.01,
    )
    factory._wrap_apply_patch(tool)
    guard = ActionApprovalGuard(_settings(mode="ask"))
    with patch.object(LlmJudge, "evaluate", return_value=_verdict()):
        task = asyncio.create_task(
            invoke_function_tool(
                function_tool=tool, context=_ctx(guard), arguments='{"input":"patch"}'
            )
        )
        request = (await _pending(guard))[0]
        await asyncio.sleep(0.02)
        assert not task.done()
        guard.resolve(request["approval_id"], approved=True)
        assert await task == "Tool 'apply_patch' timed out after 0.01 seconds."


def test_settings_defaults_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = ActionApprovalSettings()
    assert not settings.enabled
    assert settings.mode == "ask"
    assert {
        "exec_command",
        "write_stdin",
        "repeat_request",
        "call_mcp",
        "apply_patch",
    } == action_approvals.ACTION_APPROVAL_TOOLS
    assert settings.timeout_seconds == 300
    assert settings.on_timeout == "block"
    assert settings.model is None
    assert settings.api_key is None
    assert settings.api_base is None
    assert "threshold" not in ActionApprovalSettings.model_fields
    assert "tools" not in ActionApprovalSettings.model_fields
    assert not Settings().action_approvals.enabled
    monkeypatch.setenv("STRIX_ACTION_APPROVALS", "true")
    monkeypatch.setenv("STRIX_ACTION_APPROVAL_MODE", "AUTO")
    monkeypatch.setenv("STRIX_ACTION_APPROVAL_TOOLS", '["exec_command"]')
    monkeypatch.setenv("STRIX_ACTION_APPROVAL_MODEL", "deepseek/deepseek-chat")
    monkeypatch.setenv("ACTION_APPROVAL_API_BASE", "https://judge.test/v1")
    monkeypatch.setenv("ACTION_APPROVAL_API_KEY", "primary-key")
    resolved = ActionApprovalSettings()
    assert resolved.api_key == "primary-key"
    assert resolved.enabled and resolved.mode == "auto"
    assert resolved.model == "deepseek/deepseek-chat"
    assert resolved.api_base == "https://judge.test/v1"
    assert "tools" not in resolved.model_dump()


def test_removed_judge_setting_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_ACTION_APPROVAL_JUDGE", "retired")
    settings = ActionApprovalSettings.model_validate({"STRIX_ACTION_APPROVAL_JUDGE": "retired"})
    assert "judge" not in ActionApprovalSettings.model_fields
    assert settings.model is None
    assert isinstance(ActionApprovalGuard(settings).judge, LlmJudge)


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", sorted(action_approvals.ACTION_APPROVAL_TOOLS))
async def test_legacy_controls_cannot_disable_checks(
    monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    monkeypatch.setenv("STRIX_ACTION_APPROVAL_TOOLS", "not JSON")
    monkeypatch.setenv("STRIX_ACTION_APPROVAL_THRESHOLD", "not a number")
    settings = _settings(tools=[], threshold=1)
    assert "tools" not in settings.model_dump()
    assert "threshold" not in settings.model_dump()
    with patch.object(LlmJudge, "evaluate", return_value=_verdict(risky=True)) as judge:
        guard = ActionApprovalGuard(settings)
        assert await guard.check(_ctx(guard), tool, {}) is not None
        judge.assert_awaited_once()


@pytest.mark.parametrize(
    "overrides",
    [
        {"timeout_seconds": 0},
        {"mode": "other"},
        {"on_timeout": "other"},
    ],
)
def test_settings_reject_invalid_values(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        _settings(**overrides)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides,tool",
    [({"enabled": False}, "exec_command"), ({}, "other_tool")],
)
async def test_disabled_and_unguarded_never_call_judge(
    overrides: dict[str, Any], tool: str
) -> None:
    def evaluate(_state: dict[str, Any]) -> tuple[bool, str, str | None]:
        raise AssertionError("Judge must not be called")

    with patch.object(LlmJudge, "evaluate", side_effect=evaluate):
        guard = ActionApprovalGuard(_settings(**overrides))
        assert await guard.check(_ctx(guard), tool, {}) is None


@pytest.mark.asyncio
async def test_auto_blocks_have_distinct_approval_ids() -> None:
    events: list[dict[str, Any]] = []
    with patch.object(LlmJudge, "evaluate", return_value=_verdict(risky=True)):
        guard = ActionApprovalGuard(_settings(), event_sink=events.append)
        for _ in range(2):
            await guard.check(_ctx(guard), "exec_command", {"cmd": "test command"})
    blocked = [event for event in events if event["type"] == "blocked"]
    checked = [event for event in events if event["type"] == "checked"]
    ids = [str(UUID(event["approval_id"])) for event in blocked]
    assert len(set(ids)) == 2
    assert [event["approval_id"] for event in checked] == ids


@pytest.mark.asyncio
@pytest.mark.parametrize("risky,blocked", [(False, False), (True, True)])
async def test_auto_decision_and_request_payload(risky: bool, blocked: bool) -> None:
    requests = []
    events: list[dict[str, Any]] = []

    def evaluate(state: dict[str, Any]) -> tuple[bool, str, str | None]:
        requests.append(state)
        return _verdict(risky)

    with patch.object(LlmJudge, "evaluate", side_effect=evaluate):
        guard = ActionApprovalGuard(_settings(), event_sink=events.append)
        args = {"cmd": "test command"}
        result = await guard.check(_ctx(guard), "exec_command", args)
        assert (result is not None) is blocked
        if blocked:
            assert result is not None
            assert "this action did not run" in result
        assert requests == [
            {
                "tool": "exec_command",
                "arguments": args,
                "agent_task": "Check the authorized application",
                "authorized_targets": ["example.com"],
            }
        ]
        assert events[0]["decision"] == ("blocked" if blocked else "allowed")
        assert events[0]["risky"] == risky
        assert events[0]["reason"] is None
        assert events[0]["summary"] == "test command"
        assert events[0]["agent_name"] == "Validation agent"


@pytest.mark.asyncio
@pytest.mark.parametrize("approved", [True, False])
async def test_ask_human_resolution(approved: bool) -> None:
    events: list[dict[str, Any]] = []
    with patch.object(LlmJudge, "evaluate", return_value=_verdict()):
        guard = ActionApprovalGuard(_settings(mode="ask"), event_sink=events.append)
        task = asyncio.create_task(guard.check(_ctx(guard), "exec_command", {"cmd": "test"}))
        request = (await _pending(guard))[0]
        approval_id = request["approval_id"]
        assert request["expires_at"].endswith("+00:00")
        assert not guard.resolve("unknown", approved=True)
        assert guard.resolve(approval_id, approved, "reviewer")
        assert not guard.resolve(approval_id, approved, "reviewer")
        result = await task
        assert (result is None) is approved
        if not approved:
            assert result is not None
            assert "denied by a person" in result
        assert not guard.pending()
        assert [event["type"] for event in events] == ["requested", "resolved", "checked"]
        assert events[1]["decision"] == ("approved" if approved else "denied")
        assert events[1]["decided_by"] == "reviewer"


@pytest.mark.asyncio
@pytest.mark.parametrize("policy", ["block", "allow"])
async def test_ask_timeout(policy: str) -> None:
    events: list[dict[str, Any]] = []
    with patch.object(LlmJudge, "evaluate", return_value=_verdict()):
        guard = ActionApprovalGuard(
            _settings(mode="ask", timeout_seconds=0.01, on_timeout=policy),
            event_sink=events.append,
        )
        result = await guard.check(_ctx(guard), "exec_command", {"cmd": "test"})
        assert (result is None) is (policy == "allow")
        if policy == "block":
            assert result is not None
            assert "no answer within" in result
        assert not guard.pending()
        assert events[1]["decision"] == "timed_out"
        assert events[2]["decision"] == ("allowed" if policy == "allow" else "blocked")
        assert not guard.resolve(events[0]["approval_id"], approved=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("malformed", [False, True])
async def test_judge_failure_retries_then_succeeds(
    malformed: bool, caplog: pytest.LogCaptureFixture
) -> None:
    calls = 0

    def evaluate(_state: dict[str, Any]) -> tuple[bool, str, str | None]:
        nonlocal calls
        calls += 1
        if calls == 1:
            if malformed:
                raise ValueError("Invalid approval judge response")
            raise RuntimeError("Model unavailable")
        return _verdict(risky=False)

    with patch.object(LlmJudge, "evaluate", side_effect=evaluate):
        guard = ActionApprovalGuard(_settings())
        assert await guard.check(_ctx(guard), "exec_command", {}) is None
        assert calls == 2
        assert "Action approval judge failed" in caplog.text


@pytest.mark.asyncio
async def test_concurrent_agents_have_independent_judge_calls_and_approvals() -> None:
    calls = []

    async def evaluate(state: dict[str, Any]) -> tuple[bool, str, str | None]:
        cmd = state["arguments"].get("cmd")
        calls.append(cmd)
        return _verdict(cmd != "safe")

    with patch.object(LlmJudge, "evaluate", side_effect=evaluate):
        guard = ActionApprovalGuard(_settings(mode="ask"))
        first = asyncio.create_task(guard.check(_ctx(guard, "a"), "exec_command", {"cmd": "a"}))
        await _pending(guard)
        assert await guard.check(_ctx(guard, "b"), "exec_command", {"cmd": "safe"}) is None
        assert not first.done()
        second = asyncio.create_task(guard.check(_ctx(guard, "b"), "exec_command", {"cmd": "b"}))
        pending = await _pending(guard, 2)
        for item in reversed(pending):
            assert guard.resolve(item["approval_id"], approved=True)
        assert list(await asyncio.gather(first, second)) == [None, None]
        assert calls == ["a", "safe", "b"]


@pytest.mark.asyncio
@pytest.mark.parametrize("stop_scan", [True, False])
async def test_coordinator_stop_blocks_pending(stop_scan: bool) -> None:
    with patch.object(LlmJudge, "evaluate", return_value=_verdict()):
        guard = ActionApprovalGuard(_settings(mode="ask"))
        ctx = _ctx(guard)
        task = asyncio.create_task(guard.check(ctx, "exec_command", {}))
        await _pending(guard)
        coordinator = ctx.context["coordinator"]
        if stop_scan:
            coordinator.mark_shutting_down()
        else:
            await coordinator.request_stop("agent")
        result = await task
        assert result is not None
        assert "stopped" in result
        assert not guard.pending()


@pytest.mark.asyncio
async def test_retry_is_cancellable_on_stop() -> None:
    called = asyncio.Event()

    def evaluate(_state: dict[str, Any]) -> tuple[bool, str, str | None]:
        called.set()
        raise RuntimeError("Model unavailable")

    with patch.object(LlmJudge, "evaluate", side_effect=evaluate):
        guard = ActionApprovalGuard(_settings())
        task = asyncio.create_task(guard.check(_ctx(guard), "exec_command", {}))
        await called.wait()
        guard.block_pending()
        result = await asyncio.wait_for(task, 1)
        assert result is not None
        assert "stopped" in result


@pytest.mark.asyncio
async def test_cancelled_check_leaves_no_pending_approval() -> None:
    with patch.object(LlmJudge, "evaluate", return_value=_verdict()):
        guard = ActionApprovalGuard(_settings(mode="ask"))
        task = asyncio.create_task(guard.check(_ctx(guard), "exec_command", {}))
        await _pending(guard)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not guard.pending()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name,chars,expected_calls",
    [
        ("exec_command", "", 0),
        ("write_stdin", "input", 0),
        ("write_stdin", "", 1),
    ],
)
async def test_shell_wrappers_do_not_execute_blocked_actions(
    name: str, chars: str, expected_calls: int
) -> None:
    calls = []

    async def invoke(_ctx: Any, raw_input: str) -> str:
        calls.append(json.loads(raw_input))
        return "output"

    tool = FunctionTool(name=name, description="test", params_json_schema={}, on_invoke_tool=invoke)
    wrapped = _wrap_exec_command(tool) if name == "exec_command" else _wrap_write_stdin(tool)
    with patch.object(LlmJudge, "evaluate", return_value=_verdict()):
        guard = ActionApprovalGuard(_settings())
        result = await wrapped.on_invoke_tool(
            _ctx(guard), json.dumps({"cmd": "test", "chars": chars})
        )
        assert len(calls) == expected_calls
        assert result == "output" if expected_calls else "Blocked by action approvals" in result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool,args",
    [
        (call_mcp, {"connection": "test", "tool": "change", "arguments": '{"value": 1}'}),
    ],
)
async def test_dispatch_guard_runs_before_connections_or_locks(
    tool: FunctionTool, args: dict[str, Any]
) -> None:
    requests = []

    def evaluate(state: dict[str, Any]) -> tuple[bool, str, str | None]:
        requests.append(state)
        return _verdict()

    with patch.object(LlmJudge, "evaluate", side_effect=evaluate):
        guard = ActionApprovalGuard(_settings())
        result = await tool.on_invoke_tool(_ctx(guard), json.dumps(args))
        assert "Blocked by action approvals" in result
        judged = requests[0]["arguments"]
        assert judged == {"connection": "test", "tool": "change", "arguments": {"value": 1}}


def _replay_context(
    monkeypatch: pytest.MonkeyPatch, guard: ActionApprovalGuard
) -> tuple[ToolContext[Any], list[bytes]]:
    sent: list[bytes] = []

    async def fetch(_client: Any, _request_id: str, *, part: str) -> Any:
        assert part == "request"
        assert proxy_tools._CAIDO_CALL_LOCK.locked()
        return SimpleNamespace(
            request=SimpleNamespace(
                raw=(
                    b"DELETE /users/123 HTTP/1.1\r\nHost: example.com\r\n"
                    b"Authorization: Bearer fixture-value\r\nCookie: session=fixture-cookie\r\n\r\n"
                ),
                host="example.com",
                is_tls=True,
            )
        )

    async def send(_client: Any, *, raw: bytes, connection: Any) -> dict[str, Any]:
        assert connection.host == "example.com"
        assert proxy_tools._CAIDO_CALL_LOCK.locked()
        sent.append(raw)
        return {"status": "DONE", "session_id": "replay", "elapsed_ms": 1}

    monkeypatch.setattr(caido_api, "get_request_with_client", fetch)
    monkeypatch.setattr(caido_api, "replay_send_raw", send)
    ctx = _ctx(guard)
    ctx.context["caido_client"] = object()
    return ctx, sent


@pytest.mark.asyncio
@pytest.mark.parametrize("body_length", [0, 4000, 4001])
async def test_replay_judges_effective_delete_without_header_values(
    monkeypatch: pytest.MonkeyPatch, body_length: int
) -> None:
    requests: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []

    def evaluate(state: dict[str, Any]) -> tuple[bool, str, str | None]:
        assert not proxy_tools._CAIDO_CALL_LOCK.locked()
        requests.append(state)
        return _verdict()

    with patch.object(LlmJudge, "evaluate", side_effect=evaluate):
        guard = ActionApprovalGuard(_settings(), event_sink=events.append)
        ctx, sent = _replay_context(monkeypatch, guard)
        args: dict[str, Any] = {"request_id": "123"}
        if body_length:
            args["modifications"] = {
                "params": {"force": "true"},
                "headers": {"X-Test": "private-value"},
                "body": "x" * body_length,
            }
        result = await repeat_request.on_invoke_tool(ctx, json.dumps(args))
        assert "Blocked by action approvals" in result
        assert not sent
        judged = requests[0]["arguments"]
        assert judged["method"] == "DELETE"
        url = "https://example.com/users/123" + ("?force=true" if body_length else "")
        assert judged["url"] == url
        assert {"Host", "Authorization", "Cookie", "User-Agent"} <= set(judged["header_names"])
        if body_length:
            assert {"X-Test", "Content-Length"} <= set(judged["header_names"])
        assert judged["body"] == "x" * min(body_length, 4000)
        assert judged["body_truncated"] is (body_length > 4000)
        serialized = json.dumps(requests[0])
        for private_value in ("fixture-value", "fixture-cookie", "private-value"):
            assert private_value not in serialized
        assert events[0]["summary"] == f"DELETE {url}"


@pytest.mark.asyncio
async def test_replay_approval_releases_lock_and_excludes_wait_from_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        proxy_tools,
        "asyncio",
        SimpleNamespace(
            timeout=lambda _seconds: asyncio.timeout(0.02),
            get_running_loop=asyncio.get_running_loop,
        ),
    )
    with patch.object(LlmJudge, "evaluate", return_value=_verdict()):
        guard = ActionApprovalGuard(_settings(mode="ask"))
        ctx, sent = _replay_context(monkeypatch, guard)
        task = asyncio.create_task(
            invoke_function_tool(
                function_tool=repeat_request,
                context=ctx,
                arguments='{"request_id": "123"}',
            )
        )
        request = (await _pending(guard))[0]
        await asyncio.sleep(0.04)
        assert not task.done()
        assert not proxy_tools._CAIDO_CALL_LOCK.locked()
        other = await asyncio.wait_for(
            proxy_tools.view_request.on_invoke_tool(
                ctx,
                '{"request_id": "456"}',
            ),
            timeout=1,
        )
        assert json.loads(other)["content"].startswith("DELETE /users/123")
        assert not sent
        assert guard.resolve(request["approval_id"], approved=True)
        assert json.loads(await task)["success"]
        assert len(sent) == 1
        assert sent[0].startswith(b"DELETE /users/123 HTTP/1.1")
        assert b"Authorization: Bearer fixture-value" in sent[0]
        assert b"Cookie: session=fixture-cookie" in sent[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["missing", "error", "timeout"])
async def test_replay_preparation_failure_does_not_judge_or_send(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    def evaluate(_state: dict[str, Any]) -> tuple[bool, str, str | None]:
        raise AssertionError("Judge must not run without a prepared request")

    with patch.object(LlmJudge, "evaluate", side_effect=evaluate):
        guard = ActionApprovalGuard(_settings())
        ctx, sent = _replay_context(monkeypatch, guard)

        async def fetch(_client: Any, _request_id: str, *, part: str) -> None:
            assert part == "request"
            if failure == "error":
                raise ValueError("Cannot fetch request")
            if failure == "timeout":
                raise TimeoutError

        monkeypatch.setattr(caido_api, "get_request_with_client", fetch)
        result = await repeat_request.on_invoke_tool(ctx, '{"request_id": "123"}')
        assert not sent
        if failure == "timeout":
            assert result == "Tool 'repeat_request' timed out after 120 seconds."
        else:
            assert not json.loads(result)["success"]


@pytest.mark.asyncio
async def test_approval_wait_does_not_consume_execution_timeout() -> None:
    async def invoke(_ctx: Any, _raw_input: str) -> str:
        await asyncio.sleep(0.05)
        return "not reached"

    tool = _wrap_exec_command(
        FunctionTool(
            name="exec_command",
            description="test",
            params_json_schema={},
            on_invoke_tool=invoke,
            timeout_seconds=0.01,
        )
    )
    with patch.object(LlmJudge, "evaluate", return_value=_verdict()):
        guard = ActionApprovalGuard(_settings(mode="ask"))
        task = asyncio.create_task(
            invoke_function_tool(
                function_tool=tool,
                context=_ctx(guard),
                arguments='{"cmd": "test"}',
            )
        )
        request = (await _pending(guard))[0]
        await asyncio.sleep(0.02)
        assert not task.done()
        guard.resolve(request["approval_id"], approved=True)
        assert await task == "Tool 'exec_command' timed out after 0.01 seconds."


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", ["exec_command", "write_stdin"])
@pytest.mark.parametrize("decision", ["safe", "approve", "block"])
async def test_real_sdk_shell_tools_keep_execution_timeouts_after_approval(
    monkeypatch: pytest.MonkeyPatch, tool_name: str, decision: str
) -> None:
    async def execute(_args: Any) -> str:
        await asyncio.sleep(0.05)
        return "not reached"

    session = Mock()
    tool: FunctionTool
    if tool_name == "exec_command":
        tool = ExecCommandTool(session=session)
        wrap = _wrap_exec_command
        arguments = '{"cmd": "printf safe"}'
    else:
        tool = WriteStdinTool(session=session)
        wrap = _wrap_write_stdin
        arguments = '{"session_id": 1, "chars": "printf safe\\n"}'
    run = AsyncMock(side_effect=execute)
    monkeypatch.setattr(tool, "run", run)
    tool.timeout_seconds = 0.01
    wrapped = wrap(tool)
    assert wrapped.timeout_seconds is None
    risky = decision != "safe"
    with patch.object(LlmJudge, "evaluate", return_value=_verdict(risky)):
        guard = ActionApprovalGuard(_settings(mode="ask" if decision == "approve" else "auto"))
        task = asyncio.create_task(
            invoke_function_tool(function_tool=wrapped, context=_ctx(guard), arguments=arguments)
        )
        if decision == "approve":
            request = (await _pending(guard))[0]
            await asyncio.sleep(0.02)
            assert not task.done()
            run.assert_not_awaited()
            guard.resolve(request["approval_id"], approved=True)
        result = await task
        if decision == "block":
            assert "Blocked by action approvals" in result
            run.assert_not_awaited()
        else:
            assert result == f"Tool '{tool_name}' timed out after 0.01 seconds."
            run.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [False, True])
async def test_runner_attaches_scan_override_and_sink_then_closes_guard(
    enabled: bool, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _patch_engine_scaffold(monkeypatch, tmp_path, {})
    coordinator = AgentCoordinator()
    override = _settings(enabled=enabled)
    events: list[dict[str, Any]] = []
    sink = events.append
    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-approvals",
        image="test",
        coordinator=coordinator,
        action_approvals=override,
        approval_event_sink=sink,
    )
    guard = coordinator.action_approvals
    assert guard is not None
    assert guard.settings is override
    assert guard.event_sink is sink
    assert not guard.pending()
    assert not events


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "enabled,mode,interactive,warning",
    [
        (True, "ask", False, True),
        (True, "ask", True, False),
        (False, "ask", False, False),
        (True, "auto", False, False),
    ],
)
async def test_headless_ask_warning_once(
    enabled: bool,
    mode: str,
    interactive: bool,
    warning: bool,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _patch_engine_scaffold(monkeypatch, tmp_path, {})
    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-warning",
        image="test",
        interactive=interactive,
        action_approvals=_settings(enabled=enabled, mode=mode),
    )
    messages = [
        r.message
        for r in caplog.records
        if "approvals will be decided by the timeout policy" in r.message
    ]
    assert len(messages) == (1 if warning else 0)


def _fake_llm(monkeypatch: pytest.MonkeyPatch, *outputs: str) -> tuple[Mock, AsyncMock]:
    responses = [
        SimpleNamespace(
            output=[
                ResponseOutputMessage(
                    id="judge-message",
                    type="message",
                    role="assistant",
                    status="completed",
                    content=[ResponseOutputText(type="output_text", text=text, annotations=[])],
                )
            ]
        )
        for text in outputs
    ]
    get_response = AsyncMock(side_effect=responses)
    provider = Mock()
    provider.return_value.get_model.return_value.get_response = get_response
    monkeypatch.setattr(action_approvals, "StrixProvider", provider)
    monkeypatch.setattr(action_approvals, "configure_sdk_model_defaults", Mock())
    monkeypatch.setattr(
        action_approvals,
        "load_settings",
        lambda: Settings(
            llm=LlmSettings.model_validate(
                {
                    "model": "openai/gpt-5",
                    "api_key": "main-test-key",
                    "extra_headers": {"X-Main": "private"},
                    "extra_body": {"metadata": {"main": True}},
                }
            )
        ),
    )
    return provider, get_response


@pytest.mark.asyncio
@pytest.mark.parametrize("approval_model", [None, "", "  "])
@pytest.mark.parametrize("mode,risky", [("auto", False), ("auto", True), ("ask", True)])
async def test_llm_judge_and_reason_events(
    monkeypatch: pytest.MonkeyPatch, mode: str, risky: bool, approval_model: str | None
) -> None:
    reason = "This deletes the users table in the target database."
    provider, model = _fake_llm(
        monkeypatch,
        json.dumps(
            {"risky": risky, "category": "deletes_data" if risky else "safe", "reason": reason}
        ),
    )
    events: list[dict[str, Any]] = []
    guard = ActionApprovalGuard(
        _settings(mode=mode, model=approval_model), event_sink=events.append
    )
    task = asyncio.create_task(guard.check(_ctx(guard), "exec_command", {"cmd": "test command"}))
    if mode == "ask":
        pending = await _pending(guard)
        assert pending[0]["reason"] == reason
        assert guard.resolve(pending[0]["approval_id"], approved=False)
    result = await task
    if risky:
        assert result is not None and reason in result
    else:
        assert result is None
    assert all(event["reason"] == reason for event in events)
    provider.assert_called_once_with()
    provider.return_value.get_model.assert_called_once_with("openai/gpt-5")
    request = model.call_args.kwargs
    assert request["tools"] == [] and request["handoffs"] == []
    assert request["output_schema"] is None
    assert request["system_instructions"] == action_approvals.LLM_SYSTEM_PROMPT
    assert request["model_settings"].extra_headers == {"X-Main": "private"}
    assert request["model_settings"].extra_body["metadata"] == {"main": True}
    assert json.loads(request["input"])["authorized_targets"] == ["example.com"]


@pytest.mark.asyncio
@pytest.mark.parametrize("model_name", ["openai/gpt-5", "deepseek/deepseek-chat", "ollama/qwen3"])
async def test_llm_dedicated_provider_configuration(
    monkeypatch: pytest.MonkeyPatch, model_name: str
) -> None:
    provider, model = _fake_llm(
        monkeypatch, '{"risky":false,"category":"safe","reason":"This only reads public data."}'
    )
    judge = LlmJudge(
        _settings(model=model_name, api_key="judge-key", api_base="https://judge.test/v1")
    )
    assert await judge.evaluate({}) == (0.0, "safe", "This only reads public data.")
    provider.assert_called_once_with(api_key="judge-key", base_url="https://judge.test/v1")
    provider.return_value.get_model.assert_called_once_with(model_name)
    request = model.call_args.kwargs
    assert request["model_settings"].extra_headers != {"X-Main": "private"}
    assert not request["model_settings"].extra_body
    assert "api_key" not in request["model_settings"].extra_args


@pytest.mark.asyncio
async def test_llm_optional_provider_override(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, _ = _fake_llm(
        monkeypatch, '{"risky":false,"category":"safe","reason":"This only reads public data."}'
    )
    await LlmJudge(_settings(model="deepseek/deepseek-chat", api_key="test-key")).evaluate({})
    provider.assert_called_once_with(api_key="test-key", base_url=None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides,expected",
    [
        ({"api_key": "judge-key"}, {"api_key": "judge-key", "base_url": None}),
        (
            {"api_base": "https://judge.test/v1"},
            {"api_key": None, "base_url": "https://judge.test/v1"},
        ),
    ],
)
async def test_llm_provider_override_with_scan_model(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, str], expected: dict[str, str | None]
) -> None:
    provider, model = _fake_llm(
        monkeypatch, '{"risky":false,"category":"safe","reason":"This only reads public data."}'
    )
    await LlmJudge(_settings(**overrides)).evaluate({})
    provider.assert_called_once_with(**expected)
    provider.return_value.get_model.assert_called_once_with("openai/gpt-5")
    assert model.call_args.kwargs["model_settings"].extra_headers != {"X-Main": "private"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "output",
    [
        "",
        "not JSON",
        "[]",
        "{}",
        '{"risky":0,"category":"safe","reason":"Read only."}',
        '{"risky":2,"category":"safe","reason":"Read only."}',
        '{"risky":NaN,"category":"safe","reason":"Read only."}',
        '{"risky":"false","category":"safe","reason":"Read only."}',
        '{"risky":null,"category":"safe","reason":"Read only."}',
        '{"risk":0,"category":"safe","reason":"Read only."}',
        '{"risky":false,"category":"unknown","reason":"Read only."}',
        '{"risky":false,"category":"safe","reason":""}',
        '{"risky":false,"category":"safe","reason":null}',
    ],
)
async def test_llm_invalid_output_retried(monkeypatch: pytest.MonkeyPatch, output: str) -> None:
    _, model = _fake_llm(
        monkeypatch,
        output,
        '{"risky":false,"category":"safe","reason":"This only reads public data."}',
    )
    sleep = AsyncMock()
    monkeypatch.setattr(asyncio, "sleep", sleep)
    guard = ActionApprovalGuard(_settings())
    assert await guard.check(_ctx(guard), "exec_command", {"cmd": "test command"}) is None
    assert model.await_count == 2
    sleep.assert_awaited_once_with(1.0)


@pytest.mark.asyncio
async def test_llm_requires_a_model(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_llm(monkeypatch)
    monkeypatch.setattr(
        action_approvals,
        "load_settings",
        lambda: Settings(llm=LlmSettings.model_validate({"model": None})),
    )
    with pytest.raises(ValueError, match="require an LLM model"):
        await LlmJudge(_settings()).evaluate({})


@pytest.mark.asyncio
@pytest.mark.parametrize("supports_reasoning", [True, False])
async def test_llm_low_reasoning_only_when_supported(
    monkeypatch: pytest.MonkeyPatch, supports_reasoning: bool
) -> None:
    _, model = _fake_llm(
        monkeypatch, '{"risky":false,"category":"safe","reason":"This only reads public data."}'
    )

    def supports_model_reasoning(_model_name: str) -> bool:
        return supports_reasoning

    monkeypatch.setattr(inputs, "model_supports_reasoning", supports_model_reasoning)
    await LlmJudge(_settings()).evaluate({})
    reasoning = model.call_args.kwargs["model_settings"].reasoning
    assert reasoning.effort == "low" if supports_reasoning else reasoning is None
