"""Action approval decisions, independent waits, and tool execution boundaries."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from agents.tool import FunctionTool, invoke_function_tool
from agents.tool_context import ToolContext
from openai.types.responses import ResponseOutputMessage, ResponseOutputText
from pydantic import ValidationError

from strix.agents.factory import _wrap_exec_command, _wrap_write_stdin
from strix.config.settings import ActionApprovalSettings, LlmSettings, Settings
from strix.core import action_approvals, inputs, runner
from strix.core.action_approvals import QUESTIONS, ActionApprovalGuard, LlmJudge
from strix.core.agents import AgentCoordinator
from strix.tools.mcp.agent_tools import call_mcp
from strix.tools.proxy import caido_api
from strix.tools.proxy import tools as proxy_tools
from strix.tools.proxy.tools import repeat_request
from tests.test_runner_root_prompt import _patch_engine_scaffold


def _response(risk: float = 0.99) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "answers": {
                "unsafe": {"noul": risk},
                "category": {
                    "choice": "deletes_data" if risk >= 0.5 else "safe",
                    "probabilities": {"deletes_data": risk, "safe": 1 - risk},
                },
            },
        },
    )


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
            "api_key": "test-key",
            **overrides,
        }
    )


async def _pending(guard: ActionApprovalGuard, count: int = 1) -> list[dict[str, Any]]:
    async with asyncio.timeout(2):
        while len(guard.pending()) < count:
            await asyncio.sleep(0)
    return guard.pending()


def test_settings_defaults_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = ActionApprovalSettings()
    assert not settings.enabled
    assert settings.mode == "ask"
    assert settings.tools == ["exec_command", "write_stdin", "repeat_request", "call_mcp"]
    assert settings.timeout_seconds == 300
    assert settings.on_timeout == "block"
    assert settings.model == "baseten/joey-1"
    assert settings.judge == "decision"
    assert settings.threshold == 0.5
    assert not Settings().action_approvals.enabled
    monkeypatch.setenv("STRIX_ACTION_APPROVALS", "true")
    monkeypatch.setenv("STRIX_ACTION_APPROVAL_MODE", "AUTO")
    monkeypatch.setenv("STRIX_ACTION_APPROVAL_JUDGE", "LLM")
    monkeypatch.setenv("STRIX_ACTION_APPROVAL_TOOLS", '["exec_command"]')
    monkeypatch.setenv("OPENROUTER_API_KEY", "fallback-key")
    monkeypatch.delenv("ACTION_APPROVAL_API_KEY", raising=False)
    assert ActionApprovalSettings().api_key == "fallback-key"
    monkeypatch.setenv("ACTION_APPROVAL_API_KEY", "primary-key")
    resolved = ActionApprovalSettings()
    assert resolved.api_key == "primary-key"
    assert resolved.enabled and resolved.mode == "auto"
    assert resolved.judge == "llm"
    assert resolved.tools == ["exec_command"]
    assert ActionApprovalSettings.model_validate({"tools": '["call_mcp"]'}).tools == ["call_mcp"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"threshold": -0.1},
        {"threshold": 1.1},
        {"threshold": float("nan")},
        {"timeout_seconds": 0},
        {"mode": "other"},
        {"on_timeout": "other"},
        {"judge": "other"},
    ],
)
def test_settings_reject_invalid_values(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        _settings(**overrides)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides,tool",
    [({"enabled": False}, "exec_command"), ({"tools": []}, "exec_command"), ({}, "other_tool")],
)
async def test_disabled_and_unguarded_never_call_judge(
    overrides: dict[str, Any], tool: str
) -> None:
    def transport(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("Judge must not be called")

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        guard = ActionApprovalGuard(_settings(**overrides), client=client)
        assert await guard.check(_ctx(guard), tool, {}) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("risk,blocked", [(0.02, False), (0.99, True), (0.5, True)])
async def test_auto_decision_and_request_payload(risk: float, blocked: bool) -> None:
    requests = []
    events: list[dict[str, Any]] = []

    def transport(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _response(risk)

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        guard = ActionApprovalGuard(_settings(), client=client, event_sink=events.append)
        args = {"cmd": "test command"}
        result = await guard.check(_ctx(guard), "exec_command", args)
        assert (result is not None) is blocked
        if blocked:
            assert result is not None
            assert "this action did not run" in result
        assert str(requests[0].url) == "https://openrouter.ai/api/alpha/decisions"
        body = json.loads(requests[0].content)
        assert body["questions"] == QUESTIONS
        assert body["model"] == "baseten/joey-1"
        assert body["state"] == {
            "tool": "exec_command",
            "arguments": args,
            "agent_task": "Check the authorized application",
            "authorized_targets": ["example.com"],
        }
        assert events[0]["decision"] == ("blocked" if blocked else "allowed")
        assert events[0]["risk"] == risk
        assert events[0]["reason"] is None
        assert events[0]["summary"] == "test command"
        assert events[0]["agent_name"] == "Validation agent"


@pytest.mark.asyncio
@pytest.mark.parametrize("approved", [True, False])
async def test_ask_human_resolution(approved: bool) -> None:
    events: list[dict[str, Any]] = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: _response())) as client:
        guard = ActionApprovalGuard(_settings(mode="ask"), client=client, event_sink=events.append)
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
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: _response())) as client:
        guard = ActionApprovalGuard(
            _settings(mode="ask", timeout_seconds=0.01, on_timeout=policy),
            client=client,
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

    def transport(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(200, json={"answers": {}}) if malformed else httpx.Response(503)
        return _response(0.02)

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        guard = ActionApprovalGuard(_settings(), client=client)
        assert await guard.check(_ctx(guard), "exec_command", {}) is None
        assert calls == 2
        assert "Action approval judge failed" in caplog.text


@pytest.mark.asyncio
async def test_concurrent_agents_have_independent_judge_calls_and_approvals() -> None:
    calls = []

    async def transport(request: httpx.Request) -> httpx.Response:
        cmd = json.loads(request.content)["state"]["arguments"].get("cmd")
        calls.append(cmd)
        return _response(0.02 if cmd == "safe" else 0.99)

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        guard = ActionApprovalGuard(_settings(mode="ask"), client=client)
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
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: _response())) as client:
        guard = ActionApprovalGuard(_settings(mode="ask"), client=client)
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

    def transport(_request: httpx.Request) -> httpx.Response:
        called.set()
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        guard = ActionApprovalGuard(_settings(), client=client)
        task = asyncio.create_task(guard.check(_ctx(guard), "exec_command", {}))
        await called.wait()
        guard.block_pending()
        result = await asyncio.wait_for(task, 1)
        assert result is not None
        assert "stopped" in result


@pytest.mark.asyncio
async def test_cancelled_check_leaves_no_pending_approval() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: _response())) as client:
        guard = ActionApprovalGuard(_settings(mode="ask"), client=client)
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
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: _response())) as client:
        guard = ActionApprovalGuard(_settings(), client=client)
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

    def transport(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return _response()

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        guard = ActionApprovalGuard(_settings(), client=client)
        result = await tool.on_invoke_tool(_ctx(guard), json.dumps(args))
        assert "Blocked by action approvals" in result
        judged = requests[0]["state"]["arguments"]
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

    def transport(request: httpx.Request) -> httpx.Response:
        assert not proxy_tools._CAIDO_CALL_LOCK.locked()
        requests.append(json.loads(request.content))
        return _response()

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        guard = ActionApprovalGuard(_settings(), client=client, event_sink=events.append)
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
        judged = requests[0]["state"]["arguments"]
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
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: _response())) as client:
        guard = ActionApprovalGuard(_settings(mode="ask"), client=client)
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
    def transport(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("Judge must not run without a prepared request")

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        guard = ActionApprovalGuard(_settings(), client=client)
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
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: _response())) as client:
        guard = ActionApprovalGuard(_settings(mode="ask"), client=client)
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
@pytest.mark.parametrize("enabled", [False, True])
async def test_runner_attaches_scan_override_and_sink_then_closes_guard(
    enabled: bool, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _patch_engine_scaffold(monkeypatch, tmp_path, {})
    coordinator = AgentCoordinator()
    override = _settings(enabled=enabled, tools=[])
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
@pytest.mark.parametrize("mode,risk", [("auto", 0.0), ("auto", 0.99), ("ask", 0.99)])
async def test_llm_judge_and_reason_events(
    monkeypatch: pytest.MonkeyPatch, mode: str, risk: float
) -> None:
    reason = "This deletes the users table in the target database."
    provider, model = _fake_llm(
        monkeypatch,
        json.dumps(
            {"risk": risk, "category": "deletes_data" if risk else "safe", "reason": reason}
        ),
    )
    events: list[dict[str, Any]] = []
    guard = ActionApprovalGuard(_settings(judge="llm", mode=mode), event_sink=events.append)
    task = asyncio.create_task(guard.check(_ctx(guard), "exec_command", {"cmd": "test command"}))
    if mode == "ask":
        pending = await _pending(guard)
        assert pending[0]["reason"] == reason
        assert guard.resolve(pending[0]["approval_id"], approved=False)
    result = await task
    if risk:
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
        monkeypatch, '{"risk":0,"category":"safe","reason":"This only reads public data."}'
    )
    judge = LlmJudge(
        _settings(
            judge="llm", model=model_name, api_key="judge-key", api_base="https://judge.test/v1"
        )
    )
    assert await judge.evaluate({}) == (0.0, "safe", "This only reads public data.")
    provider.assert_called_once_with(api_key="judge-key", base_url="https://judge.test/v1")
    provider.return_value.get_model.assert_called_once_with(model_name)
    request = model.call_args.kwargs
    assert request["model_settings"].extra_headers != {"X-Main": "private"}
    assert not request["model_settings"].extra_body
    assert "api_key" not in request["model_settings"].extra_args


@pytest.mark.asyncio
async def test_llm_implicit_decision_endpoint_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, _ = _fake_llm(
        monkeypatch, '{"risk":0,"category":"safe","reason":"This only reads public data."}'
    )
    await LlmJudge(_settings(judge="llm", model="openrouter/test")).evaluate({})
    provider.assert_called_once_with(api_key="test-key", base_url=None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "output",
    [
        "",
        "not JSON",
        "[]",
        "{}",
        '{"risk":true,"category":"safe","reason":"Read only."}',
        '{"risk":2,"category":"safe","reason":"Read only."}',
        '{"risk":NaN,"category":"safe","reason":"Read only."}',
        '{"risk":0,"category":"unknown","reason":"Read only."}',
        '{"risk":0,"category":"safe","reason":""}',
        '{"risk":0,"category":"safe","reason":null}',
    ],
)
async def test_llm_invalid_output_retried(monkeypatch: pytest.MonkeyPatch, output: str) -> None:
    _, model = _fake_llm(
        monkeypatch,
        output,
        '{"risk":0,"category":"safe","reason":"This only reads public data."}',
    )
    sleep = AsyncMock()
    monkeypatch.setattr(asyncio, "sleep", sleep)
    guard = ActionApprovalGuard(_settings(judge="llm"))
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
        await LlmJudge(_settings(judge="llm")).evaluate({})


@pytest.mark.asyncio
@pytest.mark.parametrize("supports_reasoning", [True, False])
async def test_llm_low_reasoning_only_when_supported(
    monkeypatch: pytest.MonkeyPatch, supports_reasoning: bool
) -> None:
    _, model = _fake_llm(
        monkeypatch, '{"risk":0,"category":"safe","reason":"This only reads public data."}'
    )

    def supports_model_reasoning(_model_name: str) -> bool:
        return supports_reasoning

    monkeypatch.setattr(inputs, "model_supports_reasoning", supports_model_reasoning)
    await LlmJudge(_settings(judge="llm")).evaluate({})
    reasoning = model.call_args.kwargs["model_settings"].reasoning
    assert reasoning.effort == "low" if supports_reasoning else reasoning is None
