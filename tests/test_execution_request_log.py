from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import httpx
import pytest
from agents import RunConfig, Runner
from openai import APIError, PermissionDeniedError

from strix.core import execution
from strix.core.agents import AgentCoordinator
from strix.llm import request_log


if TYPE_CHECKING:
    from collections.abc import AsyncIterator


def _request() -> httpx.Request:
    return httpx.Request("POST", "https://api.openai.com/v1/responses")


def _midstream_api_error() -> APIError:
    return APIError("An error occurred while processing the request.", _request(), body=None)


def _blocked_error() -> PermissionDeniedError:
    response = httpx.Response(
        403, request=_request(), headers={"x-request-id": "req_blocked_hdr"}, text="blocked"
    )
    return PermissionDeniedError("Output blocked by policy", response=response, body=None)


class _FakeStream:
    def __init__(self, exc: BaseException | None = None) -> None:
        self._exc = exc
        self.run_loop_exception: BaseException | None = None
        self.seen_context: request_log.LlmCallContext | None = None

    async def stream_events(self) -> AsyncIterator[Any]:
        self.seen_context = request_log.current_call_context()
        if self._exc is not None:
            raise self._exc
        items: tuple[Any, ...] = ()
        for item in items:
            yield item


async def _run(
    monkeypatch: pytest.MonkeyPatch,
    streams: list[_FakeStream],
    coordinator: AgentCoordinator | None = None,
) -> Any:
    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_BASE_DELAY_S", 0.0)
    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_MAX_DELAY_S", 0.0)
    calls = {"n": 0}

    def _fake_run_streamed(*_args: Any, **_kwargs: Any) -> _FakeStream:
        stream = streams[calls["n"]]
        calls["n"] += 1
        return stream

    monkeypatch.setattr(Runner, "run_streamed", _fake_run_streamed)
    coordinator = coordinator or AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    return await execution._run_cycle(
        object(),
        coordinator,
        "root",
        input_data="task",
        run_config=cast("RunConfig", object()),
        context={},
        max_turns=5,
        session=None,
        interactive=False,
        event_sink=None,
        hooks=None,
    )


@pytest.mark.asyncio
async def test_each_transient_replay_is_stamped_with_its_attempt_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams = [
        _FakeStream(exc=_midstream_api_error()),
        _FakeStream(exc=_midstream_api_error()),
        _FakeStream(),
    ]
    await _run(monkeypatch, streams)
    assert [s.seen_context.retry_attempt for s in streams if s.seen_context] == [0, 1, 2]


@pytest.mark.asyncio
async def test_blocked_provider_failure_text_carries_request_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator = AgentCoordinator()
    with pytest.raises(PermissionDeniedError):
        await _run(monkeypatch, [_FakeStream(exc=_blocked_error())], coordinator)
    assert coordinator.statuses["root"] == "failed"
    error = coordinator.errors["root"]
    assert "Output blocked by policy" in error
    assert error.endswith("[provider request id: req_blocked_hdr]")


@pytest.mark.asyncio
async def test_run_agent_loop_binds_agent_context_and_resets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, request_log.LlmCallContext] = {}

    async def _fake_loop(**_kwargs: Any) -> None:
        seen["ctx"] = request_log.current_call_context()

    monkeypatch.setattr(execution, "_run_agent_loop", _fake_loop)

    class _Agent:
        name = "Recon Agent"

    coordinator = AgentCoordinator()
    await execution.run_agent_loop(
        agent=_Agent(),
        initial_input="task",
        run_config=cast("RunConfig", object()),
        context={},
        max_turns=1,
        coordinator=coordinator,
        agent_id="agent-42",
        interactive=False,
    )
    assert seen["ctx"].agent_id == "agent-42"
    assert seen["ctx"].agent_name == "Recon Agent"
    assert request_log.current_call_context().agent_id is None
