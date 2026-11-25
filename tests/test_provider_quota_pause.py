"""A scan pauses, and later resumes, when the LLM provider account is out of budget."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import httpx
import pytest
from openai import APIStatusError, RateLimitError

from strix.core import execution
from strix.core.agents import AgentCoordinator, BudgetPolicy
from strix.core.execution import run_agent_loop
from strix.core.hooks import BudgetPausedError, ReportUsageHooks
from strix.core.sessions import open_agent_session
from strix.llm.provider_errors import classify_provider_failure


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path


def _status_error(cls: type[APIStatusError], status: int, body: dict[str, Any]) -> APIStatusError:
    request = httpx.Request("POST", "https://llm.example/v1/responses")
    response = httpx.Response(status, request=request, json={"error": body})
    return cls(body.get("message", ""), response=response, body={"error": body})


@pytest.mark.parametrize(
    "exc",
    [
        _status_error(
            RateLimitError,
            429,
            {
                "message": "You exceeded your current quota, please check your plan.",
                "code": "insufficient_quota",
            },
        ),
        _status_error(APIStatusError, 402, {"message": "Payment Required"}),
        _status_error(
            APIStatusError,
            400,
            {"message": "Your credit balance is too low to access the API."},
        ),
        _status_error(APIStatusError, 400, {"message": "x", "code": "billing_hard_limit_reached"}),
        RuntimeError("stream ended: insufficient credits"),
    ],
)
def test_out_of_budget_errors_are_classified(exc: BaseException) -> None:
    assert classify_provider_failure(exc) == "provider_quota"


@pytest.mark.parametrize(
    "exc",
    [
        _status_error(RateLimitError, 429, {"message": "Rate limit reached for requests"}),
        _status_error(APIStatusError, 401, {"message": "Incorrect API key provided"}),
        _status_error(APIStatusError, 500, {"message": "The server had an error"}),
        TimeoutError("timed out"),
        ValueError("context length exceeded"),
    ],
)
def test_other_errors_are_not_classified(exc: BaseException) -> None:
    assert classify_provider_failure(exc) is None


def test_wrapped_error_is_classified() -> None:
    try:
        try:
            raise _status_error(APIStatusError, 402, {"message": "Payment Required"})
        except APIStatusError as inner:
            raise RuntimeError("model call failed") from inner
    except RuntimeError as outer:
        assert classify_provider_failure(outer) == "provider_quota"


async def _coordinator(*agents: str) -> AgentCoordinator:
    coordinator = AgentCoordinator()
    for index, agent_id in enumerate(agents):
        await coordinator.register(agent_id, agent_id, None if index == 0 else agents[0])
    return coordinator


async def test_provider_pause_holds_until_resumed() -> None:
    coordinator = await _coordinator("root", "child")
    epoch = await coordinator.pause_for_provider("child", "provider_quota", "out of credits")

    assert coordinator.pause_reason == "provider_quota"
    assert coordinator.operator_paused
    assert coordinator.statuses == {"root": "running", "child": "budget_paused"}

    waiter = asyncio.create_task(coordinator.wait_for_budget_resume("child", parked_epoch=epoch))
    await asyncio.sleep(0.05)
    assert not waiter.done()

    assert await coordinator.resume_budget() == ["child"]
    await asyncio.wait_for(waiter, 1)
    assert coordinator.statuses["child"] == "running"
    assert not coordinator.budget_paused
    assert coordinator.pause_reason is None


async def test_one_parked_agent_probes_and_success_resumes_everyone() -> None:
    coordinator = await _coordinator("root", "a", "b")
    coordinator.provider_probe_interval = 0.05
    epoch = await coordinator.pause_for_provider("a", "provider_quota", "out of credits")
    await coordinator.pause_for_provider("b", "provider_quota", "out of credits")

    wait_a = asyncio.create_task(coordinator.wait_for_budget_resume("a", parked_epoch=epoch))
    wait_b = asyncio.create_task(coordinator.wait_for_budget_resume("b", parked_epoch=epoch))
    done, pending = await asyncio.wait({wait_a, wait_b}, timeout=0.3)

    assert len(done) == 1
    assert len(pending) == 1
    probe = "a" if wait_a in done else "b"
    other = "b" if probe == "a" else "a"
    assert coordinator.is_provider_probe(probe)
    assert coordinator.statuses[probe] == "running"
    assert coordinator.statuses[other] == "budget_paused"
    assert coordinator.pause_reason == "provider_quota"

    await coordinator.provider_call_succeeded(probe)
    await asyncio.wait_for(next(iter(pending)), 1)
    assert coordinator.statuses[other] == "running"
    assert coordinator.pause_reason is None


async def test_failed_probe_parks_again() -> None:
    coordinator = await _coordinator("root")
    coordinator.provider_probe_interval = 0.02
    epoch = await coordinator.pause_for_provider("root", "provider_quota", "out of credits")
    await asyncio.wait_for(coordinator.wait_for_budget_resume("root", parked_epoch=epoch), 1)
    assert coordinator.is_provider_probe("root")

    await coordinator.pause_for_provider("root", "provider_quota", "still out of credits")
    assert not coordinator.is_provider_probe("root")
    assert coordinator.statuses["root"] == "budget_paused"
    assert coordinator.pause_detail == "still out of credits"


async def test_user_message_resumes_a_provider_pause() -> None:
    coordinator = await _coordinator("root")
    await coordinator.pause_for_provider("root", "provider_quota", "out of credits")

    assert await coordinator.send("root", {"from": "user", "content": "I topped up, continue"})
    assert coordinator.pause_reason is None
    assert not coordinator.operator_paused


async def test_pause_reason_survives_a_snapshot() -> None:
    coordinator = await _coordinator("root")
    await coordinator.pause_for_provider("root", "provider_quota", "out of credits")
    restored = AgentCoordinator()
    await restored.restore(await coordinator.snapshot())
    assert restored.pause_reason == "provider_quota"
    assert restored.pause_detail == "out of credits"


class _QuotaStream:
    """One model call per run: rejected while ``state['broke']``, else the agent finishes."""

    def __init__(
        self,
        state: dict[str, Any],
        hooks: Any,
        context: dict[str, Any],
        coordinator: AgentCoordinator,
    ) -> None:
        self._state = state
        self._hooks = hooks
        self._context = context
        self._coordinator = coordinator
        self.run_loop_exception: BaseException | None = None
        self.final_output = None

    async def stream_events(self) -> AsyncIterator[Any]:
        agent_id = str(self._context["agent_id"])
        wrapper = MagicMock()
        wrapper.context = self._context
        try:
            await self._hooks.on_llm_start(wrapper, MagicMock(), None, [])
        except BudgetPausedError as exc:
            self.run_loop_exception = exc
            return
        self._state["attempts"].append(agent_id)
        if self._state["broke"]:
            raise _status_error(
                RateLimitError,
                429,
                {"message": "You exceeded your current quota.", "code": "insufficient_quota"},
            )
        await self._hooks.on_llm_end(wrapper, MagicMock(), MagicMock())
        await self._coordinator.set_status(agent_id, "completed")
        empty: tuple[Any, ...] = ()
        for item in empty:
            yield item

    def cancel(self, mode: str = "immediate") -> None:  # noqa: ARG002
        return


async def _noop_compact(*_args: Any, **_kwargs: Any) -> bool:
    return False


async def _until(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    async def poll() -> None:
        while not predicate():
            await asyncio.sleep(0.005)

    await asyncio.wait_for(poll(), timeout)


@pytest.mark.parametrize(
    ("probe_interval", "budget_policy"),
    [(None, "stop"), (0.05, "stop"), (0.05, "pause")],
)
async def test_scan_pauses_on_quota_and_finishes_after_it_is_restored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe_interval: float | None,
    budget_policy: BudgetPolicy,
) -> None:
    state: dict[str, Any] = {"broke": True, "attempts": []}
    coordinator = AgentCoordinator()
    coordinator.provider_probe_interval = probe_interval
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=None, budget_policy=budget_policy)

    class _Runner:
        @staticmethod
        def run_streamed(
            agent: Any,  # noqa: ARG004
            input: Any,  # noqa: A002, ARG004
            *,
            run_config: Any,  # noqa: ARG004
            context: dict[str, Any],
            max_turns: int,  # noqa: ARG004
            session: Any,  # noqa: ARG004
            hooks: Any,
        ) -> _QuotaStream:
            return _QuotaStream(state, hooks, context, coordinator)

    monkeypatch.setattr(execution, "Runner", _Runner)
    monkeypatch.setattr(execution, "_compact_session", _noop_compact)
    monkeypatch.setattr("strix.core.hooks.get_global_report_state", lambda: None)

    tasks = []
    for agent_id, parent in (("root", None), ("child", "root")):
        await coordinator.register(agent_id, agent_id, parent)
        tasks.append(
            asyncio.create_task(
                run_agent_loop(
                    agent=MagicMock(),
                    initial_input=[],
                    run_config=MagicMock(),
                    context={"agent_id": agent_id, "parent_id": parent, "coordinator": coordinator},
                    max_turns=50,
                    coordinator=coordinator,
                    agent_id=agent_id,
                    interactive=False,
                    session=open_agent_session(agent_id, tmp_path / "agents.sqlite"),
                    hooks=hooks,
                )
            )
        )

    await _until(lambda: all(coordinator.statuses[a] == "budget_paused" for a in ("root", "child")))
    assert coordinator.pause_reason == "provider_quota"
    assert "quota" in (coordinator.pause_detail or "")
    assert not any(task.done() for task in tasks)

    state["broke"] = False
    if probe_interval is None:
        await coordinator.resume_budget()

    await asyncio.wait_for(asyncio.gather(*tasks), 5)
    assert coordinator.statuses == {"root": "completed", "child": "completed"}
    assert coordinator.pause_reason is None


async def test_restarting_a_quota_paused_scan_puts_parked_agents_back_to_work() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "root", None)
    await coordinator.register("child", "child", "root")
    await coordinator.pause_for_provider("child", "provider_quota", "out of credits")

    restored = AgentCoordinator()
    await restored.restore(await coordinator.snapshot())
    assert await restored.clear_restored_provider_pause()

    assert restored.statuses == {"root": "running", "child": "running"}
    assert not restored.operator_paused
    assert not restored.budget_paused
    assert restored.pause_reason is None
    assert not await restored.clear_restored_provider_pause()


async def test_restarted_agent_reads_messages_queued_while_it_was_parked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parked = AgentCoordinator()
    await parked.register("root", "root", None)
    await parked.register("child", "child", "root")
    await parked.pause_for_provider("child", "provider_quota", "out of credits")
    await parked.send("child", {"from": "root", "content": "also check /admin"})

    coordinator = AgentCoordinator()
    await coordinator.restore(await parked.snapshot())
    await coordinator.clear_restored_provider_pause()

    state: dict[str, Any] = {"broke": False, "attempts": []}
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=None, budget_policy="stop")

    class _Runner:
        @staticmethod
        def run_streamed(*_args: Any, context: dict[str, Any], **_kwargs: Any) -> _QuotaStream:
            return _QuotaStream(state, hooks, context, coordinator)

    monkeypatch.setattr(execution, "Runner", _Runner)
    monkeypatch.setattr(execution, "_compact_session", _noop_compact)
    monkeypatch.setattr("strix.core.hooks.get_global_report_state", lambda: None)

    session = open_agent_session("child", tmp_path / "agents.sqlite")
    await asyncio.wait_for(
        run_agent_loop(
            agent=MagicMock(),
            initial_input=[],
            run_config=MagicMock(),
            context={"agent_id": "child", "parent_id": "root", "coordinator": coordinator},
            max_turns=50,
            coordinator=coordinator,
            agent_id="child",
            interactive=False,
            session=session,
            hooks=hooks,
        ),
        5,
    )

    assert "also check /admin" in str(await session.get_items())
    assert coordinator.statuses["child"] == "completed"
