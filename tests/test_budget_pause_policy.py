"""``budget_policy="pause"``: agents park before a paid call and never hear about budgets."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

from strix.core import execution
from strix.core.agents import AgentCoordinator
from strix.core.execution import _start_child_runner, run_agent_loop
from strix.core.hooks import (
    BudgetExceededError,
    BudgetPausedError,
    ReportUsageHooks,
    recomputed_budget_flags,
)
from strix.core.sessions import open_agent_session


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path


COST_PER_CALL = 1.0
_CALL_LATENCY_S = 0.005


class _FakeLedger:
    def __init__(self) -> None:
        self.cost = 0.0
        self.calls: list[str] = []
        self.remaining: dict[str, int] = {}
        self.warned_inputs: list[list[Any]] = []
        self.gate: asyncio.Event | None = None
        self.in_flight = 0

    def record_sdk_usage(self, **_kwargs: Any) -> None:
        return

    def get_total_llm_cost(self) -> float:
        return self.cost


class _FakeStream:
    """One ``Runner.run_streamed`` call: several LLM turns, each guarded by the hooks.

    Mirrors the SDK's ordering: ``on_llm_start`` runs before the paid request,
    ``on_llm_end`` after it. A ``BudgetPausedError`` from ``on_llm_start`` ends
    the stream without spending, exactly like the SDK surfacing a hook error.
    """

    def __init__(
        self,
        *,
        ledger: _FakeLedger,
        hooks: ReportUsageHooks,
        context: dict[str, Any],
        agent: Any,
        coordinator: AgentCoordinator,
    ) -> None:
        self._ledger = ledger
        self._hooks = hooks
        self._context = context
        self._agent = agent
        self._coordinator = coordinator
        self.run_loop_exception: BaseException | None = None
        self.final_output = None

    async def stream_events(self) -> AsyncIterator[Any]:
        agent_id = str(self._context.get("agent_id"))
        ctx_wrapper = MagicMock()
        ctx_wrapper.context = self._context
        while self._ledger.remaining.get(agent_id, 0) > 0:
            input_items: list[Any] = []
            try:
                await self._hooks.on_llm_start(ctx_wrapper, self._agent, None, input_items)
            except BudgetPausedError as exc:
                self.run_loop_exception = exc
                return
            self._ledger.warned_inputs.append(input_items)
            if self._ledger.gate is not None:
                self._ledger.in_flight += 1
                await self._ledger.gate.wait()
                self._ledger.in_flight -= 1
            self._ledger.cost += COST_PER_CALL
            self._ledger.calls.append(agent_id)
            self._ledger.remaining[agent_id] -= 1
            await self._hooks.on_llm_end(ctx_wrapper, self._agent, MagicMock())
            await asyncio.sleep(_CALL_LATENCY_S)
        if self._coordinator.statuses.get(agent_id) == "running":
            await self._coordinator.set_status(agent_id, "completed")
        items: tuple[Any, ...] = ()
        for item in items:
            yield item

    def cancel(self, mode: str = "immediate") -> None:  # noqa: ARG002
        return


def _fake_runner(ledger: _FakeLedger, coordinator: AgentCoordinator) -> Any:
    class _FakeRunner:
        @staticmethod
        def run_streamed(
            agent: Any,
            input: Any,  # noqa: A002, ARG004
            *,
            run_config: Any,  # noqa: ARG004
            context: dict[str, Any],
            max_turns: int,  # noqa: ARG004
            session: Any,  # noqa: ARG004
            hooks: ReportUsageHooks,
        ) -> _FakeStream:
            return _FakeStream(
                ledger=ledger,
                hooks=hooks,
                context=context,
                agent=agent,
                coordinator=coordinator,
            )

    return _FakeRunner


async def _noop_compact(*_args: Any, **_kwargs: Any) -> bool:
    return False


async def _wait_until(predicate: Callable[[], bool], *, timeout: float = 5.0) -> None:
    async def _poll() -> None:
        while not predicate():
            await asyncio.sleep(0.001)

    await asyncio.wait_for(_poll(), timeout=timeout)


def _all_parked(coordinator: AgentCoordinator, *agent_ids: str) -> bool:
    return all(coordinator.statuses.get(aid) == "budget_paused" for aid in agent_ids)


class _Scan:
    """Root + children driven through the real non-interactive loops."""

    def __init__(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        max_budget_usd: float | None,
    ) -> None:
        self.ledger = _FakeLedger()
        self.hooks = ReportUsageHooks(
            model="test-model", max_budget_usd=max_budget_usd, budget_policy="pause"
        )
        self.coordinator = AgentCoordinator()
        self.coordinator.set_budget_policy("pause")
        self.coordinator.set_budget_limit_setter(self.hooks.set_max_budget_usd)
        monkeypatch.setattr(execution, "Runner", _fake_runner(self.ledger, self.coordinator))
        monkeypatch.setattr(execution, "_compact_session", _noop_compact)
        self.db_path = tmp_path / "agents.sqlite"
        self.sessions: list[Any] = []
        self.run_config = MagicMock()
        self.root_ctx: dict[str, Any] = {
            "agent_id": "root",
            "parent_id": None,
            "coordinator": self.coordinator,
        }
        self.root_task: asyncio.Task[Any] | None = None

    async def start_root(self, *, calls: int) -> None:
        self.ledger.remaining["root"] = calls
        await self.coordinator.register("root", "strix", parent_id=None)
        session = open_agent_session("root", self.db_path)
        self.sessions.append(session)
        self.root_task = asyncio.create_task(
            run_agent_loop(
                agent=MagicMock(),
                initial_input=[],
                run_config=self.run_config,
                context=self.root_ctx,
                max_turns=500,
                coordinator=self.coordinator,
                agent_id="root",
                interactive=False,
                session=session,
                hooks=self.hooks,
            )
        )

    async def start_child(self, child_id: str, *, calls: int) -> None:
        self.ledger.remaining[child_id] = calls
        await self.coordinator.register(child_id, "recon", parent_id="root")
        await _start_child_runner(
            parent_ctx=self.root_ctx,
            coordinator=self.coordinator,
            agents_db_path=self.db_path,
            sessions_to_close=self.sessions,
            run_config=self.run_config,
            max_turns=500,
            interactive=False,
            child_agent=MagicMock(),
            child_id=child_id,
            name=f"recon-{child_id}",
            parent_id="root",
            task="probe things",
            initial_input=[],
            hooks=self.hooks,
        )

    def tasks(self) -> list[asyncio.Task[Any]]:
        tasks = [self.root_task] if self.root_task is not None else []
        tasks.extend(rt.task for rt in self.coordinator.runtimes.values() if rt.task is not None)
        return tasks

    async def teardown(self) -> None:
        for task in self.tasks():
            task.cancel()
        await asyncio.gather(*self.tasks(), return_exceptions=True)
        for session in self.sessions:
            session.close()


@pytest.mark.asyncio
async def test_pause_policy_parks_every_agent_at_the_limit_and_resumes_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = _Scan(tmp_path, monkeypatch, max_budget_usd=5.0)
    agents = ("root", "child-a", "child-b")

    with patch("strix.core.hooks.get_global_report_state", return_value=scan.ledger):
        await scan.start_root(calls=100)
        await scan.start_child("child-a", calls=100)
        await scan.start_child("child-b", calls=100)

        await _wait_until(lambda: _all_parked(scan.coordinator, *agents))
        assert scan.ledger.cost == pytest.approx(5.0)
        assert len(scan.ledger.calls) == 5
        assert scan.coordinator.budget_paused is False
        assert scan.coordinator.budget_stopped is False
        assert scan.coordinator.reserve_stopped is False
        assert all(not task.done() for task in scan.tasks())

        woken = await scan.coordinator.resume_budget(max_budget_usd=8.0)
        assert sorted(woken) == sorted(agents)
        assert scan.hooks.max_budget_usd == 8.0
        await _wait_until(lambda: scan.ledger.cost >= 8.0)
        await _wait_until(lambda: _all_parked(scan.coordinator, *agents))
        assert scan.ledger.cost == pytest.approx(8.0)

        await scan.coordinator.resume_budget(max_budget_usd=9.0)
        await _wait_until(lambda: scan.ledger.cost >= 9.0)
        await _wait_until(lambda: _all_parked(scan.coordinator, *agents))
        assert scan.ledger.cost == pytest.approx(9.0)
        assert len(scan.ledger.calls) == 9
        assert all(not task.done() for task in scan.tasks())

        # The model never saw a budget message: no warning band, no resume note.
        assert scan.ledger.warned_inputs
        assert all(items == [] for items in scan.ledger.warned_inputs)
        for session in scan.sessions:
            assert await session.get_items() == []

        # Stop while parked: an individual stop wakes that loop and it exits.
        child_a_task = scan.coordinator.runtimes["child-a"].task
        assert child_a_task is not None
        await scan.coordinator.request_stop("child-a")
        await asyncio.wait_for(child_a_task, timeout=5.0)
        assert scan.coordinator.statuses["child-a"] == "stopped"
        assert scan.coordinator.statuses["root"] == "budget_paused"
        assert scan.coordinator.statuses["child-b"] == "budget_paused"

        # A scan-wide cancel while parked tears the rest down cleanly.
        await scan.teardown()
        assert all(task.done() for task in scan.tasks())
        assert scan.ledger.cost == pytest.approx(9.0)


@pytest.mark.asyncio
async def test_pause_policy_operator_pause_and_resume_without_a_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = _Scan(tmp_path, monkeypatch, max_budget_usd=None)
    agents = ("root", "child-a", "child-b")

    with patch("strix.core.hooks.get_global_report_state", return_value=scan.ledger):
        await scan.start_root(calls=6)
        await scan.start_child("child-a", calls=6)
        await scan.start_child("child-b", calls=6)

        await _wait_until(lambda: scan.ledger.cost >= 3.0)
        await scan.coordinator.pause_budget()
        spent_at_pause = scan.ledger.cost
        await _wait_until(lambda: _all_parked(scan.coordinator, *agents))
        await _wait_until(lambda: scan.coordinator.budget_paused, timeout=0.1)
        assert scan.ledger.cost == pytest.approx(spent_at_pause)
        assert all(not task.done() for task in scan.tasks())

        await asyncio.sleep(0.05)
        assert scan.ledger.cost == pytest.approx(spent_at_pause)

        woken = await scan.coordinator.resume_budget()
        assert sorted(woken) == sorted(agents)
        await _wait_until(lambda: not scan.coordinator.budget_paused, timeout=0.1)
        await asyncio.wait_for(asyncio.gather(*scan.tasks(), return_exceptions=True), timeout=5.0)
        assert scan.ledger.cost == pytest.approx(18.0)
        assert {aid: str(s) for aid, s in scan.coordinator.statuses.items()} == {
            "root": "completed",
            "child-a": "completed",
            "child-b": "completed",
        }
        assert all(items == [] for items in scan.ledger.warned_inputs)

    for session in scan.sessions:
        session.close()


@pytest.mark.asyncio
async def test_pause_policy_keeps_in_flight_overshoot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = _Scan(tmp_path, monkeypatch, max_budget_usd=1.0)
    scan.ledger.gate = asyncio.Event()
    await scan.coordinator.register("root", "strix", parent_id=None)

    with patch("strix.core.hooks.get_global_report_state", return_value=scan.ledger):
        await scan.start_child("child-a", calls=100)
        await scan.start_child("child-b", calls=100)

        # Both calls were dispatched under the limit; neither is cancelled.
        await _wait_until(lambda: scan.ledger.in_flight == 2)
        assert scan.ledger.cost == 0.0
        scan.ledger.gate.set()

        await _wait_until(lambda: _all_parked(scan.coordinator, "child-a", "child-b"))
        assert scan.ledger.cost == pytest.approx(2.0)
        assert scan.hooks.max_budget_usd is not None
        assert scan.ledger.cost > scan.hooks.max_budget_usd
        assert scan.coordinator.budget_stopped is False
        assert all(not task.done() for task in scan.tasks())

        # Resuming at a limit that is already spent parks again without a call.
        await scan.coordinator.resume_budget(max_budget_usd=1.5)
        await asyncio.sleep(0.05)
        await _wait_until(lambda: _all_parked(scan.coordinator, "child-a", "child-b"))
        assert scan.ledger.cost == pytest.approx(2.0)

        await scan.teardown()


@pytest.mark.asyncio
async def test_resume_between_park_decision_and_wait_is_not_missed() -> None:
    coordinator = AgentCoordinator()
    coordinator.set_budget_policy("pause")
    await coordinator.register("a", "strix", parent_id=None)

    parked_epoch = coordinator.resume_epoch
    await coordinator.park_for_budget("a")
    assert _all_parked(coordinator, "a")
    await coordinator.resume_budget()

    await asyncio.wait_for(
        coordinator.wait_for_budget_resume("a", parked_epoch=parked_epoch), timeout=1.0
    )
    assert coordinator.statuses["a"] == "running"


@pytest.mark.asyncio
async def test_parked_wait_returns_on_stop_signals() -> None:
    coordinator = AgentCoordinator()
    coordinator.set_budget_policy("pause")
    await coordinator.register("a", "strix", parent_id=None)
    await coordinator.register("b", "recon", parent_id="a")
    await coordinator.park_for_budget("a")
    await coordinator.park_for_budget("b")

    wait_a = asyncio.create_task(
        coordinator.wait_for_budget_resume("a", parked_epoch=coordinator.resume_epoch)
    )
    wait_b = asyncio.create_task(
        coordinator.wait_for_budget_resume("b", parked_epoch=coordinator.resume_epoch)
    )
    await asyncio.sleep(0.02)
    assert not wait_a.done()
    assert not wait_b.done()

    await coordinator.request_stop("b")
    await asyncio.wait_for(wait_b, timeout=1.0)
    assert coordinator.statuses["b"] == "stopped"
    assert not wait_a.done()

    await coordinator.trigger_budget_stop()
    await asyncio.wait_for(wait_a, timeout=1.0)
    assert coordinator.statuses["a"] == "budget_paused"


@pytest.mark.asyncio
async def test_park_never_overwrites_a_stop_that_landed_first() -> None:
    coordinator = AgentCoordinator()
    coordinator.set_budget_policy("pause")
    await coordinator.register("a", "strix", parent_id=None)

    parked_epoch = coordinator.resume_epoch
    await coordinator.request_stop("a")
    assert await coordinator.park_for_budget("a") is False
    assert coordinator.statuses["a"] == "stopped"

    await asyncio.wait_for(
        coordinator.wait_for_budget_resume("a", parked_epoch=parked_epoch), timeout=1.0
    )
    assert coordinator.statuses["a"] == "stopped"


@pytest.mark.asyncio
async def test_parked_children_keep_the_scan_open() -> None:
    coordinator = AgentCoordinator()
    coordinator.set_budget_policy("pause")
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "recon", parent_id="root")
    assert await coordinator.park_for_budget("child") is True

    active = await coordinator.active_agents_except("root")
    assert [a["agent_id"] for a in active] == ["child"]
    assert active[0]["status"] == "budget_paused"


@pytest.mark.asyncio
async def test_resume_budget_replaces_the_limit_and_validates_it() -> None:
    hooks = ReportUsageHooks(model="m", max_budget_usd=10.0, budget_policy="pause")
    coordinator = AgentCoordinator()
    coordinator.set_budget_policy("pause")
    coordinator.set_budget_limit_setter(hooks.set_max_budget_usd)

    await coordinator.resume_budget(max_budget_usd=25.0)
    assert hooks.max_budget_usd == 25.0
    await coordinator.resume_budget()
    assert hooks.max_budget_usd == 25.0
    with pytest.raises(ValueError, match="greater than 0"):
        await coordinator.resume_budget(max_budget_usd=0.0)
    with pytest.raises(ValueError, match="finite"):
        await coordinator.resume_budget(max_budget_usd=float("inf"))
    assert hooks.max_budget_usd == 25.0


def _ctx(coordinator: AgentCoordinator | None, *, parent_id: str | None = None) -> MagicMock:
    wrapper = MagicMock()
    wrapper.context = {"agent_id": "x", "parent_id": parent_id}
    if coordinator is not None:
        wrapper.context["coordinator"] = coordinator
    return wrapper


@pytest.mark.asyncio
async def test_pause_hooks_never_warn_and_park_only_at_the_limit() -> None:
    ledger = _FakeLedger()
    hooks = ReportUsageHooks(model="m", max_budget_usd=10.0, budget_policy="pause")
    coordinator = AgentCoordinator()
    coordinator.set_budget_policy("pause")

    with patch("strix.core.hooks.get_global_report_state", return_value=ledger):
        for cost in (7.0, 8.5, 9.5, 9.99):
            ledger.cost = cost
            for parent_id in (None, "root"):
                items: list[Any] = []
                await hooks.on_llm_start(
                    _ctx(coordinator, parent_id=parent_id), MagicMock(), None, items
                )
                assert items == []
                await hooks.on_llm_end(
                    _ctx(coordinator, parent_id=parent_id), MagicMock(), MagicMock()
                )

        ledger.cost = 10.0
        await hooks.on_llm_end(_ctx(coordinator, parent_id="root"), MagicMock(), MagicMock())
        with pytest.raises(BudgetPausedError) as at_limit:
            await hooks.on_llm_start(_ctx(coordinator), MagicMock(), None, [])
        assert at_limit.value.resume_epoch == coordinator.resume_epoch

        ledger.cost = 13.7
        with pytest.raises(BudgetPausedError):
            await hooks.on_llm_start(_ctx(coordinator, parent_id="root"), MagicMock(), None, [])

        hooks.set_max_budget_usd(20.0)
        items = []
        await hooks.on_llm_start(_ctx(coordinator), MagicMock(), None, items)
        assert items == []

        await coordinator.pause_budget()
        with pytest.raises(BudgetPausedError, match="paused"):
            await hooks.on_llm_start(_ctx(coordinator), MagicMock(), None, [])


@pytest.mark.asyncio
async def test_pause_hooks_do_not_count_a_parked_turn() -> None:
    ledger = _FakeLedger()
    ledger.cost = 10.0
    hooks = ReportUsageHooks(model="m", max_budget_usd=10.0, budget_policy="pause")
    coordinator = AgentCoordinator()
    ctx = _ctx(coordinator)
    with patch("strix.core.hooks.get_global_report_state", return_value=ledger):
        with pytest.raises(BudgetPausedError):
            await hooks.on_llm_start(ctx, MagicMock(), None, [])
        assert "llm_turn" not in ctx.context
        hooks.set_max_budget_usd(11.0)
        await hooks.on_llm_start(ctx, MagicMock(), None, [])
        assert ctx.context["llm_turn"] == 1


@pytest.mark.asyncio
async def test_stop_policy_is_unchanged() -> None:
    ledger = _FakeLedger()
    hooks = ReportUsageHooks(model="m", max_budget_usd=10.0)
    assert hooks.budget_policy == "stop"

    with patch("strix.core.hooks.get_global_report_state", return_value=ledger):
        ledger.cost = 7.0
        items: list[Any] = []
        await hooks.on_llm_start(_ctx(None), MagicMock(), None, items)
        assert len(items) == 1
        assert "Scan cost budget" in str(items[0])

        ledger.cost = 10.0
        with pytest.raises(BudgetExceededError):
            await hooks.on_llm_end(_ctx(None), MagicMock(), MagicMock())

    assert recomputed_budget_flags(10.0, 10.0, interactive=False, budget_policy="stop") == (
        True,
        True,
    )
    assert recomputed_budget_flags(10.0, 10.0, interactive=False, budget_policy="pause") == (
        False,
        False,
    )


def test_budget_policy_is_validated() -> None:
    with pytest.raises(ValueError, match="budget_policy"):
        ReportUsageHooks(model="m", budget_policy="later")  # type: ignore[arg-type]
