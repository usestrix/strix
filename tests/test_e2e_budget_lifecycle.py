from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

from strix.core import execution
from strix.core.agents import AgentCoordinator, WaitKind
from strix.core.execution import _start_child_runner, run_agent_loop
from strix.core.hooks import BudgetExceededError, ReportUsageHooks
from strix.core.sessions import open_agent_session


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path


MAX_BUDGET = 10.0
COST_PER_CALL = 1.0


class _FakeLedger:
    def __init__(self) -> None:
        self.cost = 0.0
        self.calls: list[str] = []

    def record_sdk_usage(self, **_kwargs: Any) -> None:
        return

    def get_total_llm_cost(self) -> float:
        return self.cost


class _FakeStream:
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
        self._ledger.cost += COST_PER_CALL
        self._ledger.calls.append(agent_id)
        ctx_wrapper = MagicMock()
        ctx_wrapper.context = self._context
        try:
            await self._hooks.on_llm_end(ctx_wrapper, self._agent, MagicMock())
        except Exception as exc:  # noqa: BLE001
            self.run_loop_exception = exc
        # Stand in for the explicit yield tool a real turn ends with. Without it
        # every turn looks like a forgotten tool call and burns the recovery
        # budget, which is a different scenario from the one under test here.
        if self._coordinator.statuses.get(agent_id) == "running":
            wait_kind: WaitKind = "user" if self._context.get("parent_id") is None else "agents"
            await self._coordinator.park_waiting(agent_id, wait_kind=wait_kind)
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
            await asyncio.sleep(0.01)

    await asyncio.wait_for(_poll(), timeout=timeout)


@pytest.mark.asyncio
async def test_full_budget_lifecycle_reserve_then_cap(  # noqa: PLR0915
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = _FakeLedger()
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=MAX_BUDGET)
    coordinator = AgentCoordinator()
    monkeypatch.setattr(execution, "Runner", _fake_runner(ledger, coordinator))
    monkeypatch.setattr(execution, "_compact_session", _noop_compact)

    db_path = tmp_path / "agents.sqlite"
    sessions: list[Any] = []
    run_config = MagicMock()

    await coordinator.register("root", "strix", parent_id=None)
    root_session = open_agent_session("root", db_path)
    sessions.append(root_session)

    root_exc: list[BaseException] = []

    async def _root_loop() -> None:
        try:
            await run_agent_loop(
                agent=MagicMock(),
                initial_input=[],
                run_config=run_config,
                context={"agent_id": "root", "parent_id": None},
                max_turns=500,
                coordinator=coordinator,
                agent_id="root",
                interactive=True,
                session=root_session,
                start_parked=True,
                hooks=hooks,
            )
        except BaseException as exc:
            root_exc.append(exc)
            raise

    with patch("strix.core.hooks.get_global_report_state", return_value=ledger):
        root_task = asyncio.create_task(_root_loop())
        await asyncio.sleep(0.05)

        for child_id in ("child-a", "child-b"):
            await coordinator.register(child_id, "recon", parent_id="root")
            await _start_child_runner(
                parent_ctx={"agent_id": "root", "parent_id": None},
                coordinator=coordinator,
                agents_db_path=db_path,
                sessions_to_close=sessions,
                run_config=run_config,
                max_turns=500,
                interactive=True,
                child_agent=MagicMock(),
                child_id=child_id,
                name=f"recon-{child_id}",
                parent_id="root",
                task="probe things",
                initial_input=[],
                hooks=hooks,
            )
        await _wait_until(lambda: ledger.cost >= 2.0)
        reserve_before = coordinator.reserve_stopped
        assert reserve_before is False

        async def _wait_spend_above(amount: float) -> None:
            await _wait_until(lambda: ledger.cost > amount)

        turn = 0
        while ledger.cost < MAX_BUDGET * 0.90 - 1e-9:
            target = ("child-a", "child-b")[turn % 2]
            spent_before = ledger.cost
            assert await coordinator.send(target, {"from": "user", "content": "keep going"})
            await _wait_spend_above(spent_before)
            turn += 1

        await _wait_until(lambda: coordinator.reserve_stopped)

        await _wait_until(
            lambda: (
                coordinator.statuses["child-a"] == "stopped"
                and coordinator.statuses["child-b"] == "stopped"
            )
        )

        assert coordinator.reserve_stopped is True

        await _wait_until(lambda: coordinator.budget_stopped)
        assert ledger.cost == pytest.approx(MAX_BUDGET)

        assert len(ledger.calls) == 10
        assert set(ledger.calls[:9]) == {"child-a", "child-b"}
        assert ledger.calls[9] == "root"

        root_items = await root_session.get_items()
        notices = [item for item in root_items if "Budget reserve" in str(item)]
        assert len(notices) == 1

        with pytest.raises(BudgetExceededError):
            await root_task
        assert root_exc and isinstance(root_exc[0], BudgetExceededError)

        assert {aid: str(status) for aid, status in coordinator.statuses.items()} == {
            "root": "stopped",
            "child-a": "stopped",
            "child-b": "stopped",
        }
        assert coordinator.budget_stopped is True
        assert coordinator.reserve_stopped is True

    for session in sessions:
        session.close()


@pytest.mark.asyncio
async def test_respawned_children_after_reserve_never_spend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = _FakeLedger()
    ledger.cost = 9.5
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=MAX_BUDGET)
    monkeypatch.setattr(execution, "_compact_session", _noop_compact)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child-a", "recon", parent_id="root")
    snap = await coordinator.snapshot()
    snap["reserve_stopped"] = True

    restored = AgentCoordinator()
    await restored.restore(snap)
    assert restored.reserve_stopped is True
    monkeypatch.setattr(execution, "Runner", _fake_runner(ledger, restored))

    sessions: list[Any] = []
    with patch("strix.core.hooks.get_global_report_state", return_value=ledger):
        await _start_child_runner(
            parent_ctx={"agent_id": "root", "parent_id": None},
            coordinator=restored,
            agents_db_path=tmp_path / "agents.sqlite",
            sessions_to_close=sessions,
            run_config=MagicMock(),
            max_turns=500,
            interactive=True,
            child_agent=MagicMock(),
            child_id="child-a",
            name="recon-child-a",
            parent_id="root",
            task="probe things",
            initial_input=[],
            hooks=hooks,
        )
        await _wait_until(lambda: restored.statuses["child-a"] == "stopped")

    assert ledger.cost == pytest.approx(9.5)
    assert ledger.calls == []
    for session in sessions:
        session.close()


@pytest.mark.asyncio
async def test_resumed_parked_root_after_reserve_is_renotified_and_finalizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = _FakeLedger()
    ledger.cost = 9.0
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=MAX_BUDGET)
    monkeypatch.setattr(execution, "_compact_session", _noop_compact)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.set_status("root", "waiting")
    snap = await coordinator.snapshot()
    snap["reserve_stopped"] = True

    restored = AgentCoordinator()
    await restored.restore(snap)
    assert restored.reserve_stopped is True
    monkeypatch.setattr(execution, "Runner", _fake_runner(ledger, restored))

    root_session = open_agent_session("root", tmp_path / "agents.sqlite")
    with patch("strix.core.hooks.get_global_report_state", return_value=ledger):
        root_task = asyncio.create_task(
            run_agent_loop(
                agent=MagicMock(),
                initial_input=[],
                run_config=MagicMock(),
                context={"agent_id": "root", "parent_id": None},
                max_turns=500,
                coordinator=restored,
                agent_id="root",
                interactive=True,
                session=root_session,
                start_parked=True,
                hooks=hooks,
            )
        )
        with pytest.raises(BudgetExceededError):
            await asyncio.wait_for(root_task, timeout=5.0)

    assert ledger.calls == ["root"]
    assert ledger.cost == pytest.approx(MAX_BUDGET)
    root_items = await root_session.get_items()
    notices = [item for item in root_items if "Budget reserve" in str(item)]
    assert len(notices) == 1
    root_session.close()


@pytest.mark.asyncio
async def test_interactive_budget_pause_then_user_message_extends_and_resumes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = _FakeLedger()
    ledger.cost = 9.0
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=MAX_BUDGET, interactive=True)
    coordinator = AgentCoordinator()
    monkeypatch.setattr(execution, "Runner", _fake_runner(ledger, coordinator))
    monkeypatch.setattr(execution, "_compact_session", _noop_compact)

    coordinator.set_budget_extender(hooks.extend_budget)
    await coordinator.register("root", "strix", parent_id=None)
    root_session = open_agent_session("root", tmp_path / "agents.sqlite")

    with patch("strix.core.hooks.get_global_report_state", return_value=ledger):
        root_task = asyncio.create_task(
            run_agent_loop(
                agent=MagicMock(),
                initial_input=[],
                run_config=MagicMock(),
                context={"agent_id": "root", "parent_id": None},
                max_turns=500,
                coordinator=coordinator,
                agent_id="root",
                interactive=True,
                session=root_session,
                start_parked=True,
                hooks=hooks,
            )
        )
        await asyncio.sleep(0.05)

        assert await coordinator.send("root", {"from": "user", "content": "go"})
        await _wait_until(lambda: coordinator.budget_paused)
        assert coordinator.statuses["root"] == "budget_paused"
        assert ledger.cost == pytest.approx(MAX_BUDGET)
        assert not root_task.done()
        assert coordinator.budget_stopped is False

        assert await coordinator.send("root", {"from": "user", "content": "keep going"})
        await _wait_until(lambda: not coordinator.budget_paused)
        await _wait_until(lambda: ledger.cost > MAX_BUDGET)
        await _wait_until(lambda: coordinator.statuses["root"] == "waiting")
        assert not root_task.done()

        root_task.cancel()
        await root_task

    root_session.close()
