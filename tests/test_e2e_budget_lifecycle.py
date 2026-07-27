"""End-to-end budget lifecycle: real coordinator + run loops driven by a fake model.

Exercises the full state machine in-process — root and children running through the
real ``run_agent_loop`` / ``_run_cycle`` / ``_start_child_runner`` code paths with real
SQLite sessions and the real ``ReportUsageHooks`` enforcement, while ``Runner.run_streamed``
is replaced by a fake that charges a fixed cost per model call:

    spend below reserve -> reserve trip (one child) -> single root notice ->
    sibling force-exit without spending -> root finishes gate open ->
    root spends into the cap -> scan-wide budget stop -> everyone stopped.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

from strix.core import execution
from strix.core.agents import AgentCoordinator
from strix.core.execution import _start_child_runner, run_agent_loop
from strix.core.hooks import BudgetExceededError, ReportUsageHooks
from strix.core.sessions import open_agent_session
from strix.tools.finish.tool import _blocking_active_agents


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from pathlib import Path


MAX_BUDGET = 10.0
COST_PER_CALL = 1.0


class _FakeLedger:
    """Stands in for the global ReportState: a mutable cumulative cost counter."""

    def __init__(self) -> None:
        self.cost = 0.0
        self.calls: list[str] = []

    def record_sdk_usage(self, **_kwargs: Any) -> None:
        return

    def get_total_llm_cost(self) -> float:
        return self.cost


class _FakeStream:
    """Minimal stand-in for the SDK's streamed run result.

    Charges the ledger and runs the real ``on_llm_end`` enforcement when consumed,
    surfacing any hook exception through ``run_loop_exception`` exactly like the SDK.
    """

    def __init__(
        self,
        *,
        ledger: _FakeLedger,
        hooks: ReportUsageHooks,
        context: dict[str, Any],
        agent: Any,
    ) -> None:
        self._ledger = ledger
        self._hooks = hooks
        self._context = context
        self._agent = agent
        self.run_loop_exception: BaseException | None = None
        self.final_output = None

    async def stream_events(self) -> AsyncIterator[Any]:
        self._ledger.cost += COST_PER_CALL
        self._ledger.calls.append(str(self._context.get("agent_id")))
        ctx_wrapper = MagicMock()
        ctx_wrapper.context = self._context
        try:
            await self._hooks.on_llm_end(ctx_wrapper, self._agent, MagicMock())
        except Exception as exc:  # noqa: BLE001 - mirrors the SDK surfacing hook errors
            self.run_loop_exception = exc
        items: tuple[Any, ...] = ()  # yields nothing; makes this an async generator
        for item in items:
            yield item

    def cancel(self, mode: str = "immediate") -> None:  # noqa: ARG002
        return


def _fake_runner(ledger: _FakeLedger) -> Any:
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
            return _FakeStream(ledger=ledger, hooks=hooks, context=context, agent=agent)

    return _FakeRunner


async def _noop_compact(*_args: Any, **_kwargs: Any) -> bool:
    return False


async def _wait_until(predicate: Callable[[], bool], *, timeout: float = 5.0) -> None:
    async def _poll() -> None:
        while not predicate():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(_poll(), timeout=timeout)


@pytest.mark.asyncio
async def test_full_budget_lifecycle_reserve_then_cap(  # noqa: PLR0915 - one scenario, asserted end to end
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = _FakeLedger()
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=MAX_BUDGET)
    monkeypatch.setattr(execution, "Runner", _fake_runner(ledger))
    monkeypatch.setattr(execution, "_compact_session", _noop_compact)

    coordinator = AgentCoordinator()
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
        except BaseException as exc:  # captured for assertions
            root_exc.append(exc)
            raise

    with patch("strix.core.hooks.get_global_report_state", return_value=ledger):
        root_task = asyncio.create_task(_root_loop())
        await asyncio.sleep(0.05)  # root parks in wait_for_message

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
        # both children run their initial cycle: 2 calls -> $2.00
        await _wait_until(lambda: ledger.cost >= 2.0)
        reserve_before = coordinator.reserve_stopped
        assert reserve_before is False

        async def _wait_spend_above(amount: float) -> None:
            await _wait_until(lambda: ledger.cost > amount)

        # Alternate "keep working" messages until cumulative spend reaches the 90%
        # reserve ($9.00) on a child's own response.
        turn = 0
        while ledger.cost < MAX_BUDGET * 0.90 - 1e-9:
            target = ("child-a", "child-b")[turn % 2]
            spent_before = ledger.cost
            assert await coordinator.send(target, {"from": "user", "content": "keep going"})
            await _wait_spend_above(spent_before)
            turn += 1

        # --- reserve tripped at exactly $9.00 by a child ------------------------------
        await _wait_until(lambda: coordinator.reserve_stopped)

        # both children settle as stopped; the parked sibling exits WITHOUT spending
        await _wait_until(
            lambda: (
                coordinator.statuses["child-a"] == "stopped"
                and coordinator.statuses["child-b"] == "stopped"
            )
        )

        # the finish_scan active-sibling gate must be open for the root
        assert await _blocking_active_agents(coordinator, "root", None) == []

        # --- root spends the reserved slice and hits the cap --------------------------
        # The reserve notice woke the root; its next cycle charges $1.00 -> $10.00,
        # which is the scan-wide hard stop.
        await _wait_until(lambda: coordinator.budget_stopped)
        assert ledger.cost == pytest.approx(MAX_BUDGET)

        # exact spend sequence: the first 9 calls ($9.00, up to the reserve) are all
        # child calls — the parked root never spends early, and neither child gets a
        # call after the reserve trips; the 10th and final call is the root's.
        assert len(ledger.calls) == 10
        assert set(ledger.calls[:9]) == {"child-a", "child-b"}
        assert ledger.calls[9] == "root"

        # exactly one reserve notice reached the root's session
        root_items = await root_session.get_items()
        notices = [item for item in root_items if "Budget reserve" in str(item)]
        assert len(notices) == 1

        with pytest.raises(BudgetExceededError):
            await root_task
        assert root_exc and isinstance(root_exc[0], BudgetExceededError)

        # terminal state: everyone stopped, no further spend possible
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
    """Resume path: children restarted after the reserve tripped exit without a model call."""
    ledger = _FakeLedger()
    ledger.cost = 9.5  # restored scan already past the reserve
    hooks = ReportUsageHooks(model="test-model", max_budget_usd=MAX_BUDGET)
    monkeypatch.setattr(execution, "Runner", _fake_runner(ledger))
    monkeypatch.setattr(execution, "_compact_session", _noop_compact)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child-a", "recon", parent_id="root")
    snap = await coordinator.snapshot()
    snap["reserve_stopped"] = True

    restored = AgentCoordinator()
    await restored.restore(snap)
    assert restored.reserve_stopped is True

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

    assert ledger.cost == pytest.approx(9.5)  # no paid response happened
    assert ledger.calls == []
    for session in sessions:
        session.close()
