"""Tests for the opt-in cross-turn no-progress guard wired into the run hooks."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from strix.core.hooks import ReportUsageHooks
from strix.guard.hooks import ProgressGuardHooks, build_run_hooks, progress_guard_enabled


if TYPE_CHECKING:
    import pytest


class _Ctx:
    def __init__(self, agent_id: str) -> None:
        self.context: dict[str, Any] = {"agent_id": agent_id, "parent_id": None}


class _Agent:
    def __init__(self, name: str = "tester") -> None:
        self.name = name


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name


def _guard(**kwargs: Any) -> ProgressGuardHooks:
    base: dict[str, Any] = {
        "model": "test-model",
        "max_budget_usd": None,
        "max_turns": None,
        "interactive": False,
    }
    base.update(kwargs)
    return ProgressGuardHooks(**base)


async def _call_tool(hooks: ProgressGuardHooks, ctx: _Ctx, agent: _Agent, tool_name: str) -> None:
    await hooks.on_tool_start(ctx, agent, _Tool(tool_name))  # type: ignore[arg-type]


async def _turn(hooks: ProgressGuardHooks, ctx: _Ctx, agent: _Agent) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    await hooks.on_llm_start(ctx, agent, None, items)  # type: ignore[arg-type]
    return items


# --- factory (opt-in) --------------------------------------------------------

def test_build_run_hooks_plain_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX2_PROGRESS_GUARD", raising=False)
    hooks = build_run_hooks(
        model="m", max_budget_usd=None, max_turns=None, interactive=False
    )
    assert type(hooks) is ReportUsageHooks  # not the guard subclass
    assert not progress_guard_enabled()


def test_build_run_hooks_guard_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX2_PROGRESS_GUARD", "1")
    hooks = build_run_hooks(
        model="m", max_budget_usd=None, max_turns=None, interactive=False
    )
    assert isinstance(hooks, ProgressGuardHooks)
    # Still a ReportUsageHooks: budget extension + usage behavior are preserved.
    assert isinstance(hooks, ReportUsageHooks)
    assert hasattr(hooks, "extend_budget")


# --- nudging behavior --------------------------------------------------------

async def test_repeated_tool_triggers_nudge() -> None:
    hooks = _guard(repeat_threshold=3)
    ctx, agent = _Ctx("a1"), _Agent()
    for _ in range(3):
        await _call_tool(hooks, ctx, agent, "list_candidates")
    items = await _turn(hooks, ctx, agent)
    assert len(items) == 1
    assert "NO-PROGRESS" in items[0]["content"]
    assert items[0]["role"] == "user"


async def test_no_nudge_before_threshold() -> None:
    hooks = _guard(repeat_threshold=3)
    ctx, agent = _Ctx("a1"), _Agent()
    for _ in range(2):
        await _call_tool(hooks, ctx, agent, "list_candidates")
    assert await _turn(hooks, ctx, agent) == []


async def test_alternating_tools_no_nudge() -> None:
    hooks = _guard(repeat_threshold=3)
    ctx, agent = _Ctx("a1"), _Agent()
    for name in ["scan", "read", "scan", "read", "scan", "read"]:
        await _call_tool(hooks, ctx, agent, name)
    assert await _turn(hooks, ctx, agent) == []


async def test_nudges_are_capped_per_agent() -> None:
    hooks = _guard(repeat_threshold=2, max_nudges=2)
    ctx, agent = _Ctx("a1"), _Agent()
    nudges = 0
    for _ in range(10):
        await _call_tool(hooks, ctx, agent, "spin")
        await _call_tool(hooks, ctx, agent, "spin")
        if await _turn(hooks, ctx, agent):
            nudges += 1
    assert nudges == 2  # capped; the guard goes quiet after max_nudges


async def test_final_nudge_advises_wrapping_up() -> None:
    hooks = _guard(repeat_threshold=2, max_nudges=1)
    ctx, agent = _Ctx("a1"), _Agent()
    await _call_tool(hooks, ctx, agent, "spin")
    await _call_tool(hooks, ctx, agent, "spin")
    items = await _turn(hooks, ctx, agent)
    assert "finish_scan" in items[0]["content"]


async def test_agents_tracked_independently() -> None:
    hooks = _guard(repeat_threshold=2)
    agent = _Agent()
    a, b = _Ctx("a1"), _Ctx("b2")
    await _call_tool(hooks, a, agent, "spin")
    await _call_tool(hooks, a, agent, "spin")  # a1 stalls
    await _call_tool(hooks, b, agent, "work")  # b2 made one call only
    assert await _turn(hooks, a, agent)  # a1 gets a nudge
    assert await _turn(hooks, b, agent) == []  # b2 does not


async def test_nudge_cleared_after_delivery() -> None:
    hooks = _guard(repeat_threshold=2, max_nudges=5)
    ctx, agent = _Ctx("a1"), _Agent()
    await _call_tool(hooks, ctx, agent, "spin")
    await _call_tool(hooks, ctx, agent, "spin")
    assert await _turn(hooks, ctx, agent)  # delivered once
    assert await _turn(hooks, ctx, agent) == []  # not re-delivered without a new stall


async def test_observe_never_raises_on_bad_tool() -> None:
    hooks = _guard()
    ctx, agent = _Ctx("a1"), _Agent()
    # A tool object without a name must not break the guard (advisory, best-effort).
    await hooks.on_tool_start(ctx, agent, object())  # type: ignore[arg-type]
    assert await _turn(hooks, ctx, agent) == []
