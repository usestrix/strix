"""Tests for budget enforcement in ReportUsageHooks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from strix.core.hooks import (
    BudgetExceededError,
    NoProgressExceededError,
    ReportUsageHooks,
    ScanLimitError,
)


def _make_hooks(max_budget: float | None) -> ReportUsageHooks:
    return ReportUsageHooks(model="test-model", max_budget_usd=max_budget)


def _make_report_state(cost: float) -> MagicMock:
    state = MagicMock()
    state.get_total_llm_cost.return_value = cost
    state.record_sdk_usage = MagicMock()
    return state


def _make_context(agent_id: str = "test-agent") -> MagicMock:
    ctx: MagicMock = MagicMock()
    ctx.context = {"agent_id": agent_id}
    return ctx


@pytest.mark.asyncio
async def test_no_budget_never_raises() -> None:
    hooks = _make_hooks(None)
    state = _make_report_state(9999.0)
    with patch("strix.core.hooks.get_global_report_state", return_value=state):
        await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())


@pytest.mark.asyncio
async def test_under_budget_does_not_raise() -> None:
    hooks = _make_hooks(10.0)
    state = _make_report_state(9.99)
    with patch("strix.core.hooks.get_global_report_state", return_value=state):
        await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())


@pytest.mark.asyncio
async def test_at_budget_raises() -> None:
    hooks = _make_hooks(10.0)
    state = _make_report_state(10.0)
    with (
        patch("strix.core.hooks.get_global_report_state", return_value=state),
        pytest.raises(BudgetExceededError),
    ):
        await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())


@pytest.mark.asyncio
async def test_over_budget_raises() -> None:
    hooks = _make_hooks(10.0)
    state = _make_report_state(10.01)
    with (
        patch("strix.core.hooks.get_global_report_state", return_value=state),
        pytest.raises(BudgetExceededError),
    ):
        await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())


@pytest.mark.asyncio
async def test_budget_check_uses_live_cost_accessor() -> None:
    # The check must read the live ledger, not the persisted run-record snapshot,
    # so it stays accurate even when a save fails after a usage record.
    hooks = _make_hooks(5.0)
    state = _make_report_state(6.0)
    with (
        patch("strix.core.hooks.get_global_report_state", return_value=state),
        pytest.raises(BudgetExceededError),
    ):
        await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())
    state.get_total_llm_cost.assert_called_once()
    state.get_total_llm_usage.assert_not_called()


@pytest.mark.asyncio
async def test_error_message_includes_amounts() -> None:
    hooks = _make_hooks(5.0)
    state = _make_report_state(7.1234)
    with patch("strix.core.hooks.get_global_report_state", return_value=state):
        with pytest.raises(BudgetExceededError, match=r"\$5\.00") as exc_info:
            await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())
        assert "7.1234" in str(exc_info.value)


@pytest.mark.asyncio
async def test_no_raise_when_report_state_none() -> None:
    hooks = _make_hooks(1.0)
    with patch("strix.core.hooks.get_global_report_state", return_value=None):
        # Should return early without raising, even with budget set
        await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())


@pytest.mark.parametrize("bad_budget", [0.0, -0.01, -5.0])
def test_non_positive_budget_rejected(bad_budget: float) -> None:
    with pytest.raises(ValueError, match="greater than 0"):
        ReportUsageHooks(model="test-model", max_budget_usd=bad_budget)


def test_budget_exceeded_error_is_runtime_error() -> None:
    err = BudgetExceededError("test")
    assert isinstance(err, RuntimeError)


# ---------------------------------------------------------------------------
# No-progress circuit breaker
# ---------------------------------------------------------------------------


def _make_state_with_counts(*, findings: int, cost: float = 0.0) -> MagicMock:
    state = MagicMock()
    state.get_total_llm_cost.return_value = cost
    state.record_sdk_usage = MagicMock()
    # Real list so len() works inside _check_no_progress.
    state.vulnerability_reports = [object() for _ in range(findings)]
    return state


async def _calls_until_no_progress(
    hooks: ReportUsageHooks,
    *,
    findings: int,
    notes: int,
    max_calls: int = 30,
) -> int | None:
    """Return the 1-based on_llm_end call index that raised, or None."""
    state = _make_state_with_counts(findings=findings)
    with (
        patch("strix.core.hooks.get_global_report_state", return_value=state),
        patch("strix.core.hooks.notes_count", return_value=notes),
    ):
        for i in range(1, max_calls + 1):
            try:
                await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())
            except NoProgressExceededError:
                return i
    return None


@pytest.mark.asyncio
async def test_no_progress_trips_after_threshold() -> None:
    # threshold=3, counts frozen: baseline taken on call 1 (no count),
    # then 3 stale turns -> raises on call 4.
    hooks = ReportUsageHooks(model="m", no_progress_max_turns=3)
    raised_at = await _calls_until_no_progress(hooks, findings=1, notes=2)
    assert raised_at == 4


@pytest.mark.asyncio
async def test_no_progress_resets_on_new_finding() -> None:
    # Findings increase every turn -> counter always resets -> never trips.
    hooks = ReportUsageHooks(model="m", no_progress_max_turns=3)
    with (
        patch("strix.core.hooks.get_global_report_state") as gs,
        patch("strix.core.hooks.notes_count", return_value=0),
    ):
        gs.return_value = _make_state_with_counts(findings=0)
        # Simulate growing findings by swapping the report state each call.
        for turn in range(6):
            gs.return_value = _make_state_with_counts(findings=turn + 1)
            await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())


@pytest.mark.asyncio
async def test_no_progress_trips_on_note_count_too() -> None:
    # Notes frozen while findings frozen -> still trips.
    hooks = ReportUsageHooks(model="m", no_progress_max_turns=2)
    raised_at = await _calls_until_no_progress(hooks, findings=0, notes=5)
    assert raised_at == 3


@pytest.mark.asyncio
async def test_no_progress_disabled_when_none() -> None:
    hooks = ReportUsageHooks(model="m", no_progress_max_turns=None)
    raised_at = await _calls_until_no_progress(hooks, findings=0, notes=0, max_calls=10)
    assert raised_at is None


@pytest.mark.parametrize("bad", [0, -1, -5])
def test_no_progress_non_positive_rejected(bad: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        ReportUsageHooks(model="m", no_progress_max_turns=bad)


def test_no_progress_error_hierarchy() -> None:
    err = NoProgressExceededError("stuck")
    assert isinstance(err, ScanLimitError)
    assert isinstance(err, RuntimeError)
    # BudgetExceededError and NoProgressExceededError share the ScanLimitError base.
    assert issubclass(BudgetExceededError, ScanLimitError)
    assert issubclass(NoProgressExceededError, ScanLimitError)


@pytest.mark.asyncio
async def test_no_progress_message_includes_counts() -> None:
    hooks = ReportUsageHooks(model="m", no_progress_max_turns=1)
    state = _make_state_with_counts(findings=2)
    with (
        patch("strix.core.hooks.get_global_report_state", return_value=state),
        patch("strix.core.hooks.notes_count", return_value=3),
        pytest.raises(NoProgressExceededError, match=r"findings=2.*notes=3"),
    ):
        # call 1: baseline; call 2: stale -> trips (threshold=1).
        await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())
        await hooks.on_llm_end(_make_context(), MagicMock(), MagicMock())
