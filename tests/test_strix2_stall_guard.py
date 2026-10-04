"""Tests for the Strix 2 stall caps (empty-recovery limit + transient-retry budget)."""

from __future__ import annotations

import signal
from typing import TYPE_CHECKING

from strix.guard.checkpoint import (
    _NOT_INSTALLED,
    install_sigterm_as_interrupt,
    restore_sigterm,
)
from strix.guard.stall import (
    DEFAULT_MAX_EMPTY_RECOVERIES,
    DEFAULT_TRANSIENT_RETRY_BUDGET_S,
    StallLimits,
    load_stall_limits,
    noninteractive_recovery_limit,
    transient_retry_budget_exhausted,
)


if TYPE_CHECKING:
    import pytest


_LIMITS = StallLimits(max_empty_recoveries=6, transient_retry_budget_s=600.0)


# --- noninteractive_recovery_limit (the empty-output cap) --------------------


def test_recovery_limit_caps_a_large_budget() -> None:
    # The opus failure: max_turns=120 forced 120 empty continuations. Now capped.
    assert noninteractive_recovery_limit(120, _LIMITS) == 6


def test_recovery_limit_never_exceeds_max_turns() -> None:
    assert noninteractive_recovery_limit(3, _LIMITS) == 3
    assert noninteractive_recovery_limit(1, _LIMITS) == 1


def test_recovery_limit_is_at_least_one() -> None:
    assert noninteractive_recovery_limit(0, _LIMITS) == 1


# --- transient_retry_budget_exhausted ----------------------------------------


def test_budget_not_exhausted_under_limit() -> None:
    assert transient_retry_budget_exhausted(100.0, 200.0, _LIMITS) is False


def test_budget_exhausted_when_next_delay_would_exceed() -> None:
    assert transient_retry_budget_exhausted(500.0, 200.0, _LIMITS) is True


def test_budget_boundary_is_inclusive_limit() -> None:
    # Exactly at the budget is allowed; one over is not.
    assert transient_retry_budget_exhausted(400.0, 200.0, _LIMITS) is False
    assert transient_retry_budget_exhausted(400.0, 200.01, _LIMITS) is True


# --- load_stall_limits (env resolution) --------------------------------------


def test_defaults_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX2_MAX_EMPTY_RECOVERIES", raising=False)
    monkeypatch.delenv("STRIX2_TRANSIENT_RETRY_BUDGET_S", raising=False)
    limits = load_stall_limits()
    assert limits.max_empty_recoveries == DEFAULT_MAX_EMPTY_RECOVERIES
    assert limits.transient_retry_budget_s == DEFAULT_TRANSIENT_RETRY_BUDGET_S


def test_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX2_MAX_EMPTY_RECOVERIES", "10")
    monkeypatch.setenv("STRIX2_TRANSIENT_RETRY_BUDGET_S", "120")
    limits = load_stall_limits()
    assert limits.max_empty_recoveries == 10
    assert limits.transient_retry_budget_s == 120.0


def test_invalid_or_nonpositive_env_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX2_MAX_EMPTY_RECOVERIES", "not-a-number")
    monkeypatch.setenv("STRIX2_TRANSIENT_RETRY_BUDGET_S", "-5")
    limits = load_stall_limits()
    assert limits.max_empty_recoveries == DEFAULT_MAX_EMPTY_RECOVERIES
    assert limits.transient_retry_budget_s == DEFAULT_TRANSIENT_RETRY_BUDGET_S


# --- SIGTERM-finalize checkpoint ---------------------------------------------


def test_sigterm_install_routes_to_interrupt_and_restores() -> None:
    before = signal.getsignal(signal.SIGTERM)
    token = install_sigterm_as_interrupt()
    try:
        if token is not _NOT_INSTALLED:
            # SIGTERM now raises KeyboardInterrupt, exactly like Ctrl-C.
            assert signal.getsignal(signal.SIGTERM) is signal.default_int_handler
    finally:
        restore_sigterm(token)
    assert signal.getsignal(signal.SIGTERM) is before


def test_restore_is_noop_on_not_installed_token() -> None:
    restore_sigterm(_NOT_INSTALLED)  # must not raise
