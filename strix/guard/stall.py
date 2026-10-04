"""Stall caps — bound the two unproductive loops that can burn a whole budget.

Two failure modes seen in real runs on a no-prompt-cache gateway:

* **empty-output loop** — the model returns turns with no lifecycle tool call over
  and over; the recovery nudger forces continuation up to ``max_turns`` (a 120-turn
  budget ground an opus run to ~$63 with zero findings).
* **transient-retry grind** — a persistent provider error (e.g. a rate limit that
  resets in minutes) is retried with growing backoff, cycle after cycle, until the
  host wall-clock cap kills the run with nothing finalized.

These pure helpers let ``core.execution`` cap both so the run aborts early and ends
through its normal terminal path (which finalizes artifacts) instead of grinding.
Defaults are conservative and overridable by env; both are on by default because an
unbounded money-burn is never the desired behavior.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


DEFAULT_MAX_EMPTY_RECOVERIES = 6
DEFAULT_TRANSIENT_RETRY_BUDGET_S = 600.0


@dataclass(frozen=True)
class StallLimits:
    """Caps for the empty-output and transient-retry loops."""

    max_empty_recoveries: int = DEFAULT_MAX_EMPTY_RECOVERIES
    transient_retry_budget_s: float = DEFAULT_TRANSIENT_RETRY_BUDGET_S


def _positive_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _positive_float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def load_stall_limits() -> StallLimits:
    """Resolve the stall caps from env (``STRIX2_MAX_EMPTY_RECOVERIES`` /
    ``STRIX2_TRANSIENT_RETRY_BUDGET_S``), falling back to the defaults."""
    return StallLimits(
        max_empty_recoveries=_positive_int_env(
            "STRIX2_MAX_EMPTY_RECOVERIES", DEFAULT_MAX_EMPTY_RECOVERIES
        ),
        transient_retry_budget_s=_positive_float_env(
            "STRIX2_TRANSIENT_RETRY_BUDGET_S", DEFAULT_TRANSIENT_RETRY_BUDGET_S
        ),
    )


def noninteractive_recovery_limit(max_turns: int, limits: StallLimits) -> int:
    """How many consecutive no-tool-call recoveries a non-interactive run allows.

    Capped at ``max_empty_recoveries`` so a model that emits empty turns cannot force
    continuation for the whole ``max_turns`` budget, but never above ``max_turns``
    itself (a tiny budget stays tiny). A productive turn resets the counter upstream,
    so this only bites a genuine stall.
    """
    return max(1, min(max_turns, limits.max_empty_recoveries))


def transient_retry_budget_exhausted(
    cumulative_delay_s: float, next_delay_s: float, limits: StallLimits
) -> bool:
    """Whether adding ``next_delay_s`` would exceed the transient-retry time budget.

    When True, stop retrying a persistent provider error and let the agent end
    cleanly rather than keep backing off until the host time cap kills the run.
    """
    return (cumulative_delay_s + next_delay_s) > limits.transient_retry_budget_s
