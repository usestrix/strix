"""Strix 2 Phase 5 — progress guards.

Advisory, in-memory detectors that spot a stalled agent (repeated identical tool
calls, or a run of calls with no new coverage) so the caller can nudge or stop it.
Upstream already has a per-turn tool-call cap and budget/turn ceilings; this adds
the missing *cross-turn no-progress* signal without rebuilding those.
"""

from strix.guard.checkpoint import install_sigterm_as_interrupt, restore_sigterm
from strix.guard.progress import NoProgressDetector, ProgressSignal
from strix.guard.stall import (
    StallLimits,
    load_stall_limits,
    noninteractive_recovery_limit,
    transient_retry_budget_exhausted,
)


__all__ = [
    "NoProgressDetector",
    "ProgressSignal",
    "StallLimits",
    "install_sigterm_as_interrupt",
    "load_stall_limits",
    "noninteractive_recovery_limit",
    "restore_sigterm",
    "transient_retry_budget_exhausted",
]
