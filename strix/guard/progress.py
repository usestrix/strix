"""Cross-turn no-progress detection (advisory).

Feed each tool call (and, when available, the run's coverage count) to
:meth:`NoProgressDetector.record`. It returns a :class:`ProgressSignal` when the
agent looks stuck — the same call repeated, or a window of calls with no coverage
growth — and ``None`` otherwise. It is pure and in-memory; the caller decides what
to do with a signal (warn the agent, then stop it). This complements upstream's
per-turn tool-call cap and budget/turn ceilings, which do not catch a cross-turn
loop that stays under those limits.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProgressSignal:
    """A detected stall. ``kind`` is ``repeated_call`` or ``no_coverage``."""

    kind: str
    detail: str
    count: int


def _call_fingerprint(tool_name: str, arguments: Any) -> str:
    try:
        payload = json.dumps(arguments, sort_keys=True, default=str)
    except (TypeError, ValueError):
        payload = repr(arguments)
    return hashlib.sha256(f"{tool_name}\x00{payload}".encode()).hexdigest()


class NoProgressDetector:
    """Flags repeated-identical calls and no-coverage-growth windows.

    Args:
        repeat_threshold: consecutive identical calls that trigger a
            ``repeated_call`` signal (must be ≥ 2).
        stall_window: number of consecutive calls with no coverage growth that
            triggers a ``no_coverage`` signal (must be ≥ 1). Only evaluated when a
            ``coverage_count`` is supplied to :meth:`record`.
    """

    def __init__(self, *, repeat_threshold: int = 3, stall_window: int = 8) -> None:
        self.repeat_threshold = max(2, repeat_threshold)
        self.stall_window = max(1, stall_window)
        self._last_fp: str | None = None
        self._repeat_count = 0
        self._last_coverage: int | None = None
        self._no_growth_streak = 0

    def record(
        self, tool_name: str, arguments: Any = None, *, coverage_count: int | None = None
    ) -> ProgressSignal | None:
        """Record one tool call; return a signal if the agent looks stalled."""
        signal: ProgressSignal | None = None

        fingerprint = _call_fingerprint(tool_name, arguments)
        if fingerprint == self._last_fp:
            self._repeat_count += 1
        else:
            self._last_fp = fingerprint
            self._repeat_count = 1
        if self._repeat_count >= self.repeat_threshold:
            signal = ProgressSignal(
                kind="repeated_call",
                detail=f"{tool_name} repeated with identical arguments {self._repeat_count}x",
                count=self._repeat_count,
            )

        if coverage_count is not None:
            if self._last_coverage is not None and coverage_count <= self._last_coverage:
                self._no_growth_streak += 1
            else:
                self._no_growth_streak = 0
            self._last_coverage = coverage_count
            if signal is None and self._no_growth_streak >= self.stall_window:
                signal = ProgressSignal(
                    kind="no_coverage",
                    detail=(
                        f"{self._no_growth_streak} calls with no new coverage "
                        f"(count stuck at {coverage_count})"
                    ),
                    count=self._no_growth_streak,
                )

        return signal

    def reset(self) -> None:
        """Clear all state (e.g. after nudging the agent, to re-arm the detector)."""
        self._last_fp = None
        self._repeat_count = 0
        self._last_coverage = None
        self._no_growth_streak = 0
