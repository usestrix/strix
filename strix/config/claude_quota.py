"""Subscription usage-limit gate for the Claude Code backend.

A Claude Pro/Max subscription has a 5-hour and a 7-day usage window. When one
is spent, every ``claude -p`` turn fails at once with "You've hit your session
limit · resets 12:30pm (Europe/London)" and no status code, until the window
resets. A deep scan runs for hours and fans out to many agents, so it reaches
the limit in normal use. Before this gate each failed turn took the statusless
retry path, five attempts over about three minutes, and then crashed its agent.
One run logged 127 limit hits and filed nothing.

The gate turns the limit into a wait. The first turn that is refused closes the
gate until the reset time the CLI reports. Every turn then waits before it
spawns a process, and the refused turn is sent again unchanged when the gate
opens. The agents see a slow turn, not an error, so the conversation and the
scan state are unchanged.

The reset time comes from the ``rate_limit_event`` that ``--verbose``
stream-json output carries on every turn::

    {"type": "rate_limit_event", "rate_limit_info": {"status": "rejected",
     "resetsAt": 1792698000, "rateLimitType": "five_hour", ...,
     "unifiedWindows": {"five_hour": {"utilization": 1.0, "resetsAt": ...},
                        "seven_day": {"utilization": 0.4, "resetsAt": ...}}}}

The refusal text is the fallback when the event is missing.

Knobs:

``STRIX_CLAUDE_CODE_QUOTA_MAX_WAIT``
    Longest wait, in seconds, for one closure. Default eight days, so a weekly
    reset is covered. ``0`` turns waiting off: a refused turn then fails at
    once with a non-retryable error instead of using up the retry budget.
``STRIX_CLAUDE_CODE_QUOTA_CEILING``
    A utilization fraction, for example ``0.85``. When a turn reports a window
    at or above it, the gate closes until that window resets, before the limit
    is reached. This keeps headroom on an account that a person also uses.
    Unset by default.

Time is wall-clock time. The wait sleeps in short steps and checks
``time.time()`` each step, because a monotonic sleep does not advance while a
laptop sleeps and would wake hours after the reset.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import logging
import math
import os
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from strix.config import claude_code
from strix.config.claude_bridge import RATE_LIMIT_KEY


if TYPE_CHECKING:
    from collections.abc import Iterator


logger = logging.getLogger(__name__)

_DEFAULT_MAX_WAIT_S = 8 * 24 * 3600
# Wait this long past the reported reset before the first retry. The reset is
# reported to the second, but the clocks of this host and the limiter differ.
_RESET_MARGIN_S = 30.0
# The wait when a refusal gives no usable reset time. The retry is cheap (the
# CLI refuses in about a second and spends nothing), so a short wait is safe.
_UNKNOWN_RESET_WAIT_S = 15 * 60
# Longest single sleep, so a wall-clock jump (host sleep, NTP) is seen soon.
_SLEEP_STEP_S = 30.0

# Phrases of a refused turn. Observed: "You've hit your session limit · resets
# 12:30pm (Europe/London)". Older releases said "Claude AI usage limit
# reached|<epoch>". The rest are in the 2.1.308 binary.
_REFUSAL_MARKERS = (
    "hit your session limit",
    "hit your weekly limit",
    "hit your limit",
    "hit your opus limit",
    "usage limit reached",
    "reached your weekly usage limit",
)
_RESETS_RE = re.compile(
    r"resets\s+(?:(?P<date>[A-Z][a-z]{2,8}\s+\d{1,2}),?\s*(?:at\s+)?)?"
    r"(?P<hour>\d{1,2})(?::(?P<minute>\d{2}))?\s*(?P<ampm>am|pm)"
    r"(?:\s*\((?P<tz>[A-Za-z_]+(?:/[A-Za-z_+\-]+)*)\))?",
    re.IGNORECASE,
)
_EPOCH_RE = re.compile(r"usage limit reached\|(?P<epoch>\d{9,11})", re.IGNORECASE)


class QuotaExhaustedError(claude_code.ClaudeCodeError):
    """A turn was refused by the subscription's usage limit and waiting is off.

    Not retryable: a retry before the reset is refused again at once.
    """

    def __init__(self, message: str, *, resets_at: float | None) -> None:
        super().__init__(message, retryable=False)
        self.resets_at = resets_at


def describe_exhaustion(resets_at: float | None) -> str:
    """A clear, actionable one-liner for a spent subscription window.

    Used where Strix fails fast rather than waiting (e.g. the interactive TUI
    setup screen): it names the reset time in the local zone when known and
    points the user at the headless wait path for an unattended scan.
    """
    if resets_at is not None:
        when = datetime.fromtimestamp(resets_at).astimezone().strftime("%Y-%m-%d %H:%M %Z")
        window = f"the usage window resets at {when}"
    else:
        window = "the usage window will reset shortly"
    return (
        f"Claude subscription usage limit reached — {window}. Re-run once it resets. "
        "For an unattended scan that waits out the window instead, run headless "
        "(STRIX_CLAUDE_CODE_QUOTA_MAX_WAIT controls the wait)."
    )


@dataclass(frozen=True)
class Refusal:
    """A turn refused by the usage limit."""

    message: str
    resets_at: float | None
    window: str | None


def _finite(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    return number if math.isfinite(number) and number > 0 else None


def _env_float(name: str) -> float | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        logger.warning("%s=%r is not a number; ignoring it", name, raw)
        return None
    return value if math.isfinite(value) else None


def max_wait() -> float:
    """Longest wait for one closure in seconds; 0 means waiting is off."""
    value = _env_float("STRIX_CLAUDE_CODE_QUOTA_MAX_WAIT")
    if value is None:
        return float(_DEFAULT_MAX_WAIT_S)
    return max(0.0, value)


def ceiling() -> float | None:
    """The utilization fraction that closes the gate early, or None."""
    value = _env_float("STRIX_CLAUDE_CODE_QUOTA_CEILING")
    if value is None or value <= 0 or value >= 1:
        if value is not None:
            logger.warning(
                "STRIX_CLAUDE_CODE_QUOTA_CEILING=%s is outside (0, 1); ignoring it", value
            )
        return None
    return value


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #


def _info(result: dict[str, Any]) -> dict[str, Any]:
    raw = result.get(RATE_LIMIT_KEY)
    return cast("dict[str, Any]", raw) if isinstance(raw, dict) else {}


def _text(result: dict[str, Any]) -> str:
    raw = result.get("result")
    return raw if isinstance(raw, str) else ""


def parse_reset_text(text: str, *, now: datetime | None = None) -> float | None:
    """The reset time in a refusal message as a Unix time, or None.

    Reads "resets 12:30pm (Europe/London)", "resets 4am", "resets Oct 25, 4am
    (Europe/London)" and the older "usage limit reached|<epoch>". A time with
    no date is the next time it occurs. A message with no zone is read in the
    local zone, which is the zone the CLI prints it in.
    """
    epoch = _EPOCH_RE.search(text)
    if epoch:
        return _finite(int(epoch.group("epoch")))
    match = _RESETS_RE.search(text)
    if match is None:
        return None
    zone: Any = None
    if match.group("tz"):
        with contextlib.suppress(ZoneInfoNotFoundError, ValueError):
            zone = ZoneInfo(match.group("tz"))
    current = (now or datetime.now(UTC)).astimezone(zone)
    hour = int(match.group("hour")) % 12 + (12 if match.group("ampm").lower() == "pm" else 0)
    minute = int(match.group("minute") or 0)
    if minute > 59:
        return None
    if match.group("date"):
        try:
            day = datetime.strptime(  # noqa: DTZ007 - the zone is attached below
                f"{match.group('date')} {current.year}", "%b %d %Y"
            )
        except ValueError:
            try:
                day = datetime.strptime(  # noqa: DTZ007
                    f"{match.group('date')} {current.year}", "%B %d %Y"
                )
            except ValueError:
                return None
        candidate = current.replace(
            month=day.month, day=day.day, hour=hour, minute=minute, second=0, microsecond=0
        )
        if candidate < current - timedelta(days=1):
            # "Jan 2" read in late December is next year.
            candidate = candidate.replace(year=current.year + 1)
        return candidate.timestamp()
    candidate = current.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= current:
        candidate += timedelta(days=1)
    return candidate.timestamp()


def refusal(result: dict[str, Any]) -> Refusal | None:
    """The usage-limit refusal in a finished turn's result event, or None.

    Only an error result counts. A ``rejected`` status beside a successful
    result is a turn that was served anyway (overage, or a race at the reset).
    """
    if not result.get("is_error"):
        return None
    info = _info(result)
    text = _text(result)
    lowered = text.lower()
    rejected = str(info.get("status") or "").lower() == "rejected"
    if not rejected and not any(marker in lowered for marker in _REFUSAL_MARKERS):
        return None
    resets_at = _finite(info.get("resetsAt")) if rejected else None
    if resets_at is None:
        resets_at = parse_reset_text(text)
    window = info.get("rateLimitType")
    return Refusal(
        message=text or "usage limit reached",
        resets_at=resets_at,
        window=str(window) if window else None,
    )


def over_ceiling(result: dict[str, Any], limit: float) -> tuple[str, float] | None:
    """The window at or above ``limit``, with its reset time, that resets last."""
    windows = _info(result).get("unifiedWindows")
    if not isinstance(windows, dict):
        return None
    worst: tuple[str, float] | None = None
    for name, raw in cast("dict[str, Any]", windows).items():
        if not isinstance(raw, dict):
            continue
        window = cast("dict[str, Any]", raw)
        used = _finite(window.get("utilization"))
        resets_at = _finite(window.get("resetsAt"))
        if used is None or resets_at is None or used < limit:
            continue
        if worst is None or resets_at > worst[1]:
            worst = (str(name), resets_at)
    return worst


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #


def _describe(when: float) -> str:
    local = datetime.fromtimestamp(when).astimezone()
    remaining = max(0, int(when - time.time()))
    hours, rest = divmod(remaining, 3600)
    return f"{local:%Y-%m-%d %H:%M %Z} (in {hours}h{rest // 60:02d}m)"


class QuotaGate:
    """Process-wide closure state. Plain attributes, no asyncio primitives.

    No event or lock here: Strix runs a warm-up event loop and then a separate
    scan loop, and an asyncio primitive binds to the first loop that waits on it.
    Waiters poll the wall clock instead, which the host-sleep case needs anyway.
    """

    def __init__(self) -> None:
        self._until: float = 0.0
        self._reason: str = ""
        self._closures = 0

    @property
    def until(self) -> float:
        return self._until

    @property
    def closures(self) -> int:
        return self._closures

    def is_closed(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) < self._until

    def close(self, until: float, reason: str) -> None:
        """Close the gate until ``until``; a later reset already set wins."""
        if until <= self._until:
            return
        was_closed = self.is_closed()
        self._until = until
        self._reason = reason
        if not was_closed:
            self._closures += 1
        logger.warning(
            "Claude subscription usage limit: %s. Pausing every claude -p turn until %s; "
            "the scan continues after the reset.",
            reason,
            _describe(until),
        )

    def close_for_refusal(self, refused: Refusal, *, now: float | None = None) -> float:
        """Close the gate for a refused turn and return the time it opens."""
        current = now if now is not None else time.time()
        if refused.resets_at is not None and refused.resets_at > current:
            until = refused.resets_at + _RESET_MARGIN_S
        else:
            # No reset time, or one already past: the window turned over between
            # the refusal and now, or the clocks disagree. Retry soon.
            until = current + (_UNKNOWN_RESET_WAIT_S if refused.resets_at is None else 60.0)
        window = f"{refused.window} window" if refused.window else "limit"
        self.close(until, f"{window} reached ({refused.message.strip()})")
        return until

    def observe(self, result: dict[str, Any]) -> None:
        """Close the gate early when a turn reports a window over the ceiling."""
        limit = ceiling()
        if limit is None:
            return
        hit = over_ceiling(result, limit)
        if hit is not None:
            name, resets_at = hit
            if resets_at > time.time():
                self.close(
                    resets_at + _RESET_MARGIN_S,
                    f"{name} window at or above the {limit:.0%} ceiling",
                )

    async def wait(self) -> None:
        """Return once the gate is open. Cancellation-safe; holds nothing."""
        while True:
            remaining = self._until - time.time()
            if remaining <= 0:
                return
            await asyncio.sleep(min(_SLEEP_STEP_S, remaining))

    def reset(self) -> None:
        self._until = 0.0
        self._reason = ""
        self._closures = 0


GATE = QuotaGate()

# False inside the scan preflight: a refused preflight must surface at once so
# the warm-up can say why it is waiting, instead of timing out silently.
_waiting_enabled: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "strix_claude_quota_waiting", default=True
)


@contextlib.contextmanager
def no_waiting() -> Iterator[None]:
    """Within this block a refused turn raises :class:`QuotaExhaustedError`."""
    token = _waiting_enabled.set(False)
    try:
        yield
    finally:
        _waiting_enabled.reset(token)


def waiting_enabled() -> bool:
    return _waiting_enabled.get() and max_wait() > 0


def exhausted_error(refused: Refusal) -> QuotaExhaustedError:
    when = f" It resets at {_describe(refused.resets_at)}." if refused.resets_at else ""
    return QuotaExhaustedError(
        f"Claude subscription usage limit reached: {refused.message.strip()}.{when}",
        resets_at=refused.resets_at,
    )


def check_wait_allowed(until: float, waited_since: float) -> None:
    """Raise when waiting until ``until`` would exceed the configured maximum.

    ``waited_since`` is when this turn was first refused, so repeated refusals
    with no usable reset time cannot wait forever in short steps.
    """
    limit = max_wait()
    if until - waited_since > limit:
        raise QuotaExhaustedError(
            f"Claude subscription usage limit: the reset at {_describe(until)} is beyond "
            f"STRIX_CLAUDE_CODE_QUOTA_MAX_WAIT ({limit:.0f}s). Stopping; resume the run "
            "after the reset with --resume.",
            resets_at=until,
        )


__all__ = [
    "GATE",
    "RATE_LIMIT_KEY",
    "QuotaExhaustedError",
    "QuotaGate",
    "Refusal",
    "ceiling",
    "check_wait_allowed",
    "exhausted_error",
    "max_wait",
    "no_waiting",
    "over_ceiling",
    "parse_reset_text",
    "refusal",
    "waiting_enabled",
]
