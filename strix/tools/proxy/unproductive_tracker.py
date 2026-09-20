"""Per-agent circuit breaker on unproductive proxy requests.

This is deliberately independent from the two other guardrails in this
codebase:

- ``strix/core/agents.py``'s budget pause/stop machinery watches the
  *global* dollar spend across the whole scan.
- ``strix/config/tool_call_limits.py``'s ``TurnToolCallLimiter`` bounds how
  many tool calls *one LLM turn* may queue, catching a runaway burst.

Neither catches an agent that spends its budget slowly and "legitimately" —
one well-formed HTTP request at a time, each individually reasonable, that
just keeps landing on 404s or on the same generic error page while guessing
conventional REST paths. A third-party review of Strix (Protego) reproduced
exactly this failure mode: ~1,300 of ~1,350 requests against a live target
were 404s from guessed conventional paths (``/api/qa``) that never found the
real nested route (``/api/qa/questions``), burning ~$17 of budget before any
finding.

This module tracks, per agent, how many *consecutive* proxy requests in a
row have been "non-informative" and returns an actionable warning message
once a threshold is crossed. It never blocks or errors the underlying tool
call — it only adds an extra, ignorable signal the agent can act on next
turn.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass


# Fired every time an agent's consecutive-unproductive-request count crosses
# a multiple of this value (15, 30, 45, ...). 15 is chosen as "clearly past
# ordinary recon noise": a few 404s while probing plausible paths is normal
# and expected pentesting behavior, but 15 in a row with zero new
# information is a strong, low-false-positive signal that the agent is
# fuzzing blind rather than reasoning about the target. Low enough to catch
# the failure mode long before hundreds of dollars are burned, high enough
# not to nag an agent doing legitimate varied probing.
UNPRODUCTIVE_STREAK_THRESHOLD = 15

# A non-404 response shape (status_code, response_body_length) that repeats
# identically this many times *in a row* is treated as non-informative too —
# this catches the "every guessed path returns the same generic HTML error
# page with a 200" variant of blind fuzzing, not just literal 404s. Small
# on purpose: two identical responses could be coincidence (e.g. two
# genuinely empty resources), but three in a row from an agent that is
# supposed to be varying its probes is a real signal.
IDENTICAL_SHAPE_REPEAT_THRESHOLD = 3

STRATEGY_WARNING_TEMPLATE = (
    "[STRATEGY WARNING] {streak} consecutive requests with no new information "
    "(mostly 404s or repeated identical responses guessing conventional paths). "
    "Stop path-guessing. Extract real routes from JS/HTML via the browser tool, "
    "check for an OpenAPI/Swagger spec, or ask the coordinator for the app's "
    "actual route list from recon findings."
)


@dataclass
class _AgentUnproductiveState:
    consecutive_unproductive: int = 0
    last_shape: tuple[int, int] | None = None
    shape_streak: int = 0


_states: dict[str, _AgentUnproductiveState] = {}
_lock = threading.Lock()


def reset_unproductive_tracker() -> None:
    """Clear all per-agent state. Call once per scan start, like the other
    ``hydrate_*_from_disk`` resets in ``strix/core/runner.py`` — this tracker
    is purely in-memory (nothing worth persisting across a resume) but it
    must not leak counters from one scan into the next.
    """
    with _lock:
        _states.clear()


def _is_informative(state: _AgentUnproductiveState, status_code: int, response_length: int) -> bool:
    """Update shape-tracking state and decide if this response was informative.

    Any 2xx is always informative — success responses vary enough (and matter
    enough) that they must never be folded into the "blind fuzzing" bucket
    even if several in a row happen to share a shape (e.g. IDOR testing
    across many valid ids that all return the same shaped 200).
    """
    shape = (status_code, response_length)
    if shape == state.last_shape:
        state.shape_streak += 1
    else:
        state.last_shape = shape
        state.shape_streak = 1

    if 200 <= status_code < 300:
        return True

    if status_code == 404:
        return False

    return state.shape_streak < IDENTICAL_SHAPE_REPEAT_THRESHOLD


def record_response(
    agent_id: str | None, status_code: int | None, response_length: int | None
) -> str | None:
    """Record one proxy response for ``agent_id`` and return a warning to
    surface to the agent, or ``None`` if nothing should be injected.

    Safe to call with ``agent_id=None`` or ``status_code=None`` (e.g. a
    request that errored before any response came back) — these are no-ops
    that neither raise nor advance any streak.
    """
    if not agent_id or status_code is None:
        return None

    length = response_length if isinstance(response_length, int) else 0

    with _lock:
        state = _states.setdefault(agent_id, _AgentUnproductiveState())
        informative = _is_informative(state, status_code, length)

        if informative:
            state.consecutive_unproductive = 0
            return None

        state.consecutive_unproductive += 1
        streak = state.consecutive_unproductive

    if streak % UNPRODUCTIVE_STREAK_THRESHOLD == 0:
        return STRATEGY_WARNING_TEMPLATE.format(streak=streak)
    return None
