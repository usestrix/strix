"""Tests for the per-agent unproductive-request circuit breaker.

Covers the tracker in isolation (``strix.tools.proxy.unproductive_tracker``)
and its wiring into ``repeat_request``'s response formatting
(``strix.tools.proxy.tools._format_replay_tool_result``).
"""

from __future__ import annotations

import json

import pytest

from strix.tools.proxy import tools
from strix.tools.proxy.unproductive_tracker import (
    UNPRODUCTIVE_STREAK_THRESHOLD,
    record_response,
    reset_unproductive_tracker,
)


@pytest.fixture(autouse=True)
def _reset() -> None:
    reset_unproductive_tracker()


def test_consecutive_404s_past_threshold_triggers_warning() -> None:
    warning = None
    for _ in range(UNPRODUCTIVE_STREAK_THRESHOLD):
        warning = record_response("agent-1", 404, 128)

    assert warning is not None
    assert "STRATEGY WARNING" in warning
    assert str(UNPRODUCTIVE_STREAK_THRESHOLD) in warning


def test_no_warning_before_threshold_reached() -> None:
    for _ in range(UNPRODUCTIVE_STREAK_THRESHOLD - 1):
        assert record_response("agent-1", 404, 128) is None


def test_2xx_response_resets_the_streak() -> None:
    for _ in range(UNPRODUCTIVE_STREAK_THRESHOLD - 1):
        assert record_response("agent-1", 404, 128) is None

    # One success in the middle of a near-threshold 404 run must clear it.
    assert record_response("agent-1", 200, 512) is None

    for _ in range(UNPRODUCTIVE_STREAK_THRESHOLD - 1):
        assert record_response("agent-1", 404, 128) is None


def test_repeated_identical_shape_counts_as_unproductive_even_without_404() -> None:
    # Every guessed path comes back 200 with the exact same generic body —
    # no literal 404s, but still zero new information after a few repeats.
    warning = None
    for _ in range(UNPRODUCTIVE_STREAK_THRESHOLD + 2):
        # Route through a 3xx/4xx-adjacent non-2xx status so the "always
        # informative" 2xx override doesn't mask the identical-shape check.
        warning = record_response("agent-1", 500, 999)

    assert warning is not None


def test_varied_shapes_never_trigger_the_warning() -> None:
    # Legitimate varied recon: different status/length every time.
    for i in range(UNPRODUCTIVE_STREAK_THRESHOLD * 2):
        warning = record_response("agent-1", 401, 100 + i)
        assert warning is None


def test_different_agents_do_not_interfere() -> None:
    for _ in range(UNPRODUCTIVE_STREAK_THRESHOLD - 1):
        assert record_response("agent-a", 404, 128) is None
        assert record_response("agent-b", 404, 128) is None

    # agent-a crosses the threshold; agent-b, one request behind, must not.
    assert record_response("agent-a", 404, 128) is not None
    assert record_response("agent-b", 200, 128) is None


def test_warning_does_not_refire_immediately_after_firing() -> None:
    fired_at: list[int] = []
    for i in range(1, UNPRODUCTIVE_STREAK_THRESHOLD * 2 + 1):
        warning = record_response("agent-1", 404, 128)
        if warning is not None:
            fired_at.append(i)

    assert fired_at == [UNPRODUCTIVE_STREAK_THRESHOLD, UNPRODUCTIVE_STREAK_THRESHOLD * 2]


def test_missing_agent_id_or_status_is_a_no_op() -> None:
    assert record_response(None, 404, 128) is None
    assert record_response("agent-1", None, 128) is None


def test_format_replay_tool_result_injects_warning_field_at_threshold() -> None:
    replay = {
        "status": "DONE",
        "session_id": "sess-1",
        "elapsed_ms": 12,
        "error": None,
        "response_raw": b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nabc",
    }

    payload = None
    for _ in range(UNPRODUCTIVE_STREAK_THRESHOLD):
        payload = json.loads(tools._format_replay_tool_result(replay, agent_id="agent-x"))

    assert payload is not None
    assert "strategy_warning" in payload
    assert "STRATEGY WARNING" in payload["strategy_warning"]


def test_format_replay_tool_result_has_no_warning_field_by_default() -> None:
    replay = {
        "status": "DONE",
        "session_id": "sess-1",
        "elapsed_ms": 12,
        "error": None,
        "response_raw": b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
    }

    payload = json.loads(tools._format_replay_tool_result(replay, agent_id="agent-x"))
    assert "strategy_warning" not in payload
