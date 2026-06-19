"""Tests for strix/core/execution.py — Fix 1: context-window bypass."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
from litellm.exceptions import ContextWindowExceededError

from strix.core.execution import _run_cycle


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _context_window_exc() -> ContextWindowExceededError:
    return ContextWindowExceededError(
        message="prompt is too long: 1023797 tokens > 1000000 maximum",
        model="claude-sonnet-4-6",
        llm_provider="anthropic",
    )


def _make_coordinator() -> AsyncMock:
    coordinator = AsyncMock()
    coordinator.is_shutting_down = False
    return coordinator


async def _empty_events() -> AsyncGenerator[None]:
    """Async generator that yields nothing — simulates a completed stream."""
    for _ in ():
        yield


def _make_stream(exception: Exception | None = None) -> MagicMock:
    stream = MagicMock()
    stream.stream_events.return_value = _empty_events()
    stream.run_loop_exception = exception
    return stream


# ---------------------------------------------------------------------------
# Fix 1 tests
# ---------------------------------------------------------------------------


async def test_context_window_error_sets_status_failed() -> None:
    """ContextWindowExceededError must park the agent as 'failed', not retry."""
    exc = _context_window_exc()
    coordinator = _make_coordinator()

    with (
        patch("strix.core.execution.Runner") as mock_runner,
        patch(
            "strix.core.execution.strip_all_images_from_session", return_value=True
        ) as mock_strip,
    ):
        mock_runner.run_streamed.return_value = _make_stream(exception=exc)

        with pytest.raises(ContextWindowExceededError):
            await _run_cycle(
                MagicMock(),  # agent
                coordinator,
                "agent-001",
                input_data=[],
                run_config=MagicMock(),
                context={},  # no parent_id → will re-raise
                max_turns=10,
                session=AsyncMock(),  # non-None so image-strip guard could trigger
                interactive=True,
                event_sink=None,
                hooks=None,
            )

        # Image-strip must NOT have been attempted.
        mock_strip.assert_not_called()
        # Agent must be parked as failed.
        coordinator.set_status.assert_called_once_with("agent-001", "failed")


async def test_context_window_error_returns_none_for_child_agent() -> None:
    """Child agents (parent_id set) must return None rather than re-raising."""
    exc = _context_window_exc()
    coordinator = _make_coordinator()

    with patch("strix.core.execution.Runner") as mock_runner:
        mock_runner.run_streamed.return_value = _make_stream(exception=exc)

        result = await _run_cycle(
            MagicMock(),
            coordinator,
            "child-001",
            input_data=[],
            run_config=MagicMock(),
            context={"parent_id": "root-001"},
            max_turns=10,
            session=AsyncMock(),
            interactive=True,
            event_sink=None,
            hooks=None,
        )

    assert result is None
    coordinator.set_status.assert_called_once_with("child-001", "failed")


async def test_non_context_window_400_still_triggers_image_strip() -> None:
    """A plain 400 error (not ContextWindowExceededError) must still attempt image stripping."""

    class _Plain400Error(Exception):
        """Minimal stand-in for any non-context-window 400 error."""

        status_code = 400

    plain_400 = _Plain400Error("some other bad request")
    coordinator = _make_coordinator()

    with (
        patch("strix.core.execution.Runner") as mock_runner,
        patch(
            "strix.core.execution.strip_all_images_from_session", return_value=False
        ) as mock_strip,
    ):
        mock_runner.run_streamed.return_value = _make_stream(exception=plain_400)

        # Not interactive → re-raises immediately without retry when strip returns False.
        with pytest.raises(_Plain400Error):
            await _run_cycle(
                MagicMock(),
                coordinator,
                "agent-002",
                input_data=[],
                run_config=MagicMock(),
                context={},
                max_turns=10,
                session=AsyncMock(),
                interactive=False,
                event_sink=None,
                hooks=None,
            )

        # strip WAS attempted (it's the right path for plain 400).
        mock_strip.assert_called_once()
