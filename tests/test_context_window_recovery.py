"""Tests for context-window recovery branching in the agent run cycle."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from strix.core.execution import _run_cycle


class ContextWindowExceededError(Exception):
    status_code = 400

    def __init__(self) -> None:
        super().__init__("1,023,797 tokens > 1,000,000 max")


class ImageRejectedError(Exception):
    status_code = 400

    def __init__(self) -> None:
        super().__init__("invalid image content")


class _FailOnceStream:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc
        self.run_loop_exception = None

    async def stream_events(self) -> Any:
        raise self._exc
        yield  # pragma: no cover — force async-generator type for `async for`


@pytest.mark.asyncio
async def test_context_window_error_uses_truncation_not_image_strip() -> None:
    coordinator = MagicMock()
    coordinator.mark_running = AsyncMock()
    coordinator.attach_stream = AsyncMock()
    coordinator.detach_stream = AsyncMock()
    coordinator.set_status = AsyncMock()
    coordinator._lock = AsyncMock()
    coordinator._lock.__aenter__ = AsyncMock(return_value=None)
    coordinator._lock.__aexit__ = AsyncMock(return_value=None)
    coordinator.statuses = {"agent": "running"}
    coordinator.parent_of = {}
    coordinator.names = {"agent": "strix"}
    coordinator.is_shutting_down = False

    session = MagicMock()
    stream1 = _FailOnceStream(ContextWindowExceededError())
    stream2 = MagicMock()
    stream2.run_loop_exception = None

    async def _empty_events() -> Any:
        if False:  # pragma: no cover
            yield None
        return

    stream2.stream_events = _empty_events

    with (
        patch("strix.core.execution.Runner") as runner_cls,
        patch(
            "strix.core.execution.truncate_large_outputs_in_session",
            new_callable=AsyncMock,
            return_value=True,
        ) as trunc,
        patch(
            "strix.core.execution.strip_all_images_from_session",
            new_callable=AsyncMock,
            return_value=True,
        ) as strip,
        patch("strix.core.execution.load_settings") as settings,
    ):
        settings.return_value.runtime.max_tool_output_chars = 65_536
        runner_cls.run_streamed = MagicMock(side_effect=[stream1, stream2])

        result = await _run_cycle(
            agent=MagicMock(),
            coordinator=coordinator,
            agent_id="agent",
            input_data=[],
            run_config=MagicMock(),
            context={"parent_id": None},
            max_turns=10,
            session=session,
            interactive=True,
            event_sink=None,
            hooks=None,
        )

    assert result is stream2
    trunc.assert_awaited()
    strip.assert_not_awaited()


@pytest.mark.asyncio
async def test_image_rejection_still_uses_image_strip() -> None:
    coordinator = MagicMock()
    coordinator.mark_running = AsyncMock()
    coordinator.attach_stream = AsyncMock()
    coordinator.detach_stream = AsyncMock()
    coordinator.set_status = AsyncMock()
    coordinator._lock = AsyncMock()
    coordinator._lock.__aenter__ = AsyncMock(return_value=None)
    coordinator._lock.__aexit__ = AsyncMock(return_value=None)
    coordinator.statuses = {"agent": "running"}
    coordinator.parent_of = {}
    coordinator.names = {"agent": "strix"}
    coordinator.is_shutting_down = False

    session = MagicMock()
    stream1 = _FailOnceStream(ImageRejectedError())
    stream2 = MagicMock()
    stream2.run_loop_exception = None

    async def _empty_events() -> Any:
        if False:  # pragma: no cover
            yield None
        return

    stream2.stream_events = _empty_events

    with (
        patch("strix.core.execution.Runner") as runner_cls,
        patch(
            "strix.core.execution.truncate_large_outputs_in_session",
            new_callable=AsyncMock,
            return_value=False,
        ) as trunc,
        patch(
            "strix.core.execution.strip_all_images_from_session",
            new_callable=AsyncMock,
            return_value=True,
        ) as strip,
        patch("strix.core.execution.load_settings") as settings,
    ):
        settings.return_value.runtime.max_tool_output_chars = 65_536
        runner_cls.run_streamed = MagicMock(side_effect=[stream1, stream2])

        result = await _run_cycle(
            agent=MagicMock(),
            coordinator=coordinator,
            agent_id="agent",
            input_data=[],
            run_config=MagicMock(),
            context={"parent_id": None},
            max_turns=10,
            session=session,
            interactive=True,
            event_sink=None,
            hooks=None,
        )

    assert result is stream2
    # Image rejection is not a context-window error, so truncation path is skipped.
    trunc.assert_not_awaited()
    strip.assert_awaited()
