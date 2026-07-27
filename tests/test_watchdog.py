"""Tests for the scan event-loop watchdog."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import pytest

from strix.core.watchdog import LoopWatchdog


if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.asyncio
async def test_watchdog_quiet_when_loop_is_healthy(tmp_path: Path) -> None:
    stall_path = tmp_path / "loop-stalls.txt"
    watchdog = LoopWatchdog(stall_path=stall_path, stall_seconds=0.5, beat_interval=0.05)
    watchdog.start()
    await asyncio.sleep(0.3)
    await watchdog.stop()

    assert not stall_path.exists()


@pytest.mark.asyncio
async def test_watchdog_dumps_stacks_when_loop_wedges(tmp_path: Path) -> None:
    stall_path = tmp_path / "loop-stalls.txt"
    watchdog = LoopWatchdog(stall_path=stall_path, stall_seconds=0.3, beat_interval=0.05)
    watchdog.start()
    await asyncio.sleep(0.1)
    # Block the loop thread so the heartbeat stops advancing; the off-loop monitor
    # thread must notice and dump every thread's stack.
    time.sleep(0.7)
    await watchdog.stop()

    assert stall_path.exists()
    contents = stall_path.read_text(encoding="utf-8")
    assert "loop stall" in contents
