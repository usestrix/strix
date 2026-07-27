"""Detect and diagnose event-loop wedges during a Strix scan.

A scan runs on one asyncio loop in a background thread. If any callback blocks the
loop thread (rather than awaiting), every agent coroutine and the TUI's state feed
silently stall at once — the failure mode where a single sub-agent crash coincided
with the whole scan ceasing to make progress.

This watchdog runs a heartbeat coroutine on the scan loop and an independent daemon
thread that watches it. When the heartbeat stops advancing for longer than
``stall_seconds``, the loop thread is wedged; the watchdog dumps every thread's stack
to a file so the blocked frame can be identified after the fact.
"""

from __future__ import annotations

import asyncio
import contextlib
import faulthandler
import logging
import threading
import time
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)


class LoopWatchdog:
    def __init__(
        self,
        *,
        stall_path: Path | None = None,
        stall_seconds: float = 20.0,
        beat_interval: float = 1.0,
    ) -> None:
        self._stall_path = stall_path
        self._stall_seconds = stall_seconds
        self._beat_interval = beat_interval
        self._last_beat = time.monotonic()
        self._beat_task: asyncio.Task[None] | None = None
        self._monitor: threading.Thread | None = None
        self._stop = threading.Event()
        self._reported = False

    def start(self) -> None:
        """Start the heartbeat task on the running loop and the monitor thread."""
        loop = asyncio.get_running_loop()
        self._last_beat = time.monotonic()
        self._stop.clear()
        self._reported = False
        self._beat_task = loop.create_task(self._beat())
        self._monitor = threading.Thread(
            target=self._run_monitor,
            name="strix-loop-watchdog",
            daemon=True,
        )
        self._monitor.start()

    async def _beat(self) -> None:
        while True:
            self._last_beat = time.monotonic()
            await asyncio.sleep(self._beat_interval)

    def _run_monitor(self) -> None:
        while not self._stop.wait(self._beat_interval):
            stalled_for = time.monotonic() - self._last_beat
            if stalled_for < self._stall_seconds:
                self._reported = False
                continue
            if self._reported:
                continue
            self._reported = True
            self._dump(stalled_for)

    def _dump(self, stalled_for: float) -> None:
        logger.error(
            "Scan event loop unresponsive for %.1fs — the loop thread stopped servicing "
            "callbacks. Dumping all thread stacks%s.",
            stalled_for,
            f" to {self._stall_path}" if self._stall_path is not None else "",
        )
        if self._stall_path is None:
            return
        try:
            self._stall_path.parent.mkdir(parents=True, exist_ok=True)
            with self._stall_path.open("a", encoding="utf-8") as fh:
                header = (
                    f"\n===== loop stall: unresponsive for {stalled_for:.1f}s @ "
                    f"{time.strftime('%Y-%m-%d %H:%M:%S')} =====\n"
                )
                fh.write(header)
                fh.flush()
                faulthandler.dump_traceback(file=fh, all_threads=True)
                fh.flush()
        except Exception:
            logger.exception("watchdog failed to write stall stack dump")

    async def stop(self) -> None:
        self._stop.set()
        if self._beat_task is not None:
            self._beat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._beat_task
            self._beat_task = None
        if self._monitor is not None:
            self._monitor.join(timeout=2.0)
            self._monitor = None
