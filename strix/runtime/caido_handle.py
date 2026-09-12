"""Handle for a Caido bootstrap running concurrently with the scan start.

The Caido sidecar login + project setup costs a couple of seconds of
guest-side polling, and nothing needs the client until the first proxy
tool call (or the first traffic poll). :class:`CaidoBootstrapHandle`
wraps the in-flight bootstrap task so session bring-up can return as
soon as the container is up; consumers resolve the client at first use.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from caido_sdk_client import Client


logger = logging.getLogger(__name__)


class CaidoBootstrapHandle:
    """Resolves to the connected Caido client once the bootstrap finishes.

    A failed bootstrap is surfaced (once) to every ``get()`` caller as the
    original exception; proxy tools degrade to their "client unavailable"
    result instead of the failure killing the scan at bring-up.
    """

    def __init__(self, task: asyncio.Task[Client]) -> None:
        self._task = task

    async def get(self) -> Client:
        """Wait for the bootstrap and return the client.

        Shielded so one caller's cancellation (e.g. a tool timeout) does not
        cancel the shared bootstrap for everyone else.
        """
        return await asyncio.shield(self._task)

    def peek(self) -> Client | None:
        """Return the client if the bootstrap already finished cleanly."""
        if self._task.done() and not self._task.cancelled() and self._task.exception() is None:
            return self._task.result()
        return None

    async def aclose(self) -> None:
        """Cancel an in-flight bootstrap or close the finished client."""
        if not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            return
        client = self.peek()
        if client is not None:
            with contextlib.suppress(Exception):
                await client.aclose()
