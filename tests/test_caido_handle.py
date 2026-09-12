"""Tests for the concurrent Caido bootstrap handle."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from strix.runtime.caido_handle import CaidoBootstrapHandle


class _FakeClient:
    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


def _handle(coro: Any) -> CaidoBootstrapHandle:
    return CaidoBootstrapHandle(asyncio.ensure_future(coro))


async def test_get_waits_for_the_bootstrap() -> None:
    client = _FakeClient()
    started = asyncio.Event()

    async def _bootstrap() -> Any:
        started.set()
        await asyncio.sleep(0.01)
        return client

    handle = _handle(_bootstrap())
    await started.wait()
    assert handle.peek() is None
    assert await handle.get() is client
    assert handle.peek() is client


async def test_get_reraises_bootstrap_failure_to_every_caller() -> None:
    async def _bootstrap() -> Any:
        raise RuntimeError("caido never came up")

    handle = _handle(_bootstrap())
    for _ in range(2):
        with pytest.raises(RuntimeError, match="caido never came up"):
            await handle.get()
    assert handle.peek() is None


async def test_caller_cancellation_does_not_cancel_the_shared_bootstrap() -> None:
    client = _FakeClient()

    async def _bootstrap() -> Any:
        await asyncio.sleep(0.05)
        return client

    handle = _handle(_bootstrap())

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(handle.get(), timeout=0.01)

    assert await handle.get() is client


async def test_aclose_closes_a_finished_client() -> None:
    client = _FakeClient()

    async def _bootstrap() -> Any:
        return client

    handle = _handle(_bootstrap())
    await handle.get()
    await handle.aclose()
    assert client.closed is True


async def test_aclose_cancels_an_in_flight_bootstrap() -> None:
    cancelled = asyncio.Event()

    async def _bootstrap() -> Any:
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return _FakeClient()

    handle = _handle(_bootstrap())
    await asyncio.sleep(0)
    await handle.aclose()
    assert cancelled.is_set()


async def test_aclose_swallows_a_failed_bootstrap() -> None:
    async def _bootstrap() -> Any:
        raise RuntimeError("boom")

    handle = _handle(_bootstrap())
    with pytest.raises(RuntimeError, match="boom"):
        await handle.get()
    await handle.aclose()
