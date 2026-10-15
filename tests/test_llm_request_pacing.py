"""Tests for the global LLM request cap and inter-request delay.

Both settings default to off. A scan that does not set them must start every
request immediately, including requests that overlap. A positive cap is one
semaphore for every route; a positive delay is the minimum gap between the
starts of successive requests.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

import pytest
from agents.items import ModelResponse
from agents.model_settings import ModelSettings
from agents.models.interface import Model, ModelTracing
from agents.usage import Usage
from pydantic import ValidationError

from strix.config import loader
from strix.config.loader import load_settings
from strix.llm import request_log


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

    from agents.items import TResponseStreamEvent


class _ProbeModel(Model):
    """Records when each call holds the provider, and can stay there on demand.

    The Model methods match the SDK signature and ignore its arguments: pacing
    depends on when the call is in flight, not on what it asks the provider.
    """

    def __init__(self) -> None:
        self.started: list[float] = []
        self.in_flight = 0
        self.peak = 0
        self.release = asyncio.Event()
        self.entered = asyncio.Event()
        self._active = 0

    async def _hold(self) -> ModelResponse:
        self._active += 1
        self.in_flight = self._active
        self.peak = max(self.peak, self._active)
        self.started.append(time.monotonic())
        self.entered.set()
        try:
            await self.release.wait()
        finally:
            self._active -= 1
            self.in_flight = self._active
        return ModelResponse(output=[], usage=Usage(), response_id="resp-probe")

    async def get_response(self, *_args: Any, **_kwargs: Any) -> ModelResponse:
        return await self._hold()

    async def stream_response(
        self, *_args: Any, **_kwargs: Any
    ) -> AsyncIterator[TResponseStreamEvent]:
        await self._hold()
        if False:  # pragma: no cover - keeps this an async generator
            yield None


def _logging(inner: Model) -> request_log.RequestLoggingModel:
    return request_log.RequestLoggingModel(
        inner,
        model_name="probe",
        provider="openai",
        base_url=None,
    )


def _call(model: Model) -> Any:
    return model.get_response(
        None,
        "go",
        ModelSettings(),
        [],
        None,
        [],
        ModelTracing.DISABLED,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    )


def _stream(model: Model) -> AsyncIterator[Any]:
    return model.stream_response(
        None,
        "go",
        ModelSettings(),
        [],
        None,
        [],
        ModelTracing.DISABLED,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    )


@pytest.fixture
def _reset_gate(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in ("LLM_MAX_CONCURRENT_REQUESTS", "LLM_REQUEST_DELAY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    monkeypatch.setattr(request_log, "_request_gate", None)
    yield
    monkeypatch.setattr(request_log, "_request_gate", None)


def test_defaults_leave_requests_unpaced(_reset_gate: None) -> None:
    llm = load_settings().llm

    gate = request_log.configure_request_pacing()

    assert llm.max_concurrent_requests == 0
    assert llm.request_delay == 0
    assert gate.max_concurrent == 0
    assert gate.delay == 0
    assert gate._semaphore is None


def test_settings_install_the_gate(monkeypatch: pytest.MonkeyPatch, _reset_gate: None) -> None:
    monkeypatch.setenv("LLM_MAX_CONCURRENT_REQUESTS", "3")
    monkeypatch.setenv("LLM_REQUEST_DELAY", "1.5")
    monkeypatch.setattr(loader, "_cached", None)

    gate = request_log.configure_request_pacing()

    assert gate.max_concurrent == 3
    assert gate.delay == 1.5
    assert gate._semaphore is not None


async def test_default_gate_lets_requests_overlap(_reset_gate: None) -> None:
    request_log.configure_request_pacing()
    probe = _ProbeModel()
    model = _logging(probe)

    calls = [asyncio.create_task(_call(model)) for _ in range(4)]
    await asyncio.wait_for(probe.entered.wait(), timeout=1)
    await asyncio.sleep(0.05)
    assert probe.peak == 4
    probe.release.set()

    await asyncio.wait_for(asyncio.gather(*calls), timeout=1)


async def test_concurrency_cap_is_global(_reset_gate: None) -> None:
    request_log.configure_request_pacing(max_concurrent=2, delay=0)
    first = _ProbeModel()
    second = _ProbeModel()
    models = (_logging(first), _logging(second))

    calls = [asyncio.create_task(_call(models[i % 2])) for i in range(4)]
    await asyncio.wait_for(first.entered.wait(), timeout=1)
    await asyncio.sleep(0.05)
    assert first.peak + second.peak == 2
    assert first.in_flight + second.in_flight == 2

    first.release.set()
    second.release.set()
    await asyncio.wait_for(asyncio.gather(*calls), timeout=1)
    assert first.peak + second.peak == 2


async def test_delay_spaces_request_starts(_reset_gate: None) -> None:
    delay = 0.08
    request_log.configure_request_pacing(max_concurrent=0, delay=delay)
    probe = _ProbeModel()
    probe.release.set()
    model = _logging(probe)

    await asyncio.wait_for(asyncio.gather(*[_call(model) for _ in range(3)]), timeout=1)

    gaps = [probe.started[i + 1] - probe.started[i] for i in range(len(probe.started) - 1)]
    assert len(gaps) == 2
    assert all(gap >= delay * 0.85 for gap in gaps)


async def test_open_stream_holds_its_slot_until_closed(_reset_gate: None) -> None:
    request_log.configure_request_pacing(max_concurrent=1, delay=0)
    streaming = _ProbeModel()
    waiting = _ProbeModel()
    waiting.release.set()

    stream = _stream(_logging(streaming))
    reader = asyncio.create_task(stream.__anext__())
    await asyncio.wait_for(streaming.entered.wait(), timeout=1)

    follower = asyncio.create_task(_call(_logging(waiting)))
    await asyncio.sleep(0.05)
    assert waiting.started == []

    streaming.release.set()
    with pytest.raises(StopAsyncIteration):
        await asyncio.wait_for(reader, timeout=1)
    await stream.aclose()
    await asyncio.wait_for(follower, timeout=1)
    assert len(waiting.started) == 1


def test_negative_values_are_rejected() -> None:
    with pytest.raises(ValidationError, match="greater than or equal to 0"):
        load_settings().llm.__class__.model_validate(
            {"LLM_MAX_CONCURRENT_REQUESTS": -1, "LLM_REQUEST_DELAY": -0.1}
        )
