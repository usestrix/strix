from __future__ import annotations

from typing import Any, cast

import httpx
import pytest
from agents import RunConfig, Runner
from agents.items import ModelResponse
from agents.stream_events import RawResponsesStreamEvent
from agents.usage import Usage
from openai import (
    APIConnectionError,
    APIError,
    APIStatusError,
    APITimeoutError,
    BadRequestError,
    InternalServerError,
    RateLimitError,
)

from strix.config import codex, loader
from strix.config.models import _completed_stream_event
from strix.core import execution
from strix.core.agents import AgentCoordinator


@pytest.fixture(autouse=True)
def _isolate_llm_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """Resolve the retry settings from defaults and this test's env only."""
    for key in ("STRIX_LLM_MAX_RETRIES", "STRIX_LLM_RETRY_MAX_DELAY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_override", tmp_path / "no-config.json")
    monkeypatch.setattr(loader, "_cached", None)


def _request() -> httpx.Request:
    return httpx.Request("POST", "https://api.openai.com/v1/responses")


def _midstream_api_error() -> APIError:
    return APIError("An error occurred while processing the request.", _request(), body=None)


def _status_error(status: int) -> APIStatusError:
    return APIStatusError(
        f"status {status}",
        response=httpx.Response(status_code=status, request=_request()),
        body=None,
    )


def test_midstream_api_error_is_transient() -> None:
    assert execution._is_transient_model_error(_midstream_api_error()) is True


def test_network_errors_are_transient() -> None:
    assert execution._is_transient_model_error(APITimeoutError(_request())) is True
    assert execution._is_transient_model_error(APIConnectionError(request=_request())) is True


def test_server_errors_are_transient() -> None:
    assert (
        execution._is_transient_model_error(
            InternalServerError("boom", response=httpx.Response(500, request=_request()), body=None)
        )
        is True
    )
    for status in (502, 503, 504, 408):
        assert execution._is_transient_model_error(_status_error(status)) is True


def test_rate_limit_is_retried() -> None:
    rate_limited = RateLimitError(
        "slow down", response=httpx.Response(429, request=_request()), body=None
    )
    assert execution._is_transient_model_error(rate_limited) is True


def test_dns_and_connection_errors_are_transient() -> None:
    assert execution._is_transient_model_error(OSError("nodename nor servname provided")) is True
    assert execution._is_transient_model_error(ConnectionError("reset")) is True
    assert execution._is_transient_model_error(TimeoutError("timed out")) is True


def test_content_guardrail_is_not_retried() -> None:
    guardrail = APIError(
        "This content was flagged for possible cybersecurity risk",
        _request(),
        body=None,
    )
    assert codex.is_content_guardrail_error(guardrail) is True
    assert execution._is_transient_model_error(guardrail) is False


def test_client_errors_are_transient() -> None:
    bad_request = BadRequestError(
        "bad", response=httpx.Response(400, request=_request()), body=None
    )
    assert execution._is_transient_model_error(bad_request) is True
    for status in (401, 402, 403, 404):
        assert execution._is_transient_model_error(_status_error(status)) is False
    assert execution._is_transient_model_error(ValueError("nope")) is False


class _FakeStream:
    def __init__(self, exc: BaseException | None = None, events: list[Any] | None = None) -> None:
        self._exc = exc
        self._events: list[Any] = list(events or [])
        self.run_loop_exception: BaseException | None = None

    async def stream_events(self) -> Any:
        for event in self._events:
            yield event
        if self._exc is not None:
            raise self._exc


def _patch_fast_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_BASE_DELAY_S", 0.0)


async def _run_once(
    monkeypatch: pytest.MonkeyPatch,
    streams: list[_FakeStream],
    session: Any = None,
) -> Any:
    _patch_fast_backoff(monkeypatch)
    calls = {"n": 0}

    def _fake_run_streamed(*_args: Any, **_kwargs: Any) -> _FakeStream:
        stream = streams[calls["n"]]
        calls["n"] += 1
        return stream

    monkeypatch.setattr(Runner, "run_streamed", _fake_run_streamed)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)

    result = await execution._run_cycle(
        object(),
        coordinator,
        "root",
        input_data="task",
        run_config=cast("RunConfig", object()),
        context={},
        max_turns=5,
        session=session,
        interactive=False,
        event_sink=None,
        hooks=None,
    )
    return result, calls["n"], coordinator


@pytest.mark.asyncio
async def test_run_cycle_retries_transient_midstream_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams = [_FakeStream(exc=_midstream_api_error()), _FakeStream()]
    result, attempts, _coordinator = await _run_once(monkeypatch, streams)

    assert result is streams[1]
    assert attempts == 2


@pytest.mark.asyncio
async def test_run_cycle_gives_up_after_max_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    max_retries = loader.load_settings().llm.max_retries
    streams = [_FakeStream(exc=_midstream_api_error()) for _ in range(max_retries + 1)]
    with pytest.raises(APIError):
        await _run_once(monkeypatch, streams)


@pytest.mark.asyncio
async def test_run_cycle_does_not_retry_permanent_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams = [_FakeStream(exc=ValueError("nope")), _FakeStream()]
    with pytest.raises(ValueError, match="nope"):
        await _run_once(monkeypatch, streams)


def _dropped_stream_error() -> httpx.RemoteProtocolError:
    # What the OpenAI SDK lets through when a provider answers 200 and then closes
    # the connection before the streamed body ends.
    return httpx.RemoteProtocolError(
        "peer closed connection without sending complete message body (incomplete chunked read)"
    )


def _completed_response_event() -> RawResponsesStreamEvent:
    response = ModelResponse(output=[], usage=Usage(), response_id=None)
    return RawResponsesStreamEvent(data=_completed_stream_event(response, "model"))


def test_midstream_transport_errors_are_transient() -> None:
    for exc in (
        _dropped_stream_error(),
        httpx.ReadError("connection reset by peer"),
        httpx.ConnectError("connection refused"),
        httpx.ReadTimeout("timed out"),
    ):
        assert execution._is_transient_model_error(exc) is True, exc


def test_transport_error_raised_from_a_wrapper_is_transient() -> None:
    try:
        try:
            raise _dropped_stream_error()
        except httpx.RemoteProtocolError as dropped:
            raise RuntimeError("stream failed") from dropped
    except RuntimeError as wrapped:
        assert execution._is_transient_model_error(wrapped) is True


def test_local_transport_misconfiguration_is_not_transient() -> None:
    assert execution._is_transient_model_error(httpx.UnsupportedProtocol("ftp://x")) is False
    assert execution._is_transient_model_error(httpx.LocalProtocolError("bad header")) is False


@pytest.mark.asyncio
async def test_run_cycle_replays_turn_after_dropped_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams = [_FakeStream(exc=_dropped_stream_error()), _FakeStream()]
    result, attempts, coordinator = await _run_once(monkeypatch, streams)

    assert result is streams[1]
    assert attempts == 2
    assert coordinator.statuses.get("root") != "crashed"


@pytest.mark.asyncio
async def test_retry_budget_resets_after_a_completed_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM_MAX_RETRIES", "1")
    streams = [
        _FakeStream(exc=_dropped_stream_error()),
        # A turn completes before the next drop, so that drop is the first in a row.
        _FakeStream(exc=_dropped_stream_error(), events=[_completed_response_event()]),
        _FakeStream(),
    ]
    result, attempts, _coordinator = await _run_once(monkeypatch, streams)

    assert result is streams[2]
    assert attempts == 3


@pytest.mark.asyncio
async def test_consecutive_drops_without_progress_exhaust_the_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM_MAX_RETRIES", "1")
    streams = [_FakeStream(exc=_dropped_stream_error()) for _ in range(2)] + [_FakeStream()]
    with pytest.raises(httpx.RemoteProtocolError):
        await _run_once(monkeypatch, streams)


@pytest.mark.asyncio
async def test_retries_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM_MAX_RETRIES", "0")
    streams = [_FakeStream(exc=_dropped_stream_error()), _FakeStream()]
    with pytest.raises(httpx.RemoteProtocolError):
        await _run_once(monkeypatch, streams)


def test_retry_settings_read_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM_MAX_RETRIES", "12")
    monkeypatch.setenv("STRIX_LLM_RETRY_MAX_DELAY", "240")
    llm = loader.load_settings().llm
    assert llm.max_retries == 12
    assert llm.retry_max_delay == 240


def test_retry_delay_doubles_up_to_the_cap_with_jitter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(execution.random, "uniform", lambda _low, high: high)
    assert [execution._transient_model_retry_delay(n, 90.0) for n in range(1, 9)] == [
        2.0,
        4.0,
        8.0,
        16.0,
        32.0,
        64.0,
        90.0,
        90.0,
    ]
    monkeypatch.setattr(execution.random, "uniform", lambda low, _high: low)
    assert execution._transient_model_retry_delay(3, 90.0) == 4.0
    assert execution._transient_model_retry_delay(30, 240.0) == 120.0


def test_retry_delay_is_randomized() -> None:
    delays = {execution._transient_model_retry_delay(4, 90.0) for _ in range(50)}
    assert len(delays) > 1
    assert all(8.0 <= delay <= 16.0 for delay in delays)


@pytest.mark.parametrize(
    ("status", "message", "expected"),
    [
        (
            404,
            "litellm.NotFoundError: NotFoundError: OpenrouterException - "
            '{"error":{"message":"No endpoints found that support image input","code":404,'
            '"metadata":{"failed_routing_step":"Filter by Image Support"}}}',
            True,
        ),
        (400, "Invalid content type. image_url is only supported by certain models.", True),
        (400, "my-model is not a multimodal model", True),
        (400, "This model doesn't support the image field for user messages.", True),
        (422, "messages[3]: unknown variant `image_url`, expected `text`", True),
        (400, "'Image URLs in user messages' functionality not supported.", True),
        (
            400,
            "OpenRouterException: Message: This model's maximum context length is 1048576 "
            "tokens, but the request requires 1073484 tokens (942412 input including "
            "image/vision expansion + 131072 for the completion). Reduce the input length "
            "or max_tokens.",
            False,
        ),
        (400, "At most 5 image(s) may be provided in one prompt.", False),
        (
            400,
            "Upstream error from Relace: Generation stopped with an incomplete tool call",
            False,
        ),
        (500, "No endpoints found that support image input", False),
    ],
)
def test_is_image_rejection(status: int, message: str, expected: bool) -> None:
    exc = APIStatusError(message, response=httpx.Response(status, request=_request()), body=None)
    assert execution._is_image_rejection(exc) is expected


async def _run_with_image_session(
    monkeypatch: pytest.MonkeyPatch, streams: list[_FakeStream]
) -> tuple[Any, int, int]:
    strips = {"n": 0}

    async def _fake_strip(_session: Any) -> bool:
        strips["n"] += 1
        return True

    async def _no_compact(*_args: Any, **_kwargs: Any) -> bool:
        return False

    monkeypatch.setattr(execution, "strip_all_images_from_session", _fake_strip)
    monkeypatch.setattr(execution, "_compact_session", _no_compact)
    result, attempts, _coordinator = await _run_once(monkeypatch, streams, session=object())
    return result, attempts, strips["n"]


@pytest.mark.asyncio
async def test_run_cycle_strips_images_on_image_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rejection = APIStatusError(
        "No endpoints found that support image input",
        response=httpx.Response(status_code=404, request=_request()),
        body=None,
    )
    streams = [_FakeStream(exc=rejection), _FakeStream()]
    result, attempts, strips = await _run_with_image_session(monkeypatch, streams)

    assert result is streams[1]
    assert attempts == 2
    assert strips == 1
