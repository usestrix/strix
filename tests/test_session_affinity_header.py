"""Tests for STRIX_SESSION_AFFINITY_HEADER: a per-agent session id header."""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.model_settings import ModelSettings

from strix.config import loader, models
from strix.config.loader import load_settings
from strix.llm import request_log


if TYPE_CHECKING:
    from collections.abc import Iterator

    from agents.models.interface import ModelTracing


_ENV_KEYS = ["STRIX_LLM", "LLM_API_KEY", "LLM_API_BASE", "STRIX_SESSION_AFFINITY_HEADER"]

# The wrapper only forwards `tracing`, so a placeholder is enough here.
_TRACING = cast("ModelTracing", None)


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    monkeypatch.setattr(models, "_AGENT_SESSION_IDS", {})
    yield


class _Recorder:
    """Stands in for the wrapped model, capturing the settings it is handed."""

    def __init__(self) -> None:
        self.settings: ModelSettings | None = None

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        self.settings = args[2] if len(args) > 2 else kwargs["model_settings"]
        return None


@contextmanager
def _agent(agent_id: str) -> Iterator[None]:
    token = request_log.bind_call_context(agent_id, None)
    try:
        yield
    finally:
        request_log.reset_call_context(token)


async def _record(recorder: _Recorder) -> ModelSettings:
    model = models._SessionAffinityModel(recorder, "x-bf-session-id")  # type: ignore[arg-type]
    settings = ModelSettings(extra_headers={"X-Static": "keep"})
    await model.get_response(
        None,
        [],
        settings,
        [],
        None,
        [],
        _TRACING,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    )
    assert recorder.settings is not None
    return recorder.settings


def test_header_parsed_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SESSION_AFFINITY_HEADER", "x-bf-session-id")
    assert load_settings().llm.session_affinity_header == "x-bf-session-id"


def test_header_absent_by_default() -> None:
    assert load_settings().llm.session_affinity_header is None


async def test_header_carries_one_session_per_agent() -> None:
    recorder = _Recorder()

    with _agent("root"):
        first = await _record(recorder)
        again = await _record(recorder)
    with _agent("child"):
        other = await _record(recorder)

    assert first.extra_headers is not None
    assert first.extra_headers["X-Static"] == "keep"
    session = first.extra_headers["x-bf-session-id"]
    assert again.extra_headers == first.extra_headers
    assert other.extra_headers is not None
    assert other.extra_headers["x-bf-session-id"] != session


async def test_no_header_outside_an_agent_run() -> None:
    recorder = _Recorder()
    model = models._SessionAffinityModel(recorder, "x-bf-session-id")  # type: ignore[arg-type]
    settings = ModelSettings()

    await model.get_response(
        None,
        [],
        settings,
        [],
        None,
        [],
        _TRACING,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    )

    assert recorder.settings is settings
