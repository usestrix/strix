"""Tests for the preflight tool-calling probe (issue #520 fail-fast)."""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.items import ModelResponse
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from strix.core import warmup
from strix.core.warmup import (
    ToolCallingUnsupportedError,
    probe_tool_calling,
    requires_tool_call_probe,
)


if TYPE_CHECKING:
    from strix.config.settings import Settings


def _settings(*, api_base: str | None = None, skip: bool = False) -> Settings:
    llm = types.SimpleNamespace(api_base=api_base, skip_tool_call_probe=skip, extra_headers=None)
    return cast("Settings", types.SimpleNamespace(llm=llm))


def _tool_call_response() -> ModelResponse:
    call = ResponseFunctionToolCall(
        arguments='{"ok": true}',
        call_id="call-1",
        name="strix_preflight_check",
        type="function_call",
    )
    return ModelResponse(output=[call], usage=Usage(), response_id=None)


def _text_response(text: str = "exec_command(cmd='nmap')") -> ModelResponse:
    msg = ResponseOutputMessage(
        id="msg-1",
        content=[ResponseOutputText(annotations=[], text=text, type="output_text")],
        role="assistant",
        status="completed",
        type="message",
    )
    return ModelResponse(output=[msg], usage=Usage(), response_id=None)


class _FakeModel:
    def __init__(self, responses: list[ModelResponse | BaseException]) -> None:
        self._responses = list(responses)
        self.calls = 0

    async def get_response(self, **_kwargs: Any) -> ModelResponse:
        self.calls += 1
        item = self._responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def _patch_model(monkeypatch: pytest.MonkeyPatch, model: _FakeModel) -> None:
    provider = types.SimpleNamespace(get_model=lambda _name: model)
    monkeypatch.setattr(warmup, "StrixProvider", lambda: provider)


# --- gating -------------------------------------------------------------


def test_requires_probe_for_ollama_route() -> None:
    assert requires_tool_call_probe("ollama/qwen3:8b", _settings()) is True


def test_requires_probe_when_api_base_set() -> None:
    settings = _settings(api_base="http://x:8080/v1")
    assert requires_tool_call_probe("openai/local-gguf", settings) is True


def test_skips_probe_for_hosted_provider() -> None:
    assert requires_tool_call_probe("openai/gpt-5.6", _settings()) is False
    assert requires_tool_call_probe("anthropic/claude-opus-5", _settings()) is False


# --- behaviour ----------------------------------------------------------


@pytest.mark.asyncio
async def test_probe_passes_on_structured_tool_call(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _FakeModel([_tool_call_response()])
    _patch_model(monkeypatch, model)
    await probe_tool_calling("ollama/qwen3:8b", _settings())
    assert model.calls == 1


@pytest.mark.asyncio
async def test_probe_raises_on_text_tool_call(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _FakeModel([_text_response(), _text_response()])
    _patch_model(monkeypatch, model)
    with pytest.raises(ToolCallingUnsupportedError) as excinfo:
        await probe_tool_calling("ollama/qwen3:8b", _settings())
    assert "--jinja" in str(excinfo.value)
    assert model.calls == warmup._PROBE_ATTEMPTS


@pytest.mark.asyncio
async def test_probe_retries_then_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _FakeModel([_text_response(), _tool_call_response()])
    _patch_model(monkeypatch, model)
    await probe_tool_calling("ollama/qwen3:8b", _settings())
    assert model.calls == 2


@pytest.mark.asyncio
async def test_probe_maps_jinja_error_to_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    err = RuntimeError("500 - tools param requires --jinja flag")
    model = _FakeModel([err])
    _patch_model(monkeypatch, model)
    with pytest.raises(ToolCallingUnsupportedError):
        await probe_tool_calling("ollama/qwen3:8b", _settings())
    # bails out immediately on a clear tool-config error (no retry)
    assert model.calls == 1


@pytest.mark.asyncio
async def test_probe_wraps_unrelated_error_after_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    err = RuntimeError("connection reset by peer")
    model = _FakeModel([err, err])
    _patch_model(monkeypatch, model)
    with pytest.raises(ToolCallingUnsupportedError):
        await probe_tool_calling("ollama/qwen3:8b", _settings())
    assert model.calls == warmup._PROBE_ATTEMPTS


@pytest.mark.asyncio
async def test_probe_noop_for_hosted_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _FakeModel([_text_response()])
    _patch_model(monkeypatch, model)
    await probe_tool_calling("openai/gpt-5.6", _settings())
    assert model.calls == 0


@pytest.mark.asyncio
async def test_probe_skipped_by_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _FakeModel([_text_response()])
    _patch_model(monkeypatch, model)
    await probe_tool_calling("ollama/qwen3:8b", _settings(skip=True))
    assert model.calls == 0
