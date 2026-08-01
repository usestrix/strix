"""Tests for the preflight tool-calling probe (issue #520 fail-fast)."""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, Any, cast

import httpx
import pytest
from agents.items import ModelResponse
from agents.usage import Usage
from openai import AuthenticationError
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
async def test_probe_surfaces_unrelated_error_after_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Connectivity/auth failures must not be reported as missing tool support."""
    err = RuntimeError("connection reset by peer")
    model = _FakeModel([err, err])
    _patch_model(monkeypatch, model)
    with pytest.raises(RuntimeError) as excinfo:
        await probe_tool_calling("ollama/qwen3:8b", _settings())
    assert not isinstance(excinfo.value, ToolCallingUnsupportedError)
    assert "connection reset by peer" in str(excinfo.value)
    assert model.calls == warmup._PROBE_ATTEMPTS


@pytest.mark.asyncio
async def test_auth_error_is_never_a_capability_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A gateway that echoes the request payload back must not look unsupported.

    Some gateways include the whole request (tool schemas and all) in their error
    body, so a bare substring match on the error text can mistake a 401 for a
    missing-tool-calling endpoint and send the user off to edit chat templates.
    """
    echoed = AuthenticationError(
        message="Error code: 401 - missing header; request was: tool calling tool_use --jinja",
        response=httpx.Response(401, request=httpx.Request("POST", "http://gw/v1")),
        body=None,
    )
    model = _FakeModel([echoed, echoed])
    _patch_model(monkeypatch, model)
    with pytest.raises(AuthenticationError):
        await probe_tool_calling("openai/local", _settings(api_base="http://gw/v1"))


def test_probe_request_contains_no_capability_markers() -> None:
    """Guard: our own payload must not contain the words we scan errors for."""
    tool = warmup._build_probe_tool()
    payload = f"{tool.name} {tool.description} {tool.params_json_schema}".lower()
    matched = [m for m in warmup._TOOL_CONFIG_ERROR_MARKERS if m in payload]
    assert not matched, f"probe payload would self-trigger markers: {matched}"


@pytest.mark.asyncio
async def test_probe_reports_unsupported_when_a_response_arrived(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A text-only response after a transient error is still a capability failure."""
    model = _FakeModel([RuntimeError("connection reset by peer"), _text_response()])
    _patch_model(monkeypatch, model)
    with pytest.raises(ToolCallingUnsupportedError):
        await probe_tool_calling("ollama/qwen3:8b", _settings())


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
