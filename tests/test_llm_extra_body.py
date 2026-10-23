"""Tests for LLM_EXTRA_BODY: extra fields merged into every LLM request body."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx
import litellm
import openai
import pytest
from agents.extensions.models.litellm_model import LitellmModel
from agents.models.interface import ModelTracing
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.models.openai_responses import OpenAIResponsesModel

from strix.config import loader
from strix.config.loader import load_settings
from strix.core.inputs import make_model_settings


if TYPE_CHECKING:
    from collections.abc import Iterator

    from agents.models.interface import Model


_EXTRA_BODY = {"service_tier": "flex", "safety_identifier": "user-hash"}


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("LLM_EXTRA_BODY", raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    yield


def test_extra_body_parsed_from_json_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_EXTRA_BODY", json.dumps({"service_tier": "flex", "n": 1}))

    assert load_settings().llm.extra_body == {"service_tier": "flex", "n": 1}


async def _send(
    model: Model,
    *,
    model_name: str = "gpt-5",
    reasoning_effort: str | None = None,
) -> None:
    await model.get_response(
        system_instructions=None,
        input="Reply with just 'OK'.",
        model_settings=make_model_settings(
            reasoning_effort,
            model_name=model_name,
            extra_body=_EXTRA_BODY,
        ),
        tools=[],
        output_schema=None,
        handoffs=[],
        tracing=ModelTracing.DISABLED,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    )


def _capturing_client(captured: dict[str, Any]) -> openai.AsyncOpenAI:
    def handler(request: httpx.Request) -> httpx.Response:
        captured["__path"] = request.url.path
        captured.update(json.loads(request.content))
        return httpx.Response(400, json={"error": {"message": "captured"}})

    return openai.AsyncOpenAI(
        api_key="test",
        base_url="https://gateway.example/v1",
        max_retries=0,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("model_cls", [OpenAIChatCompletionsModel, OpenAIResponsesModel])
async def test_extra_body_reaches_native_openai_request_body(model_cls: type) -> None:
    captured: dict[str, Any] = {}

    with pytest.raises(openai.BadRequestError):
        await _send(model_cls(model="gpt-5", openai_client=_capturing_client(captured)))

    assert {k: captured.get(k) for k in _EXTRA_BODY} == _EXTRA_BODY


@pytest.mark.asyncio
async def test_minimax_flash_default_responses_payload_reaches_mock_transport() -> None:
    captured: dict[str, Any] = {}
    client = _capturing_client(captured)

    with pytest.raises(openai.BadRequestError):
        await _send(
            OpenAIResponsesModel(model="openai/MiniMax-M3.1-Flash", openai_client=client),
            model_name="openai/MiniMax-M3.1-Flash",
            reasoning_effort="max",
        )

    assert captured["__path"] == "/v1/responses"
    assert captured["model"] == "openai/MiniMax-M3.1-Flash"
    assert captured["reasoning_effort"] == "max"


@pytest.mark.asyncio
async def test_extra_body_passed_to_litellm(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_acompletion(**kwargs: Any) -> Any:
        captured.update(kwargs)
        raise RuntimeError("captured")

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)

    with pytest.raises(RuntimeError, match="captured"):
        await _send(LitellmModel(model="openai/gpt-5", base_url="https://gateway.example/v1"))

    assert captured["extra_body"] == _EXTRA_BODY
