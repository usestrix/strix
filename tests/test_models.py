"""Tests for LLM model configuration helpers."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx
import litellm
import pytest
from agents.extensions.models.litellm_model import LitellmModel
from agents.model_settings import ModelSettings
from agents.models import _openai_shared
from agents.models.interface import ModelTracing
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.models.openai_responses import OpenAIResponsesModel
from openai import AsyncOpenAI
from openai.types.responses import (
    ResponseCompletedEvent,
    ResponseOutputMessage,
    ResponseOutputText,
    ResponseReasoningItem,
)

from strix.config import mistral, models
from strix.config.models import (
    StrixProvider,
    _MistralChatModel,
    _NonStreamingModel,
    _TurnGuardModel,
    configure_sdk_model_defaults,
    model_supports_images,
    request_timeout_extra_args,
    resolve_api_type,
    routes_through_litellm,
    supports_strict_tool_schemas,
    uses_chat_completions_tool_schema,
)
from strix.config.settings import Settings
from strix.llm.request_log import RequestLoggingModel


if TYPE_CHECKING:
    from collections.abc import Callable


def test_request_timeout_extra_args_positive() -> None:
    assert request_timeout_extra_args(300) == {"timeout": 300}
    assert request_timeout_extra_args(10) == {"timeout": 10}


def test_request_timeout_extra_args_survives_model_settings_json_dump() -> None:
    """The Chat Completions and LiteLLM paths pydantic-serialize ModelSettings for
    their tracing span; a non-JSON-serializable timeout fails every turn there."""
    settings = ModelSettings(extra_args=request_timeout_extra_args(300))
    assert settings.to_json_dict()["extra_args"] == {"timeout": 300}


@pytest.mark.parametrize("value", [None, 0, -1])
def test_request_timeout_extra_args_disabled(value: float | None) -> None:
    assert request_timeout_extra_args(value) is None


@pytest.mark.parametrize(
    "model_name",
    [
        "anthropic/claude-sonnet-4-6",
        "bedrock/anthropic.claude-opus-4-8-v1:0",
        "vertex_ai/claude-sonnet-5",
        "Sonnet-5",
    ],
)
def test_claude_routes_reject_strict_tool_schemas(model_name: str) -> None:
    assert not supports_strict_tool_schemas(model_name)


@pytest.mark.parametrize(
    "model_name",
    ["openai/gpt-5.4", "gpt-5.4", "gemini/gemini-3.1-pro-preview", "deepseek/deepseek-v4"],
)
def test_other_routes_keep_strict_tool_schemas(model_name: str) -> None:
    assert supports_strict_tool_schemas(model_name)


@pytest.mark.parametrize(
    ("model_name", "litellm"),
    [
        ("claude-sonnet-4-5", False),
        ("openai/claude-sonnet-4-5", False),
        ("any-llm/anthropic/claude-sonnet-4-5", False),
        ("anthropic/claude-sonnet-4-5", True),
        ("litellm/anthropic/claude-sonnet-4-5", True),
        ("bedrock/anthropic.claude-sonnet-4-5-20250929-v1:0", True),
        ("ollama/llama3", True),
    ],
)
def test_routes_through_litellm_matches_the_provider(
    monkeypatch: pytest.MonkeyPatch, model_name: str, litellm: bool
) -> None:
    """The helper must agree with what StrixProvider actually builds.

    Callers use it to decide whether a LiteLLM-only request field is safe to
    attach; on the SDK's own clients such a field raises TypeError mid-turn, so
    drift here breaks every request on that route.
    """
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    assert routes_through_litellm(model_name) is litellm
    try:
        model = StrixProvider().get_model(model_name)
    except ImportError:
        # any-llm's client is an optional dependency; reaching it at all already
        # proves the route is not LiteLLM's.
        assert not litellm
        return
    while isinstance(model, _NonStreamingModel | _TurnGuardModel | RequestLoggingModel):
        model = model._inner
    assert isinstance(model, LitellmModel) is litellm


def test_api_type_override_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "gpt-4")
    monkeypatch.setenv("STRIX_API_TYPE", "chat_completions")
    assert uses_chat_completions_tool_schema("gpt-4", Settings()) is True
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")
    monkeypatch.setenv("STRIX_API_TYPE", "responses")
    assert uses_chat_completions_tool_schema("openai/gpt-4", Settings()) is False
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-sonnet-4-5")
    assert uses_chat_completions_tool_schema("anthropic/claude-sonnet-4-5", Settings()) is True


@pytest.mark.parametrize(
    ("api_type", "expected"),
    [
        (None, OpenAIResponsesModel),
        ("chat_completions", OpenAIChatCompletionsModel),
        ("responses", OpenAIResponsesModel),
    ],
)
def test_api_type_overrides_the_api_base_route(
    monkeypatch: pytest.MonkeyPatch, api_type: str | None, expected: type
) -> None:
    """gpt-5 is catalogued on /v1/responses, so a base URL alone changes nothing."""
    monkeypatch.setattr(_openai_shared, "_use_responses_by_default", True)
    monkeypatch.setattr(_openai_shared, "_default_openai_client", None)
    monkeypatch.setattr(_openai_shared, "_default_openai_key", None)
    monkeypatch.setattr(litellm, "api_key", None)
    monkeypatch.setattr(litellm, "api_base", None)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "")
    monkeypatch.setenv("STRIX_LLM", "gpt-5")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_API_BASE", "https://gateway.example/v1")
    monkeypatch.delenv("STRIX_API_TYPE", raising=False)
    if api_type is not None:
        monkeypatch.setenv("STRIX_API_TYPE", api_type)
    configure_sdk_model_defaults(Settings())
    model = StrixProvider().get_model("gpt-5")
    while isinstance(model, _NonStreamingModel | _TurnGuardModel | RequestLoggingModel):
        model = model._inner
    assert isinstance(model, expected)


def _settings(monkeypatch: pytest.MonkeyPatch, model: str, api_base: str | None) -> Settings:
    monkeypatch.setenv("STRIX_LLM", model)
    monkeypatch.delenv("STRIX_API_TYPE", raising=False)
    for name in ("LLM_API_BASE", "OPENAI_API_BASE", "OPENAI_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    if api_base is not None:
        monkeypatch.setenv("LLM_API_BASE", api_base)
    return Settings()


@pytest.mark.parametrize(
    "api_base", [None, "https://api.openai.com/v1", "https://gateway.example/v1"]
)
def test_resolve_api_type_follows_the_catalog_not_the_base_url(
    monkeypatch: pytest.MonkeyPatch, api_base: str | None
) -> None:
    """Responses when LiteLLM lists /v1/responses for the model, chat completions otherwise."""
    settings = _settings(monkeypatch, "gpt-5", api_base)
    for model in ("gpt-5", "gpt-5.6-sol", "openai/gpt-5.4", "gpt-daybreak-blue-latest"):
        assert resolve_api_type(model, settings) == "responses", model
        assert uses_chat_completions_tool_schema(model, settings) is False, model
    for model in ("gpt-4o", "my-private-model"):
        assert resolve_api_type(model, settings) == "chat_completions", model
        assert uses_chat_completions_tool_schema(model, settings) is True, model


def test_resolve_api_type_explicit_override_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    _settings(monkeypatch, "gpt-daybreak-blue-latest", "https://gateway.example/v1")
    monkeypatch.setenv("STRIX_API_TYPE", "chat_completions")
    assert resolve_api_type("gpt-daybreak-blue-latest", Settings()) == "chat_completions"
    monkeypatch.setenv("STRIX_API_TYPE", "Responses")
    assert resolve_api_type("gpt-5", Settings()) == "responses"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("None", "none"), ("HIGH", "high"), (" xhigh ", "xhigh"), ("Max", "max")],
)
def test_reasoning_effort_is_case_insensitive(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: str
) -> None:
    monkeypatch.setenv("STRIX_REASONING_EFFORT", raw)
    monkeypatch.setenv("STRIX_DEDUPE_REASONING_EFFORT", raw)
    settings = Settings()
    assert settings.llm.reasoning_effort == expected
    assert settings.dedupe.reasoning_effort == expected


def test_configure_sdk_api_route_follows_the_given_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``model=`` override picks its own route, not ``STRIX_LLM``'s."""
    routes: list[str] = []
    monkeypatch.setattr(models, "set_default_openai_api", routes.append)
    settings = _settings(monkeypatch, "gpt-5", "https://gateway.example/v1")

    models.configure_sdk_api_route("gpt-5", settings)
    models.configure_sdk_api_route("my-private-model", settings)

    assert routes == ["responses", "chat_completions"]


def test_image_support_follows_the_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(litellm.model_cost, "acme-text", {})
    monkeypatch.setitem(litellm.model_cost, "acme-vision", {"supports_vision": True})
    assert model_supports_images("acme-text") is False
    assert model_supports_images("litellm/openai/acme-vision") is True
    assert model_supports_images("acme-unknown-model") is True


def test_mistral_subscription_resolves_to_the_chat_completions_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """lechat/<slug> must resolve to the Mistral subscription chat model, never LiteLLM."""
    client = AsyncOpenAI(api_key="placeholder", base_url="http://127.0.0.1:9/v1")
    monkeypatch.setattr(mistral, "get_subscription_client", lambda: client)

    model = StrixProvider().get_model("lechat/mistral-large-latest")
    assert isinstance(model, _TurnGuardModel)
    logged = model._inner
    assert isinstance(logged, RequestLoggingModel)
    assert isinstance(logged._inner, _MistralChatModel)
    assert logged._provider == "mistral-subscription"
    assert logged._host == "api.mistral.ai"
    assert logged._inner._client is client
    assert logged._inner.model == "mistral-large-latest"


_MISTRAL_THINKING = {"type": "thinking", "thinking": [{"type": "text", "text": "User wants pong."}]}


def _mistral_model(handler: Callable[[httpx.Request], httpx.Response]) -> _MistralChatModel:
    client = AsyncOpenAI(
        api_key="placeholder",
        base_url="http://mistral.test/v1",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    return _MistralChatModel("mistral-large-latest", client)


def _output_text_and_reasoning(output: list[Any]) -> tuple[str, str]:
    text = "".join(
        part.text
        for item in output
        if isinstance(item, ResponseOutputMessage)
        for part in item.content
        if isinstance(part, ResponseOutputText)
    )
    reasoning = "".join(
        summary.text
        for item in output
        if isinstance(item, ResponseReasoningItem)
        for summary in item.summary
    )
    return text, reasoning


@pytest.mark.asyncio
async def test_mistral_thinking_content_becomes_text_and_reasoning() -> None:
    """Mistral reasoning models answer with a list of thinking and text chunks
    where the SDK expects a string."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "c1",
                "object": "chat.completion",
                "created": 0,
                "model": "mistral-large-latest",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": [_MISTRAL_THINKING, {"type": "text", "text": "pong"}],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
            },
        )

    response = await _mistral_model(handler).get_response(
        None,
        "ping",
        ModelSettings(),
        [],
        None,
        [],
        ModelTracing.DISABLED,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    )

    assert _output_text_and_reasoning(response.output) == ("pong", "User wants pong.")


@pytest.mark.asyncio
async def test_mistral_streamed_thinking_content_becomes_text_and_reasoning() -> None:
    deltas: list[Any] = [
        [_MISTRAL_THINKING],
        [{"type": "text", "text": "po"}],
        "ng",
    ]

    def handler(_request: httpx.Request) -> httpx.Response:
        chunks = [
            {
                "id": "c1",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": "mistral-large-latest",
                "choices": [{"index": 0, "delta": {"content": delta}, "finish_reason": None}],
            }
            for delta in deltas
        ]
        chunks[-1]["choices"][0]["finish_reason"] = "stop"
        body = "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks) + "data: [DONE]\n\n"
        return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})

    events = [
        event
        async for event in _mistral_model(handler).stream_response(
            None,
            "ping",
            ModelSettings(),
            [],
            None,
            [],
            ModelTracing.DISABLED,
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
    ]

    completed = [e for e in events if isinstance(e, ResponseCompletedEvent)]
    assert len(completed) == 1
    assert _output_text_and_reasoning(completed[0].response.output) == (
        "pong",
        "User wants pong.",
    )


def test_mistral_subscription_needs_no_litellm_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """configure_sdk_model_defaults must skip LiteLLM/env setup for lechat/ models."""
    settings = _settings(monkeypatch, "lechat/mistral-large-latest", None)
    monkeypatch.setattr(litellm, "api_key", None)
    monkeypatch.setattr(litellm, "api_base", None)

    def _boom() -> None:
        msg = "LiteLLM setup must not run for a subscription model"
        raise AssertionError(msg)

    monkeypatch.setattr(models, "_configure_litellm_compatibility", _boom)
    monkeypatch.setattr(models, "_configure_attribution", _boom)
    models.configure_sdk_model_defaults(settings)
    assert litellm.api_key is None


@pytest.mark.parametrize(
    ("model_name", "expected"),
    [
        ("lechat/mistral-large-latest", True),  # chat completions route
        ("chatgpt/gpt-5.4", False),  # responses route
        ("openai/gpt-5.4", False),
        ("anthropic/claude-sonnet-4-5", True),
    ],
)
def test_uses_chat_completions_tool_schema_routes_subscriptions(
    model_name: str, expected: bool
) -> None:
    assert uses_chat_completions_tool_schema(model_name, Settings()) is expected


def test_mistral_subscription_sends_non_strict_tool_schemas() -> None:
    assert supports_strict_tool_schemas("lechat/mistral-large-latest") is False
    # The ChatGPT route keeps its existing behaviour.
    assert supports_strict_tool_schemas("chatgpt/gpt-5.4") is True


@pytest.mark.parametrize(
    "model_name",
    ["lechat/mistral-large-latest", "chatgpt/gpt-5.4"],
)
def test_subscription_prefixes_never_route_through_litellm(model_name: str) -> None:
    assert routes_through_litellm(model_name) is False


def test_mistral_api_key_prefix_still_routes_through_litellm() -> None:
    assert routes_through_litellm("mistral/mistral-large-latest") is True
    assert supports_strict_tool_schemas("mistral/mistral-large-latest") is True
