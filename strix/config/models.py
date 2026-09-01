"""SDK model configuration helpers."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import os
import time
from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, Any, cast

from agents import (
    set_default_openai_api,
    set_default_openai_key,
    set_tracing_disabled,
)
from agents.model_settings import ModelSettings
from agents.models.fake_id import FAKE_RESPONSES_ID
from agents.models.interface import Model, ModelProvider
from agents.models.multi_provider import MultiProvider
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.models.openai_responses import OpenAIResponsesModel
from agents.retry import (
    ModelRetryBackoffSettings,
    ModelRetrySettings,
    RetryPolicyContext,
    retry_policies,
)
from openai.types.responses import (
    Response,
    ResponseCompletedEvent,
    ResponseOutputItemAddedEvent,
    ResponseOutputItemDoneEvent,
)
from openai.types.responses.response_usage import ResponseUsage
from openai.types.shared import Reasoning

from strix.config import codex, opencode
from strix.config.loader import load_settings
from strix.config.tool_call_ids import TurnCallIdRewriter, dedupe_input
from strix.config.tool_call_limits import TurnToolCallLimiter


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from agents.agent_output import AgentOutputSchemaBase
    from agents.handoffs import Handoff
    from agents.items import ModelResponse, TResponseInputItem, TResponseStreamEvent
    from agents.models.interface import ModelTracing
    from agents.retry import ModelRetryAdvice, ModelRetryAdviceRequest
    from agents.tool import Tool
    from agents.usage import Usage
    from openai import AsyncOpenAI
    from openai.types.responses.response_prompt_param import ResponsePromptParam

    from strix.config.settings import LlmSettings, ReasoningEffort, Settings


logger = logging.getLogger(__name__)


def request_timeout_extra_args(timeout_s: float | None) -> dict[str, float] | None:
    """Per-request model timeout; a plain float so ``ModelSettings.to_json_dict()`` stays serializable."""  # noqa: E501
    if not timeout_s or timeout_s <= 0:
        return None
    return {"timeout": timeout_s}


def _retry_statusless_provider_errors(context: RetryPolicyContext) -> bool:
    """Retry statusless provider errors (e.g. mid-stream quota/billing), but not aborts."""
    normalized = context.normalized
    if normalized.is_abort:
        return False
    if codex.is_content_guardrail_error(context.error):
        return False
    return normalized.status_code is None


class _CodexResponsesModel(OpenAIResponsesModel):
    """Responses model for stateless subscription gateways (always streamed).

    Used for the ChatGPT subscription backend and for Responses-served models on
    the OpenCode gateway: neither stores responses server-side, so reasoning is
    carried inline via ``reasoning.encrypted_content``.
    """

    def __init__(
        self,
        model: str,
        openai_client: AsyncOpenAI,
        *,
        reasoning_effort: ReasoningEffort | None = None,
    ) -> None:
        super().__init__(model, openai_client)
        self._reasoning_effort = reasoning_effort

    def _codex_settings(self, model_settings: ModelSettings) -> ModelSettings:
        overrides = ModelSettings(store=False, response_include=["reasoning.encrypted_content"])
        effort = self._reasoning_effort
        if effort and effort != "none":
            # Clamp to efforts the backend accepts.
            match effort:
                case "minimal":
                    effort = "low"
                case "xhigh" | "max":
                    effort = "high"
                case _:
                    pass
            overrides = overrides.resolve(ModelSettings(reasoning=Reasoning(effort=effort)))
        return model_settings.resolve(overrides)

    async def _fetch_response(self, *args: Any, stream: bool = False, **kwargs: Any) -> Any:
        if len(args) >= 3:  # model_settings is positional arg 2
            args = (*args[:2], self._codex_settings(args[2]), *args[3:])
        try:
            events = await super()._fetch_response(*args, stream=True, **kwargs)  # type: ignore[call-overload]
        except Exception as exc:
            guardrail = self._as_guardrail(exc)
            if guardrail is not None:
                raise guardrail from exc
            raise
        guarded = self._guarded(events)
        if stream:
            return guarded
        final_response = None
        async for event in guarded:
            if getattr(event, "type", None) == "response.completed":
                final_response = event.response
        if final_response is None:
            msg = "ChatGPT backend stream ended without a completed response"
            raise RuntimeError(msg)
        return final_response

    def _as_guardrail(self, exc: BaseException) -> codex.CodexContentGuardrailError | None:
        if isinstance(exc, codex.CodexContentGuardrailError):
            return exc
        if codex.is_content_guardrail_error(exc):
            return codex.CodexContentGuardrailError(self.model, exc)
        return None

    async def _guarded(self, events: Any) -> AsyncIterator[Any]:
        """Convert mid-stream guardrail rejections and close the stream on exit."""
        try:
            async for event in events:
                yield event
        except Exception as exc:
            guardrail = self._as_guardrail(exc)
            if guardrail is not None:
                raise guardrail from exc
            raise
        finally:
            await self._aclose(events)

    @staticmethod
    async def _aclose(events: Any) -> None:
        aclose = getattr(events, "aclose", None)
        if callable(aclose):
            with contextlib.suppress(Exception):
                await aclose()
            return
        close = getattr(events, "close", None)
        if callable(close):
            with contextlib.suppress(Exception):
                result = close()
                if inspect.isawaitable(result):
                    await result


class _NonStreamingModel(Model):
    """Serve the SDK's streamed run loop from a single non-streaming request.

    Some OpenAI-compatible gateways do not support Server-Sent Events, or
    deliver them unreliably (dropping structured tool-call deltas, or stalling
    mid-stream so the whole turn waits out the read timeout). The SDK run loop
    Strix uses only issues streamed requests, so such a gateway fails every
    turn. Opt in with ``LLM_DISABLE_STREAMING=true`` to wrap the resolved model
    so each turn makes one non-streaming ``get_response`` (``stream:false`` on
    the wire) and the completed result is replayed as a single terminal stream
    event. The run loop then executes tools and emits run items from that final
    response exactly as it would for a real stream, so nothing else changes.
    """

    def __init__(self, inner: Model) -> None:
        self._inner = inner

    async def close(self) -> None:
        await self._inner.close()

    def get_retry_advice(self, request: ModelRetryAdviceRequest) -> ModelRetryAdvice | None:
        return self._inner.get_retry_advice(request)

    async def get_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],  # noqa: A002
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: ResponsePromptParam | None,
    ) -> ModelResponse:
        return await self._inner.get_response(
            system_instructions,
            input,
            model_settings,
            tools,
            output_schema,
            handoffs,
            tracing,
            previous_response_id=previous_response_id,
            conversation_id=conversation_id,
            prompt=prompt,
        )

    async def stream_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],  # noqa: A002
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: ResponsePromptParam | None,
    ) -> AsyncIterator[TResponseStreamEvent]:
        response = await self._inner.get_response(
            system_instructions,
            input,
            model_settings,
            tools,
            output_schema,
            handoffs,
            tracing,
            previous_response_id=previous_response_id,
            conversation_id=conversation_id,
            prompt=prompt,
        )
        yield _completed_stream_event(response, getattr(self._inner, "model", None))


class _TurnGuardModel(Model):
    """Keep one turn from corrupting the conversation or running away.

    Tool-call ids: providers that number calls per turn (``exec_command:0``,
    ...) restart the counter each turn, so the same id eventually appears twice
    in one conversation and strict providers reject every subsequent request.
    Ids that collide with the history are rewritten before the turn is
    recorded, and already-corrupted histories are repaired on the way out.

    Tool-call volume: a degenerate response can queue hundreds of calls that
    the run loop then honours one by one. Only the first
    ``LLM_MAX_TOOL_CALLS_PER_TURN`` calls of a response are kept.

    Stalled streams: a turn that emits a few tokens and then goes silent is
    not covered by the request timeout, which resets on any byte (keepalives
    included). ``LLM_STREAM_IDLE_TIMEOUT`` bounds the gap between events so the
    turn fails instead of hanging, and the existing retry path replays it.
    """

    def __init__(
        self,
        inner: Model,
        *,
        max_tool_calls_per_turn: int = 0,
        stream_idle_timeout: float = 0.0,
    ) -> None:
        self._inner = inner
        self._max_tool_calls_per_turn = max_tool_calls_per_turn
        self._stream_idle_timeout = stream_idle_timeout

    def _limiter(self) -> TurnToolCallLimiter:
        return TurnToolCallLimiter(self._max_tool_calls_per_turn)

    def _log_dropped(self, limiter: TurnToolCallLimiter) -> None:
        if limiter.dropped:
            logger.warning(
                "dropped %d tool call(s) past the per-response limit of %d",
                limiter.dropped,
                self._max_tool_calls_per_turn,
            )

    async def close(self) -> None:
        await self._inner.close()

    def get_retry_advice(self, request: ModelRetryAdviceRequest) -> ModelRetryAdvice | None:
        return self._inner.get_retry_advice(request)

    async def get_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],  # noqa: A002
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: ResponsePromptParam | None,
    ) -> ModelResponse:
        sanitized = dedupe_input(input)
        rewriter = TurnCallIdRewriter(sanitized)
        response = await self._inner.get_response(
            system_instructions,
            cast("str | list[TResponseInputItem]", sanitized),
            model_settings,
            tools,
            output_schema,
            handoffs,
            tracing,
            previous_response_id=previous_response_id,
            conversation_id=conversation_id,
            prompt=prompt,
        )
        limiter = self._limiter()
        response.output = limiter.filter_items(rewriter.rewrite_items(list(response.output)))
        self._log_dropped(limiter)
        return response

    async def stream_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],  # noqa: A002
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: ResponsePromptParam | None,
    ) -> AsyncIterator[TResponseStreamEvent]:
        sanitized = dedupe_input(input)
        rewriter = TurnCallIdRewriter(sanitized)
        limiter = self._limiter()
        stream = self._inner.stream_response(
            system_instructions,
            cast("str | list[TResponseInputItem]", sanitized),
            model_settings,
            tools,
            output_schema,
            handoffs,
            tracing,
            previous_response_id=previous_response_id,
            conversation_id=conversation_id,
            prompt=prompt,
        )
        async for event in _with_idle_timeout(stream, self._stream_idle_timeout):
            guarded = _guard_event(event, rewriter, limiter)
            if guarded is not None:
                yield guarded
        self._log_dropped(limiter)


async def _aclose(stream: AsyncIterator[TResponseStreamEvent]) -> None:
    if isinstance(stream, AsyncGenerator):
        with contextlib.suppress(Exception):
            await stream.aclose()


async def _with_idle_timeout(
    stream: AsyncIterator[TResponseStreamEvent], timeout: float
) -> AsyncIterator[TResponseStreamEvent]:
    if timeout <= 0:
        async for event in stream:
            yield event
        return

    iterator = stream.__aiter__()
    while True:
        try:
            event = await asyncio.wait_for(iterator.__anext__(), timeout)
        except StopAsyncIteration:
            return
        except TimeoutError:
            await _aclose(stream)
            message = f"model stream produced no event for {timeout:.0f}s"
            logger.warning("%s; abandoning the turn", message)
            raise TimeoutError(message) from None
        yield event


def _guard_event(
    event: TResponseStreamEvent, rewriter: TurnCallIdRewriter, limiter: TurnToolCallLimiter
) -> TResponseStreamEvent | None:
    if isinstance(event, ResponseOutputItemAddedEvent | ResponseOutputItemDoneEvent):
        rewritten = rewriter.rewrite_item(event.item)
        if not limiter.allow(rewritten):
            return None
        if rewritten is not event.item:
            return event.model_copy(update={"item": rewritten})
        return event
    if isinstance(event, ResponseCompletedEvent):
        original = list(event.response.output)
        output = limiter.filter_items(rewriter.rewrite_items(original))
        if output != original:
            return event.model_copy(
                update={"response": event.response.model_copy(update={"output": output})}
            )
    return event


def _completed_stream_event(
    model_response: ModelResponse, model_name: object | None
) -> TResponseStreamEvent:
    """Wrap a non-streamed ``ModelResponse`` as the terminal event of a stream.

    The run loop builds its authoritative per-turn response solely from the
    ``response.completed`` event, so a single event carrying the full output
    and usage is all it needs.
    """
    response = Response(
        id=model_response.response_id or FAKE_RESPONSES_ID,
        created_at=time.time(),
        model=str(model_name) if model_name else "",
        object="response",
        output=list(model_response.output),
        tool_choice="auto",
        tools=[],
        parallel_tool_calls=False,
        usage=_response_usage(model_response.usage),
    )
    return ResponseCompletedEvent(
        response=response,
        sequence_number=0,
        type="response.completed",
    )


def _response_usage(usage: Usage | None) -> ResponseUsage | None:
    if usage is None:
        return None
    return ResponseUsage(
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        total_tokens=usage.total_tokens,
        input_tokens_details=usage.input_tokens_details,
        output_tokens_details=usage.output_tokens_details,
    )


class _CredentialedLitellmProvider(ModelProvider):
    """LiteLLM route bound to one endpoint's credentials.

    ``LitellmProvider`` reads them from the process-wide LiteLLM globals, which
    belong to the main model; a secondary endpoint needs its own.
    """

    def __init__(self, api_key: str | None, base_url: str | None) -> None:
        self._api_key = api_key
        self._base_url = base_url

    def get_model(self, model_name: str | None) -> Model:
        from agents.extensions.models.litellm_model import LitellmModel
        from agents.models.default_models import get_default_model

        return LitellmModel(
            model=model_name or get_default_model(),
            api_key=self._api_key,
            base_url=self._base_url,
        )


class StrixProvider(MultiProvider):
    """Route any non-OpenAI prefix through LiteLLM with the prefix preserved,
    so users type ``deepseek/deepseek-chat`` rather than
    ``litellm/deepseek/deepseek-chat``.

    ``api_key``/``base_url`` bind every route this provider resolves to one
    endpoint, for a secondary model (the dedupe judge) whose endpoint differs
    from the main model's process-wide defaults.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            openai_api_key=api_key,
            openai_base_url=base_url,
            # A custom endpoint is OpenAI-compatible, i.e. chat completions; the
            # global default is the main model's and may say otherwise.
            openai_use_responses=False if base_url else None,
            **kwargs,
        )
        self._override_api_key = api_key
        self._override_base_url = base_url

    def _create_fallback_provider(self, prefix: str) -> ModelProvider:
        if prefix == "litellm" and (self._override_api_key or self._override_base_url):
            return _CredentialedLitellmProvider(self._override_api_key, self._override_base_url)
        return super()._create_fallback_provider(prefix)

    def _resolve_prefixed_model(
        self,
        *,
        original_model_name: str,
        prefix: str,
        stripped_model_name: str | None,
    ) -> tuple[ModelProvider, str | None]:
        if prefix in {"openai", "litellm", "any-llm"}:
            return super()._resolve_prefixed_model(
                original_model_name=original_model_name,
                prefix=prefix,
                stripped_model_name=stripped_model_name,
            )
        if prefix == "ollama" and stripped_model_name:
            return self._get_fallback_provider("litellm"), f"ollama_chat/{stripped_model_name}"
        return self._get_fallback_provider("litellm"), original_model_name

    def get_model(self, model_name: str | None) -> Model:
        llm = load_settings().llm
        slug = codex.subscription_model(model_name)
        oc = opencode.subscription_model(model_name)
        idle_timeout = float(llm.stream_idle_timeout)
        if slug:
            # The ChatGPT subscription backend is always streamed; it has no
            # non-streaming mode to fall back to, so LLM_DISABLE_STREAMING
            # does not apply here.
            model: Model = _CodexResponsesModel(
                slug,
                codex.get_subscription_client(),
                reasoning_effort=llm.reasoning_effort,
            )
        elif oc and oc.protocol == opencode.PROTOCOL_RESPONSES:
            model = _CodexResponsesModel(
                oc.slug,
                opencode.get_subscription_client(oc.base_url),
                reasoning_effort=llm.reasoning_effort,
            )
        elif oc and oc.protocol == opencode.PROTOCOL_MESSAGES:
            # Claude models are served on Anthropic's ``/messages``, which the
            # OpenAI SDK cannot speak: it has no Messages method and sends the
            # key as a bearer token rather than ``x-api-key``. LiteLLM's
            # Anthropic route handles both, so the gateway becomes an Anthropic
            # base URL with the subscription key.
            from agents.extensions.models.litellm_model import LitellmModel

            model = LitellmModel(
                model=f"anthropic/{oc.slug}",
                base_url=oc.messages_url,
                api_key=opencode.get_api_key(),
            )
            if llm.disable_streaming:
                model = _NonStreamingModel(model)
                idle_timeout = 0.0
        elif oc:
            model = OpenAIChatCompletionsModel(
                oc.slug, opencode.get_subscription_client(oc.base_url)
            )
            if llm.disable_streaming:
                model = _NonStreamingModel(model)
                idle_timeout = 0.0
        else:
            model = super().get_model(model_name)
            if llm.disable_streaming:
                model = _NonStreamingModel(model)
                # The wrapper emits its single event only once the whole request
                # is done, so an idle gap is meaningless here; the request
                # timeout bounds it instead.
                idle_timeout = 0.0
        return _TurnGuardModel(
            model,
            max_tool_calls_per_turn=llm.max_tool_calls_per_turn,
            stream_idle_timeout=idle_timeout,
        )


DEFAULT_MODEL_RETRY = ModelRetrySettings(
    max_retries=5,
    backoff=ModelRetryBackoffSettings(
        initial_delay=2.0,
        max_delay=90.0,
        multiplier=2.0,
        jitter=False,
    ),
    policy=retry_policies.any(
        retry_policies.provider_suggested(),
        retry_policies.network_error(),
        retry_policies.http_status((429, 500, 502, 503, 504)),
        _retry_statusless_provider_errors,
    ),
)

RECOMMENDED_MODEL_NAMES = (
    "openai/gpt-5.6-sol",
    "openai/gpt-5.6-terra",
    "openai/gpt-5.6-luna",
    "openai/gpt-5.6",
    "openai/gpt-5.5-pro",
    "openai/gpt-5.5",
    "openai/gpt-5.4",
    "openai/gpt-5.3-codex",
    "anthropic/claude-fable-5",
    "anthropic/claude-opus-5",
    "anthropic/claude-opus-4-8",
    "anthropic/claude-sonnet-5",
    "anthropic/claude-sonnet-4-6",
    "vertex_ai/gemini-3.1-pro-preview",
    "gemini/gemini-3.1-pro-preview",
    "gemini/gemini-3.6-flash",
    "deepseek/deepseek-v4-pro",
    "deepseek/deepseek-v4-flash",
    "dashscope/qwen3.8-max",
    "dashscope/qwen3.7-max-2026-06-08",
    "moonshot/kimi-k3",
    "moonshot/kimi-k2.7-code",
)

_RECOMMENDED_MODEL_NAME_SET = frozenset(name.lower() for name in RECOMMENDED_MODEL_NAMES)

FRONTIER_MODEL_FAMILIES = (
    (("azure", "azure_ai", "bedrock_mantle", "chatgpt", "openai", "opencode"), ("gpt-5",)),
    (
        (
            "anthropic",
            "azure_ai",
            "bedrock",
            "claude",
            "databricks",
            "opencode",
            "snowflake",
            "vertex_ai",
        ),
        ("claude-fable-5", "claude-opus-5", "claude-opus-4", "claude-sonnet-5", "claude-sonnet-4"),
    ),
    (("google", "gemini", "opencode", "vertex_ai"), ("gemini-3",)),
    (("deepseek", "opencode"), ("deepseek-v4", "deepseek-r1", "deepseek-reasoner")),
    (("alibaba", "dashscope", "opencode", "qwen"), ("qwen3.8", "qwen3.7", "qwen3-max")),
    (("kimi", "moonshot", "moonshotai", "opencode"), ("kimi-k3", "kimi-k2.7", "kimi-k2.6")),
)


def configure_sdk_model_defaults(settings: Settings) -> None:
    """Apply Strix config to SDK-native defaults."""
    llm = settings.llm
    set_tracing_disabled(True)
    oc = opencode.subscription_model(llm.model)
    if codex.subscription_model(llm.model) or oc:
        # A subscription run carries its own client and credentials, so none of
        # the api_key/api_base defaults below apply. The Anthropic route is the
        # exception: it goes through LiteLLM, which still needs the
        # compatibility flags and the cost callback.
        if oc is not None and oc.protocol == opencode.PROTOCOL_MESSAGES:
            _configure_litellm_compatibility()
        return
    _configure_litellm_compatibility()
    _configure_openrouter_attribution(llm.model)
    if llm.api_key:
        set_default_openai_key(llm.api_key, use_for_tracing=False)
        _configure_litellm_default("api_key", llm.api_key)
        _mirror_api_key_to_provider_env(llm.model, llm.api_key)
    if llm.api_base:
        os.environ["OPENAI_BASE_URL"] = llm.api_base
        _configure_litellm_default("api_base", llm.api_base)
        set_default_openai_api("chat_completions")
    else:
        set_default_openai_api("responses")
    _configure_extra_headers(llm)


def _mirror_api_key_to_provider_env(model_name: str | None, api_key: str) -> None:
    if not model_name:
        return
    import litellm

    name = model_name.strip()
    for prefix in ("litellm/", "any-llm/"):
        if name.lower().startswith(prefix):
            name = name[len(prefix) :]
            break
    try:
        report = litellm.validate_environment(model=name.lower())
    except Exception:  # noqa: BLE001
        return
    for env_key in report.get("missing_keys") or []:
        if env_key.endswith("_API_KEY"):
            os.environ.setdefault(env_key, api_key)


def _configure_litellm_compatibility() -> None:
    """Apply LiteLLM compatibility, privacy, and callback settings."""
    import litellm

    litellm.drop_params = True
    litellm.modify_params = True
    litellm.turn_off_message_logging = True
    # Strix uses LiteLLM's success callback to capture provider-reported cost.
    # Disabling streaming logging also disables that callback for streamed calls.
    litellm.disable_streaming_logging = False
    litellm.suppress_debug_info = True

    _register_litellm_cost_callback()
    _install_openrouter_stream_cost_capture()


def _install_openrouter_stream_cost_capture() -> None:
    """Preserve OpenRouter's per-stream cost, which LiteLLM drops when streaming.

    OpenRouter reports the real charge in ``usage.cost`` of the final stream
    chunk, but LiteLLM rebuilds streamed responses from token-only fields and
    discards it (its non-streamed path stashes the cost in hidden params; the
    streaming path does not). Every scan streams, so without this the cost is
    lost and Strix falls back to a cost-map estimate that is missing entirely
    for new models (e.g. kimi-k3), reporting $0. Subclass the OpenRouter
    streaming handler to record the cost keyed by response id so the cost
    callback can recover the exact charge for the matching rebuilt response.
    """
    import litellm
    from litellm.llms.openrouter.chat.transformation import (
        OpenRouterChatCompletionStreamingHandler,
        OpenrouterConfig,
    )

    from strix.report.state import streamed_openrouter_costs

    class _StrixOpenRouterStreamingHandler(OpenRouterChatCompletionStreamingHandler):
        def chunk_parser(self, chunk: dict[str, Any]) -> Any:
            stream = super().chunk_parser(chunk)
            streamed_openrouter_costs.remember(
                chunk.get("id") or getattr(stream, "id", None), chunk.get("usage")
            )
            return stream

    class _StrixOpenrouterConfig(OpenrouterConfig):
        def get_model_response_iterator(
            self, streaming_response: Any, sync_stream: bool, json_mode: bool | None = False
        ) -> Any:
            return _StrixOpenRouterStreamingHandler(
                streaming_response=streaming_response,
                sync_stream=sync_stream,
                json_mode=json_mode,
            )

    # LiteLLM's provider-config factory reads litellm.OpenrouterConfig at call
    # time, so overriding the attribute is enough for the subclass to take
    # effect. (type: ignore — mypy rejects reassigning a class attribute.)
    litellm.OpenrouterConfig = _StrixOpenrouterConfig  # type: ignore[misc]


OPENROUTER_ATTRIBUTION_HEADERS = {
    "HTTP-Referer": "https://strix.ai",
    "X-Title": "Strix",
    "X-OpenRouter-Categories": "cli-agent",
}


def is_openrouter_model(model_name: str | None) -> bool:
    return bool(model_name) and "openrouter/" in (model_name or "").strip().lower()


def _configure_openrouter_attribution(model_name: str | None) -> None:
    import litellm

    current: object = litellm.headers
    existing: dict[str, str] = current if isinstance(current, dict) else {}
    if not is_openrouter_model(model_name):
        if any(key in existing for key in OPENROUTER_ATTRIBUTION_HEADERS):
            remaining = {
                k: v for k, v in existing.items() if k not in OPENROUTER_ATTRIBUTION_HEADERS
            }
            litellm.headers = remaining or None  # type: ignore[assignment]
        return

    litellm.headers = {**existing, **OPENROUTER_ATTRIBUTION_HEADERS}  # type: ignore[assignment]


def _configure_extra_headers(llm: LlmSettings) -> None:
    """Send user-provided default headers on every LLM request.

    Some OpenAI-compatible endpoints require extra HTTP headers (e.g. request
    attribution or tenant routing) alongside the bearer token. Users supply
    them via ``LLM_EXTRA_HEADERS``; they are applied to both routing paths:
    the LiteLLM route (``litellm.headers``) and the SDK-native OpenAI route
    (a default client carrying ``default_headers``), so they take effect
    regardless of the ``STRIX_LLM`` prefix.
    """
    headers = llm.extra_headers
    if not headers:
        return
    _merge_litellm_headers(headers)
    _register_openai_client_with_headers(llm, headers)


def _merge_litellm_headers(headers: dict[str, str]) -> None:
    import litellm

    current: object = litellm.headers
    existing: dict[str, str] = current if isinstance(current, dict) else {}
    litellm.headers = {**existing, **headers}  # type: ignore[assignment]


def _register_openai_client_with_headers(llm: LlmSettings, headers: dict[str, str]) -> None:
    from agents import set_default_openai_client
    from openai import AsyncOpenAI

    client = AsyncOpenAI(
        api_key=llm.api_key or "not-needed",
        base_url=llm.api_base,
        default_headers=dict(headers),
    )
    set_default_openai_client(client, use_for_tracing=False)


def _register_litellm_cost_callback() -> None:
    import litellm

    from strix.report.state import litellm_cost_callback

    for bucket_name in ("success_callback", "_async_success_callback"):
        bucket = getattr(litellm, bucket_name, None)
        if not isinstance(bucket, list):
            continue
        if litellm_cost_callback in bucket:
            continue
        bucket.append(litellm_cost_callback)


def _configure_litellm_default(name: str, value: str) -> None:
    """Set LiteLLM's module-level defaults without adding a provider wrapper."""
    import litellm

    setattr(litellm, name, value)


def uses_chat_completions_tool_schema(model_name: str, settings: Settings) -> bool:
    """Return whether the resolved SDK route can only receive JSON function tools."""
    if codex.subscription_model(model_name):
        return False
    oc = opencode.subscription_model(model_name)
    if oc:
        # Chat Completions takes JSON function tools; so does the LiteLLM
        # Anthropic route, which translates them to Anthropic tool blocks.
        return oc.protocol != opencode.PROTOCOL_RESPONSES
    model = model_name.strip().lower()
    if "/" in model and not model.startswith("openai/"):
        return True
    if settings.llm.api_base:
        return True
    return not model_supports_reasoning(model_name)


def supports_strict_tool_schemas(model_name: str) -> bool:
    """Return whether the route accepts strict tool schemas for Strix's toolset.

    Claude caps a request at 20 strict tools and 16 union-typed parameters
    across all strict schemas. Strix ships ~30 tools and the strict dialect
    turns every optional parameter into a nullable union, so both caps are
    exceeded and the request is rejected outright.
    """
    name = model_name.strip().lower()
    return not any(marker in name for marker in _ANTHROPIC_MODEL_MARKERS)


def model_supports_reasoning(model_name: str) -> bool:
    import litellm

    name = model_name.strip().lower()
    for prefix in ("litellm/", "any-llm/", "openai/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    entry = litellm.model_cost.get(name)
    if entry is None and "/" in name:
        entry = litellm.model_cost.get(name.rsplit("/", 1)[1])
    return bool(entry and entry.get("supports_reasoning"))


def is_recommended_or_frontier_model(model_name: str) -> bool:
    """Return whether a model is recommended or in a frontier model family."""
    name = _normalized_model_name(model_name)
    if not name:
        return False
    if name in _RECOMMENDED_MODEL_NAME_SET:
        return True
    provider_name, bare_model_name = _split_model_provider(name)
    return any(
        _matches_frontier_family(provider_name, bare_model_name, provider_markers, prefixes)
        for provider_markers, prefixes in FRONTIER_MODEL_FAMILIES
    )


def _normalized_model_name(model_name: str) -> str:
    name = model_name.strip().lower()
    for prefix in ("litellm/", "any-llm/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name


def _split_model_provider(model_name: str) -> tuple[str | None, str]:
    if "/" not in model_name:
        return None, model_name
    provider_name, bare_model_name = model_name.rsplit("/", 1)
    return provider_name, bare_model_name


def _matches_frontier_family(
    provider_name: str | None,
    model_name: str,
    provider_markers: tuple[str, ...],
    model_prefixes: tuple[str, ...],
) -> bool:
    if not _matches_model_prefix(model_name, model_prefixes):
        return False
    if provider_name is None:
        return True
    return _contains_provider_marker(
        provider_name, provider_markers, split_compound_names=True
    ) or _contains_provider_marker(model_name, provider_markers)


def _matches_model_prefix(model_name: str, model_prefixes: tuple[str, ...]) -> bool:
    return any(
        candidate.startswith(prefix)
        for candidate in _model_name_candidates(model_name)
        for prefix in model_prefixes
    )


def _model_name_candidates(model_name: str) -> tuple[str, ...]:
    if "." not in model_name:
        return (model_name,)
    suffixes = tuple(
        model_name.split(".", index)[-1] for index in range(1, model_name.count(".") + 1)
    )
    return (model_name, *suffixes)


def _contains_provider_marker(
    value: str, provider_markers: tuple[str, ...], *, split_compound_names: bool = False
) -> bool:
    parts = set(value.replace(".", "/").split("/"))
    if split_compound_names:
        for separator in ("_", "-"):
            parts.update(piece for part in tuple(parts) for piece in part.split(separator))
    return any(marker in parts for marker in provider_markers)


def is_known_openai_bare_model(model_name: str) -> bool:
    import litellm

    name = model_name.strip().lower()
    if not name or "/" in name:
        return False
    entry = litellm.model_cost.get(name)
    return bool(entry and entry.get("litellm_provider") == "openai")


_ANTHROPIC_MODEL_MARKERS = ("anthropic", "claude", "sonnet", "opus", "haiku")


def is_claude_model(model_name: str) -> bool:
    return "claude" in (model_name or "").strip().lower()


def routes_through_litellm(model_name: str | None) -> bool:
    """Whether :class:`StrixProvider` sends this model through LiteLLM.

    Bare names and the ``openai/``/``any-llm/`` prefixes are served by the SDK's
    own clients, which raise ``TypeError`` on request fields they do not know,
    so LiteLLM-only fields must not be attached there. A bare ``claude-...``
    name is exactly that case: an ``LLM_API_BASE`` pointing at an
    OpenAI-compatible gateway in front of Claude.
    """
    name = (model_name or "").strip()
    if not name or codex.subscription_model(name):
        return False
    prefix, _, rest = name.partition("/")
    return bool(rest) and prefix.lower() not in {"openai", "any-llm"}


def is_bedrock_route(model_name: str) -> bool:
    name = (model_name or "").strip().lower()
    return name.startswith("bedrock/") or "anthropic." in name


def _prompt_cache_name_candidates(model_name: str) -> list[str]:
    # LiteLLM's model map keys the same model under several names; strip the
    # route prefix, then leading dotted segments (region, provider).
    name = (model_name or "").strip().lower()
    for prefix in ("litellm/", "bedrock/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    candidates = [name]
    rest = name
    while "." in rest:
        rest = rest.split(".", 1)[1]
        candidates.append(rest)
    return candidates


def bedrock_route_supports_prompt_caching(model_name: str) -> bool:
    # Bedrock rejects the cache marker for models LiteLLM's map doesn't
    # recognise as cache-capable, so callers withhold it unless confirmed here.
    import litellm

    checker = getattr(getattr(litellm, "utils", None), "supports_prompt_caching", None)
    for cand in _prompt_cache_name_candidates(model_name):
        if checker is not None:
            with contextlib.suppress(Exception):
                if checker(cand):
                    return True
        entry = litellm.model_cost.get(cand)
        if entry and entry.get("supports_prompt_caching"):
            return True
    return False
