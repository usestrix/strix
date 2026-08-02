"""SDK model configuration helpers."""

from __future__ import annotations

import contextlib
import inspect
import os
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from agents import (
    set_default_openai_api,
    set_default_openai_key,
    set_tracing_disabled,
)
from agents.extensions.models.litellm_model import LitellmModel
from agents.model_settings import ModelSettings
from agents.models.fake_id import FAKE_RESPONSES_ID
from agents.models.interface import Model, ModelProvider
from agents.models.multi_provider import MultiProvider
from agents.models.openai_responses import OpenAIResponsesModel
from agents.retry import (
    ModelRetryBackoffSettings,
    ModelRetrySettings,
    RetryPolicyContext,
    retry_policies,
)
from openai.types.responses import Response, ResponseCompletedEvent
from openai.types.responses.response_usage import ResponseUsage
from openai.types.shared import Reasoning

from strix.config import codex


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

    from strix.config.settings import ReasoningEffort, Settings


@dataclass(frozen=True)
class ResolvedModelConfig:
    model: str
    provider: str
    api_key: str | None = field(repr=False)
    api_base: str | None
    api_version: str | None = None


class _ConfiguredLiteLLMProvider(ModelProvider):
    def __init__(self, api_key: str | None, api_base: str | None) -> None:
        self._api_key = api_key
        self._api_base = api_base

    def get_model(self, model_name: str | None) -> Model:
        return LitellmModel(
            model_name or "",
            api_key=self._api_key,
            base_url=self._api_base,
        )

    async def aclose(self) -> None:
        return None


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
    """Responses model for the ChatGPT subscription backend (always streamed, stateless)."""

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


class StrixProvider(MultiProvider):
    """Route any non-OpenAI prefix through LiteLLM with the prefix preserved,
    so users type ``deepseek/deepseek-chat`` rather than
    ``litellm/deepseek/deepseek-chat``.
    """

    def __init__(
        self,
        model_name: str | None = None,
        settings: Settings | None = None,
        *,
        api_key: str | None = None,
        api_base: str | None = None,
    ) -> None:
        if settings is None:
            from strix.config.loader import load_settings

            settings = load_settings()
        self._settings = settings
        self._requested_model = (model_name or settings.llm.model or "").strip()
        self.config = resolve_model_config(
            settings,
            model_name,
            api_key=api_key,
            api_base=api_base,
        )
        openai_route = self.config.provider == "openai"
        super().__init__(
            openai_api_key=self.config.api_key if openai_route else None,
            openai_base_url=self.config.api_base if openai_route else None,
            openai_use_responses=not bool(self.config.api_base),
        )
        self._configured_litellm_provider = _ConfiguredLiteLLMProvider(
            self.config.api_key,
            self.config.api_base,
        )
        self._configured_anyllm_provider: ModelProvider | None = None
        if self.config.model.lower().startswith("any-llm/"):
            from agents.extensions.models.any_llm_provider import AnyLLMProvider

            self._configured_anyllm_provider = AnyLLMProvider(
                api_key=self.config.api_key,
                base_url=self.config.api_base,
            )

    def _resolve_prefixed_model(
        self,
        *,
        original_model_name: str,
        prefix: str,
        stripped_model_name: str | None,
    ) -> tuple[ModelProvider, str | None]:
        if prefix == "openai":
            return super()._resolve_prefixed_model(
                original_model_name=original_model_name,
                prefix=prefix,
                stripped_model_name=stripped_model_name,
            )
        if prefix == "litellm":
            return self._configured_litellm_provider, stripped_model_name
        if prefix == "any-llm":
            if self._configured_anyllm_provider is None:
                raise RuntimeError("AnyLLM provider was not initialized for this model")
            return self._configured_anyllm_provider, stripped_model_name
        if prefix == "ollama" and stripped_model_name:
            return self._configured_litellm_provider, f"ollama_chat/{stripped_model_name}"
        return self._configured_litellm_provider, original_model_name

    def get_model(self, model_name: str | None) -> Model:
        requested_model = (model_name or "").strip()
        if requested_model and requested_model != self._requested_model:
            return type(self)(requested_model, self._settings).get_model(requested_model)
        slug = codex.subscription_model(model_name)
        if slug:
            # The ChatGPT subscription backend is always streamed; it has no
            # non-streaming mode to fall back to, so LLM_DISABLE_STREAMING
            # does not apply here.
            return _CodexResponsesModel(
                slug,
                codex.get_subscription_client(),
                reasoning_effort=self._settings.llm.reasoning_effort,
            )
        from strix.config.providers import custom_provider, provider_for_model

        if custom_provider(provider_for_model(model_name) or ""):
            model = self._configured_litellm_provider.get_model(self.config.model)
        else:
            model = super().get_model(model_name)
        if self._settings.llm.disable_streaming:
            return _NonStreamingModel(model)
        return model


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


def recommended_models_by_provider() -> dict[str, list[str]]:
    """Group the recommended model names by their ``<provider>/`` prefix.

    Used by the interactive home page so ``/provider`` and ``/model`` can offer
    curated choices without hard-coding a second copy of the list.
    """
    grouped: dict[str, list[str]] = {}
    for name in RECOMMENDED_MODEL_NAMES:
        provider = name.split("/", 1)[0] if "/" in name else "openai"
        grouped.setdefault(provider, []).append(name)
    return grouped


def recommended_providers() -> list[str]:
    """Distinct provider prefixes across the recommended models, in order."""
    return list(recommended_models_by_provider().keys())


FRONTIER_MODEL_FAMILIES = (
    (("azure", "azure_ai", "bedrock_mantle", "chatgpt", "openai"), ("gpt-5",)),
    (
        ("anthropic", "azure_ai", "bedrock", "claude", "databricks", "snowflake", "vertex_ai"),
        ("claude-fable-5", "claude-opus-5", "claude-opus-4", "claude-sonnet-5", "claude-sonnet-4"),
    ),
    (("google", "gemini", "vertex_ai"), ("gemini-3",)),
    (("deepseek",), ("deepseek-v4", "deepseek-r1", "deepseek-reasoner")),
    (("alibaba", "dashscope", "qwen"), ("qwen3.8", "qwen3.7", "qwen3-max")),
    (("moonshot", "moonshotai", "kimi"), ("kimi-k3", "kimi-k2.7", "kimi-k2.6")),
)


def resolve_model_config(
    settings: Settings,
    model_name: str | None = None,
    *,
    api_key: str | None = None,
    api_base: str | None = None,
) -> ResolvedModelConfig:
    """Resolve one model route without mutating process-global credentials."""
    from strix.config.providers import (
        normalize_ollama_api_base,
        provider_for_model,
        require_provider_enabled,
        resolve_provider_api_key,
    )

    configured_model = (getattr(settings.llm, "model", None) or "").strip()
    model = (model_name or configured_model).strip()
    provider = provider_for_model(model) or "openai"
    custom = require_provider_enabled(provider)
    compatibility_route = not model_name or provider_for_model(configured_model) == provider
    compatibility_key = _programmatic_compatibility_value(
        getattr(settings.llm, "api_key", None) if compatibility_route else None,
        "LLM_API_KEY",
        "OPENAI_API_KEY",
    )
    compatibility_base = _programmatic_compatibility_value(
        getattr(settings.llm, "api_base", None) if compatibility_route else None,
        "LLM_API_BASE",
        "OPENAI_API_BASE",
        "OPENAI_BASE_URL",
        "LITELLM_BASE_URL",
        "OLLAMA_API_BASE",
    )
    resolved_key = (
        api_key
        or (
            custom.api_key
            if custom
            else resolve_provider_api_key(
                provider,
                primary_model=configured_model,
                model=model,
            )
        )
        or compatibility_key
    )

    resolved_base: str | None
    if api_base is not None:
        resolved_base = api_base
    elif custom:
        resolved_base = custom.api_base
    elif compatibility_base:
        resolved_base = compatibility_base
    elif model.lower().startswith("litellm/"):
        resolved_base = _resolve_route_env_value(provider, configured_model, "LITELLM_BASE_URL")
    elif provider == "openai":
        resolved_base = _resolve_route_env_value(
            provider,
            configured_model,
            "OPENAI_API_BASE",
            "OPENAI_BASE_URL",
        )
    elif provider in {"ollama", "ollama_chat"}:
        raw_base = _resolve_route_env_value(provider, configured_model, "OLLAMA_API_BASE")
        resolved_base = normalize_ollama_api_base(raw_base) if raw_base else None
    elif provider.startswith("azure"):
        resolved_base = _resolve_route_env_value(provider, configured_model, "AZURE_API_BASE")
    else:
        resolved_base = _resolve_route_env_value(provider, configured_model)

    resolved_api_version = (
        _resolve_route_env_value(
            provider,
            configured_model,
            "AZURE_API_VERSION",
            include_generic=False,
        )
        if provider.startswith("azure")
        else None
    )

    transport_model = model
    if custom:
        _, _, remote_model = model.partition("/")
        transport_model = f"{custom.transport}/{remote_model}"
        # OpenAI-compatible clients require a key argument even when the server does not.
        resolved_key = resolved_key or "not-needed"

    return ResolvedModelConfig(
        model=transport_model,
        provider=provider,
        api_key=resolved_key,
        api_base=resolved_base,
        api_version=resolved_api_version,
    )


def _programmatic_compatibility_value(value: str | None, *aliases: str) -> str | None:
    """Use legacy public Settings fields only when no env/config source supplied them."""
    if not value:
        return None
    from strix.config.loader import read_config_env

    alias_set = {alias.upper() for alias in aliases}
    if any(key.upper() in alias_set and raw for key, raw in os.environ.items()):
        return None
    config_env = read_config_env()
    if any(key.upper() in alias_set and raw for key, raw in config_env.items()):
        return None
    return value


def _resolve_route_env_value(
    provider: str,
    effective_model: str,
    *provider_names: str,
    include_generic: bool = True,
) -> str | None:
    """Resolve a route value without carrying a generic base between providers."""
    from strix.config.loader import read_config_env
    from strix.config.providers import provider_for_model

    process_env = {key.upper(): value for key, value in os.environ.items() if value}
    config_env = {key.upper(): value for key, value in read_config_env().items() if value}
    generic_allowed = include_generic and provider_for_model(effective_model) == provider
    if generic_allowed and (value := process_env.get("LLM_API_BASE")):
        return value
    for name in provider_names:
        if value := process_env.get(name.upper()):
            return value

    persisted_model = config_env.get("STRIX_LLM")
    if (
        include_generic
        and provider_for_model(persisted_model) == provider
        and (value := config_env.get("LLM_API_BASE"))
    ):
        return value
    for name in provider_names:
        if value := config_env.get(name.upper()):
            return value
    return None


def configure_sdk_model_defaults(settings: Settings) -> None:
    """Apply process-level SDK privacy and compatibility settings.

    Credentials, endpoints, and model-specific headers are intentionally bound
    to :class:`StrixProvider` and request settings instead of global SDK state.
    """
    set_tracing_disabled(True)
    if codex.subscription_model(settings.llm.model):
        return
    _configure_litellm_compatibility()
    route = resolve_model_config(settings)
    if route.api_key:
        set_default_openai_key(route.api_key, use_for_tracing=False)
        import litellm

        litellm.api_key = route.api_key
    if route.api_base:
        import litellm

        litellm.api_base = route.api_base
        set_default_openai_api("chat_completions")
    else:
        set_default_openai_api("responses")


def model_extra_headers(settings: Settings, model_name: str) -> dict[str, str] | None:
    """Return generic headers only for the configured model's provider route."""
    headers = settings.llm.extra_headers
    if not headers:
        return None
    from strix.config.providers import provider_for_model

    configured_model = getattr(settings.llm, "model", None)
    configured_provider = provider_for_model(configured_model)
    requested_provider = provider_for_model(model_name)
    if configured_provider is None:
        return dict(headers)
    if configured_provider != requested_provider:
        return None
    return dict(headers)


def with_model_request_headers(
    model_settings: ModelSettings,
    model_name: str,
) -> ModelSettings:
    """Attach route-specific request headers without changing LiteLLM globals."""
    from strix.config.providers import provider_for_model

    provider = provider_for_model(model_name)
    resolved = model_settings
    if provider == "openrouter":
        existing = model_settings.extra_headers or {}
        resolved = resolved.resolve(
            ModelSettings(extra_headers={**_OPENROUTER_ATTRIBUTION_HEADERS, **existing})
        )
    if provider and provider.startswith("azure"):
        from strix.config.loader import resolve_env_value

        if api_version := resolve_env_value("AZURE_API_VERSION"):
            resolved = resolved.resolve(
                ModelSettings(
                    extra_args={**(resolved.extra_args or {}), "api_version": api_version}
                )
            )
    return resolved


def _configure_litellm_compatibility() -> None:
    """Apply LiteLLM compatibility, privacy, and callback settings."""
    import litellm

    # Requests receive credentials, bases, and headers from their provider and
    # ModelSettings. Clear legacy module defaults so they cannot override those
    # values after an in-process configuration change.
    litellm.api_key = None
    litellm.api_base = None
    litellm.api_version = None
    litellm.headers = None
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


_OPENROUTER_ATTRIBUTION_HEADERS = {
    "HTTP-Referer": "https://strix.ai",
    "X-Title": "Strix",
    "X-OpenRouter-Categories": "cli-agent",
}


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


def uses_chat_completions_tool_schema(model_name: str, settings: Settings) -> bool:
    """Return whether the resolved SDK route can only receive JSON function tools."""
    if codex.subscription_model(model_name):
        return False
    model = model_name.strip().lower()
    if "/" in model and not model.startswith("openai/"):
        return True
    if resolve_model_config(settings, model_name).api_base:
        return True
    return not model_supports_reasoning(model_name)


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


def is_claude_model(model_name: str) -> bool:
    return "claude" in (model_name or "").strip().lower()


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
