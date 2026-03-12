"""
NOTE: This is a temporary workaround.
TODO: Migrate this to a standalone library and add regression tests/coverage to
      ensure it works with all providers and models. I'd hate for this to fail on
      some edge cases etc, and realistically, it's something tiny that the OS
      community could make use of. LiteLLM is really cool.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, TypeVar, overload

from browser_use.llm.base import BaseChatModel
from browser_use.llm.exceptions import ModelProviderError, ModelRateLimitError
from browser_use.llm.messages import (
    AssistantMessage,
    BaseMessage,
    SystemMessage,
    UserMessage,
)
from browser_use.llm.schema import SchemaOptimizer
from browser_use.llm.views import ChatInvokeCompletion, ChatInvokeUsage
from pydantic import BaseModel


logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


def _serialize_messages(messages: list[BaseMessage]) -> list[dict[str, Any]]:
    """Convert browser-use messages to litellm-compatible dicts (OpenAI format).

    LiteLLM accepts OpenAI-format message dicts for all providers, handling
    provider-specific conversion (e.g. image blocks for Anthropic) internally.
    """
    result: list[dict[str, Any]] = []
    for msg in messages:
        if isinstance(msg, UserMessage):
            d: dict[str, Any] = {"role": "user"}
            if isinstance(msg.content, str):
                d["content"] = msg.content
            else:
                parts: list[dict[str, Any]] = []
                for part in msg.content:
                    if part.type == "text":
                        parts.append({"type": "text", "text": part.text})
                    elif part.type == "image_url":
                        parts.append(
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": part.image_url.url,
                                    "detail": part.image_url.detail,
                                },
                            }
                        )
                d["content"] = parts
            if msg.name is not None:
                d["name"] = msg.name
            result.append(d)

        elif isinstance(msg, SystemMessage):
            d = {"role": "system"}
            if isinstance(msg.content, str):
                d["content"] = msg.content
            else:
                d["content"] = [{"type": "text", "text": p.text} for p in msg.content]
            if msg.name is not None:
                d["name"] = msg.name
            result.append(d)

        elif isinstance(msg, AssistantMessage):
            d = {"role": "assistant"}
            if msg.content is not None:
                if isinstance(msg.content, str):
                    d["content"] = msg.content
                else:
                    parts = []
                    for part in msg.content:
                        if part.type == "text":
                            parts.append({"type": "text", "text": part.text})
                        elif part.type == "refusal":
                            parts.append(
                                {
                                    "type": "text",
                                    "text": f"[Refusal] {part.refusal}",
                                }
                            )
                    d["content"] = parts
            else:
                d["content"] = None
            if msg.name is not None:
                d["name"] = msg.name
            if msg.tool_calls:
                d["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ]
            result.append(d)

        else:
            logger.warning(
                "_serialize_messages: unhandled message type %s — skipping",
                type(msg).__name__,
            )
    return result


@dataclass
class ChatLiteLLM(BaseChatModel):
    """Chat model that routes to any provider via LiteLLM.

    Uses litellm's unified ``acompletion`` API to support all providers
    (OpenAI, Anthropic, Google, Ollama, OpenRouter, DeepSeek, etc.)
    through a single interface.

    The ``model`` parameter uses litellm's model format, e.g.::

        "gpt-4o"
        "anthropic/claude-sonnet-4-20250514"
        "openrouter/google/gemini-2.0-flash-001"
        "ollama/llama3"

    Structured output (``output_format``) is handled via litellm's
    ``response_format`` parameter which translates across providers.
    """

    model: str
    api_key: str | None = None
    api_base: str | None = None
    temperature: float | None = 0.0
    max_tokens: int | None = 4096
    max_retries: int = 3

    # Resolved lazily in __post_init__
    _provider_name: str = field(default="", init=False, repr=False)
    _clean_model: str = field(default="", init=False, repr=False)
    _supports_vision: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        """Resolve provider info from the model string via litellm."""
        try:
            from litellm import get_llm_provider

            self._clean_model, self._provider_name, _, _ = get_llm_provider(self.model)
        except Exception:  # noqa: BLE001
            if "/" in self.model:
                self._provider_name, self._clean_model = self.model.split("/", 1)
            else:
                self._provider_name = "openai"
                self._clean_model = self.model

        try:
            import litellm

            self._supports_vision = bool(litellm.supports_vision(self.model))
        except Exception:  # noqa: BLE001
            self._supports_vision = False

        logger.debug(
            "ChatLiteLLM initialized: model=%s, provider=%s, clean=%s, api_base=%s, vision=%s",
            self.model,
            self._provider_name,
            self._clean_model,
            self.api_base or "(default)",
            self._supports_vision,
        )

    @property
    def provider(self) -> str:
        return self._provider_name or "litellm"

    @property
    def name(self) -> str:
        return self._clean_model or self.model

    @property
    def supports_vision(self) -> bool:
        return self._supports_vision

    # ------------------------------------------------------------------
    # Usage parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_usage(response: Any) -> ChatInvokeUsage | None:
        """Extract token usage from a litellm response."""
        usage = getattr(response, "usage", None)
        if usage is None:
            return None

        prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
        completion_tokens = getattr(usage, "completion_tokens", 0) or 0

        # Cache info — litellm exposes these at the top level for Anthropic/OpenAI
        prompt_cached = getattr(usage, "cache_read_input_tokens", None)
        cache_creation = getattr(usage, "cache_creation_input_tokens", None)

        # Fallback: nested prompt_tokens_details (OpenAI style)
        if prompt_cached is None:
            details = getattr(usage, "prompt_tokens_details", None)
            if details:
                prompt_cached = getattr(details, "cached_tokens", None)

        return ChatInvokeUsage(
            prompt_tokens=prompt_tokens,
            prompt_cached_tokens=int(prompt_cached) if prompt_cached is not None else None,
            prompt_cache_creation_tokens=int(cache_creation)
            if cache_creation is not None
            else None,
            prompt_image_tokens=None,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )

    # ------------------------------------------------------------------
    # ainvoke — the single method browser-use calls
    # ------------------------------------------------------------------

    @overload
    async def ainvoke(
        self,
        messages: list[BaseMessage],
        output_format: None = None,
        **kwargs: Any,
    ) -> ChatInvokeCompletion[str]: ...

    @overload
    async def ainvoke(
        self,
        messages: list[BaseMessage],
        output_format: type[T],
        **kwargs: Any,
    ) -> ChatInvokeCompletion[T]: ...

    async def ainvoke(
        self,
        messages: list[BaseMessage],
        output_format: type[T] | None = None,
        **kwargs: Any,
    ) -> ChatInvokeCompletion[T] | ChatInvokeCompletion[str]:
        """Invoke the model via litellm.

        Args:
            messages: List of browser-use chat messages.
            output_format: Optional Pydantic model class for structured output.
            **kwargs: Extra keyword args (``session_id`` etc.) — ignored.

        Returns:
            ``ChatInvokeCompletion`` with either a string or parsed Pydantic model.
        """
        import litellm

        litellm_messages = _serialize_messages(messages)

        params: dict[str, Any] = {
            "model": self.model,
            "messages": litellm_messages,
            "num_retries": self.max_retries,
        }

        if self.temperature is not None:
            params["temperature"] = self.temperature
        if self.max_tokens is not None:
            params["max_tokens"] = self.max_tokens
        if self.api_key:
            params["api_key"] = self.api_key
        if self.api_base:
            params["api_base"] = self.api_base

        # Structured output via JSON schema response format.
        # LiteLLM translates this across providers (OpenAI native, Anthropic
        # via tool use, etc.).
        if output_format is not None:
            schema = SchemaOptimizer.create_optimized_json_schema(output_format)
            params["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "agent_output",
                    "strict": True,
                    "schema": schema,
                },
            }

        try:
            response = await litellm.acompletion(**params)
        except litellm.RateLimitError as e:
            raise ModelRateLimitError(message=str(e), model=self.name) from e
        except litellm.Timeout as e:
            raise ModelProviderError(message=f"Request timed out: {e}", model=self.name) from e
        except litellm.APIConnectionError as e:
            raise ModelProviderError(message=str(e), model=self.name) from e
        except litellm.APIError as e:
            status = getattr(e, "status_code", 502) or 502
            raise ModelProviderError(message=str(e), status_code=status, model=self.name) from e
        except ModelProviderError:
            raise
        except Exception as e:
            raise ModelProviderError(message=str(e), model=self.name) from e

        # --- Parse response ---
        choice = response.choices[0] if response.choices else None
        if choice is None:
            raise ModelProviderError(
                message="Empty response: no choices returned by the model",
                status_code=502,
                model=self.name,
            )

        content = choice.message.content or ""
        usage = self._parse_usage(response)
        stop_reason = choice.finish_reason

        # Extract thinking/reasoning content (Anthropic extended thinking,
        # DeepSeek reasoning, etc.) if the provider surfaces it.
        thinking: str | None = None
        msg_obj = choice.message
        reasoning = getattr(msg_obj, "reasoning_content", None)
        if reasoning:
            thinking = str(reasoning)

        if output_format is not None:
            if not content:
                raise ModelProviderError(
                    message="Model returned empty content for structured output request",
                    status_code=500,
                    model=self.name,
                )
            parsed = output_format.model_validate_json(content)
            return ChatInvokeCompletion(
                completion=parsed,
                thinking=thinking,
                usage=usage,
                stop_reason=stop_reason,
            )

        return ChatInvokeCompletion(
            completion=content,
            thinking=thinking,
            usage=usage,
            stop_reason=stop_reason,
        )
