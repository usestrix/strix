"""Accept chat completions whose message content is a list of blocks.

Some OpenAI-compatible endpoints return ``message.content`` as a list of typed
blocks instead of a string. Mistral does this for its reasoning models, for
example ``[{"type": "thinking", "thinking": [...]}, {"type": "text", "text":
"OK"}]``, both in full responses and in each streamed ``delta.content``. The
SDK's chat-completions converter and stream handler assume a string and fail
validation on the first call, which surfaces as LLM CONNECTION FAILED even
though the endpoint answered normally.

:class:`BlockTolerantChatCompletionsModel` flattens that content before the SDK
reads it. Text blocks become the string content. Thinking blocks become
``reasoning_content``, which the SDK already turns into a reasoning item and
does not replay to non-DeepSeek models. Block types Strix does not know are
skipped rather than treated as an error. String content passes through as is.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Literal, cast, overload

from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable

    from agents.agent_output import AgentOutputSchemaBase
    from agents.handoffs import Handoff
    from agents.items import TResponseInputItem
    from agents.model_settings import ModelSettings
    from agents.models.interface import Model, ModelTracing
    from agents.tool import Tool
    from agents.tracing import GenerationSpanData, Span
    from openai import AsyncStream
    from openai.types.chat import ChatCompletion, ChatCompletionChunk
    from openai.types.responses import Response, ResponsePromptParam


logger = logging.getLogger(__name__)

_TEXT_BLOCK_TYPES = frozenset({"text", "output_text"})
_THINKING_BLOCK_TYPES = frozenset({"thinking", "reasoning"})


def _field(block: Any, name: str) -> Any:
    if isinstance(block, dict):
        return cast("dict[str, Any]", block).get(name)
    return getattr(block, name, None)


def _text_of(value: Any) -> str:
    """The text in a block field: a string, or a list of text chunks (Mistral's thinking)."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(
            part if isinstance(part, str) else _text_of(_field(part, "text"))
            for part in cast("Iterable[Any]", value)
        )
    return ""


def split_content_blocks(blocks: Iterable[Any]) -> tuple[str, str]:
    """Split list-shaped message content into ``(text, thinking)``."""
    text: list[str] = []
    thinking: list[str] = []
    for block in blocks:
        if isinstance(block, str):
            text.append(block)
            continue
        kind = _field(block, "type")
        if kind in _TEXT_BLOCK_TYPES:
            text.append(_text_of(_field(block, "text")))
        elif kind in _THINKING_BLOCK_TYPES:
            body = _field(block, "thinking")
            thinking.append(_text_of(body if body is not None else _field(block, "text")))
        else:
            logger.debug("Skipping unsupported content block type %r", kind)
    return "".join(text), "".join(thinking)


def flatten_message_content(message: Any) -> None:
    """Rewrite a list-valued ``content`` on a message or stream delta in place."""
    content = getattr(message, "content", None)
    if not isinstance(content, list):
        return
    text, thinking = split_content_blocks(cast("Iterable[Any]", content))
    message.content = text or None
    if thinking and not getattr(message, "reasoning_content", None):
        message.reasoning_content = thinking


class _FlattenedStream:
    """An ``AsyncStream`` of chunks whose deltas have been flattened."""

    def __init__(self, stream: AsyncStream[ChatCompletionChunk]) -> None:
        self._stream = stream

    def __aiter__(self) -> AsyncIterator[ChatCompletionChunk]:
        return self._chunks()

    async def _chunks(self) -> AsyncIterator[ChatCompletionChunk]:
        async for chunk in self._stream:
            for choice in chunk.choices:
                flatten_message_content(choice.delta)
            yield chunk

    async def aclose(self) -> None:
        await self._stream.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


class BlockTolerantChatCompletionsModel(OpenAIChatCompletionsModel):
    """Chat-completions model that accepts list-shaped message content."""

    @classmethod
    def from_stock(cls, model: OpenAIChatCompletionsModel) -> BlockTolerantChatCompletionsModel:
        return cls(
            model=model.model,
            openai_client=model._client,
            should_replay_reasoning_content=model.should_replay_reasoning_content,
            strict_feature_validation=model._strict_feature_validation,
            buffer_streamed_tool_calls=model._buffer_streamed_tool_calls,
        )

    @overload
    async def _fetch_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        span: Span[GenerationSpanData],
        tracing: ModelTracing,
        stream: Literal[True],
        prompt: ResponsePromptParam | None = None,
    ) -> tuple[Response, AsyncStream[ChatCompletionChunk]]: ...

    @overload
    async def _fetch_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        span: Span[GenerationSpanData],
        tracing: ModelTracing,
        stream: Literal[False],
        prompt: ResponsePromptParam | None = None,
    ) -> ChatCompletion: ...

    async def _fetch_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],  # noqa: A002 - matches the SDK signature
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        span: Span[GenerationSpanData],
        tracing: ModelTracing,
        stream: bool = False,
        prompt: ResponsePromptParam | None = None,
    ) -> ChatCompletion | tuple[Response, AsyncStream[ChatCompletionChunk]]:
        args = (system_instructions, input, model_settings, tools, output_schema, handoffs)
        if stream:
            response, chunks = await super()._fetch_response(
                *args, span, tracing, stream=True, prompt=prompt
            )
            # handle_stream only iterates and closes the stream.
            return response, cast("AsyncStream[ChatCompletionChunk]", _FlattenedStream(chunks))
        completion = await super()._fetch_response(
            *args, span, tracing, stream=False, prompt=prompt
        )
        for choice in completion.choices:
            flatten_message_content(choice.message)
        return completion


def tolerate_content_blocks(model: Model) -> Model:
    """Swap the SDK's stock chat-completions model for the block-tolerant one.

    Only the exact stock class is replaced, so a caller's own subclass is left
    alone. Every other model is returned unchanged.
    """
    if type(model) is not OpenAIChatCompletionsModel:
        return model
    return BlockTolerantChatCompletionsModel.from_stock(model)
