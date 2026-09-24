"""Flatten list-shaped chat-completions content from OpenAI-compatible providers.

Reasoning models behind OpenAI-compatible endpoints sometimes return the
assistant content as a list of content blocks (for example
``[{"type": "thinking", ...}, {"type": "text", "text": "OK"}]``) instead of a
plain string.

``install()`` wraps the two SDK entry points that consume chat-completions
content, flattening list-shaped ``message.content`` and ``delta.content`` into
the concatenated ``text`` blocks before the SDK sees them. Non-text blocks
(e.g. ``thinking``) and unknown block types are ignored.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, cast


logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


def _flatten_list_content(content: object) -> Any:
    """Concatenate the ``text`` blocks of list-shaped content; pass anything else through."""
    if not isinstance(content, list):
        return content
    texts: list[str] = []
    blocks = cast("list[Any]", content)  # type: ignore[redundant-cast]
    for part in blocks:
        if not isinstance(part, dict):
            continue
        block = cast("dict[str, Any]", part)
        if block.get("type") == "text":
            text = block.get("text")
            if isinstance(text, str):
                texts.append(text)
    return "".join(texts)


async def _flatten_chunk_stream(stream: AsyncIterator[Any]) -> AsyncIterator[Any]:
    async for chunk in stream:
        choices: list[Any] = getattr(chunk, "choices", None) or []
        for choice in choices:
            delta: Any = getattr(choice, "delta", None)
            content = getattr(delta, "content", None)
            if delta is not None and isinstance(content, list):
                blocks = cast("list[Any]", content)  # type: ignore[redundant-cast]
                choice.delta = delta.model_copy(update={"content": _flatten_list_content(blocks)})
        yield chunk


_installed = False


def install() -> None:
    """Wrap the SDK chat-completions content entry points (idempotent)."""
    global _installed  # noqa: PLW0603
    if _installed:
        return
    try:
        _install_wrappers()
    except Exception:  # noqa: BLE001 - a transient failure retries on the next install() call
        logger.warning("could not wrap the SDK chat-completions content handling", exc_info=True)
        return
    _installed = True


def _install_wrappers() -> None:
    from agents.models import chatcmpl_converter
    from agents.models.chatcmpl_stream_handler import ChatCmplStreamHandler

    # 0.19.0 names it Converter; later 0.19.x releases renamed it ChatCmplConverter.
    converter_cls = getattr(chatcmpl_converter, "ChatCmplConverter", None) or (
        chatcmpl_converter.Converter
    )

    convert = converter_cls.__dict__["message_to_output_items"].__func__
    handle_stream = ChatCmplStreamHandler.__dict__["handle_stream"].__func__

    def message_to_output_items(cls: Any, message: Any, *args: Any, **kwargs: Any) -> Any:
        content = getattr(message, "content", None)
        if isinstance(content, list):
            blocks = cast("list[Any]", content)  # type: ignore[redundant-cast]
            message = message.model_copy(update={"content": _flatten_list_content(blocks)})
        return convert(cls, message, *args, **kwargs)

    def handle_list_content_stream(
        cls: Any, response: Any, stream: AsyncIterator[Any], *args: Any, **kwargs: Any
    ) -> Any:
        return handle_stream(cls, response, _flatten_chunk_stream(stream), *args, **kwargs)

    converter_cls.message_to_output_items = classmethod(message_to_output_items)  # type: ignore[method-assign]
    ChatCmplStreamHandler.handle_stream = classmethod(handle_list_content_stream)  # type: ignore[assignment]
    _installed = True
