"""
Bidirectional translation between OpenAI Chat Completions and Responses API.

Strix/LiteLLM speak Chat Completions (`/chat/completions`).
The ChatGPT Codex backend only speaks the Responses API (`/responses`).
This module bridges the two formats, including streaming SSE.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, AsyncIterator, Iterable

# ---------- request: chat completions -> responses ----------


def chat_to_responses(payload: dict) -> dict:
    """Convert a Chat Completions request body to a Responses API request body."""
    out: dict[str, Any] = {
        "model": payload["model"],
        "store": False,
    }

    instructions, input_items = _messages_to_input(payload.get("messages", []))
    out["instructions"] = instructions or "You are a helpful assistant."
    out["input"] = input_items

    if payload.get("stream"):
        out["stream"] = True

    if (v := payload.get("max_tokens")) is not None:
        out["max_output_tokens"] = v
    if (v := payload.get("max_completion_tokens")) is not None:
        out["max_output_tokens"] = v
    for k in ("temperature", "top_p"):
        if (v := payload.get(k)) is not None:
            out[k] = v

    if (v := payload.get("reasoning_effort")) is not None:
        out["reasoning"] = {"effort": v}

    tools = payload.get("tools")
    if tools:
        out["tools"] = [_chat_tool_to_responses_tool(t) for t in tools if t]
    if (tc := payload.get("tool_choice")) is not None:
        out["tool_choice"] = tc

    rf = payload.get("response_format")
    if isinstance(rf, dict):
        if rf.get("type") == "json_schema":
            schema_block = rf.get("json_schema") or {}
            out["text"] = {
                "format": {
                    "type": "json_schema",
                    "name": schema_block.get("name") or "output",
                    "schema": schema_block.get("schema") or {},
                }
            }
        elif rf.get("type") == "json_object":
            out["text"] = {"format": {"type": "json_object"}}

    return out


def _messages_to_input(messages: list[dict]) -> tuple[str, list[dict]]:
    """Split chat completions messages into (instructions, input items)."""
    instructions_parts: list[str] = []
    items: list[dict] = []

    for msg in messages:
        role = msg.get("role")
        content = msg.get("content")

        if role == "system" or role == "developer":
            instructions_parts.append(_flatten_text_content(content))
            continue

        if role == "tool":
            items.append(
                {
                    "type": "function_call_output",
                    "call_id": msg.get("tool_call_id") or "",
                    "output": _flatten_text_content(content),
                }
            )
            continue

        if role == "assistant":
            text = _flatten_text_content(content)
            tool_calls = msg.get("tool_calls") or []
            if text:
                items.append({"role": "assistant", "content": text})
            for tc in tool_calls:
                fn = tc.get("function") or {}
                items.append(
                    {
                        "type": "function_call",
                        "call_id": tc.get("id") or "",
                        "name": fn.get("name") or "",
                        "arguments": fn.get("arguments") or "{}",
                    }
                )
            continue

        if role == "user":
            items.append({"role": "user", "content": _user_content_blocks(content)})
            continue

    instructions = "\n\n".join(p for p in instructions_parts if p)
    return instructions, items


def _flatten_text_content(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") in ("text", "input_text", "output_text"):
                    parts.append(block.get("text") or "")
                elif "text" in block:
                    parts.append(block["text"] or "")
        return "".join(parts)
    return str(content)


def _user_content_blocks(content: Any) -> list[dict]:
    if isinstance(content, str):
        return [{"type": "input_text", "text": content}]
    if isinstance(content, list):
        out = []
        for block in content:
            if not isinstance(block, dict):
                out.append({"type": "input_text", "text": str(block)})
                continue
            t = block.get("type")
            if t in ("text", "input_text"):
                out.append({"type": "input_text", "text": block.get("text") or ""})
            elif t == "image_url":
                url = block.get("image_url")
                if isinstance(url, dict):
                    url = url.get("url")
                out.append({"type": "input_image", "image_url": url, "detail": "low"})
            elif t == "input_image":
                out.append(block)
            else:
                if "text" in block:
                    out.append({"type": "input_text", "text": block["text"]})
        return out or [{"type": "input_text", "text": ""}]
    return [{"type": "input_text", "text": str(content) if content else ""}]


def _chat_tool_to_responses_tool(tool: dict) -> dict:
    fn = tool.get("function") or {}
    return {
        "type": "function",
        "name": fn.get("name") or "",
        "description": fn.get("description"),
        "parameters": fn.get("parameters") or {"type": "object", "properties": {}},
        "strict": False,
    }


# ---------- response: responses -> chat completions (non-streaming) ----------


def responses_to_chat(resp: dict, *, model: str) -> dict:
    """Convert a non-streaming Responses API result to a Chat Completions result."""
    text_parts: list[str] = []
    tool_calls: list[dict] = []
    finish_reason = "stop"

    for item in resp.get("output", []) or []:
        item_type = item.get("type")
        if item_type == "message":
            for block in item.get("content", []) or []:
                if block.get("type") == "output_text":
                    text_parts.append(block.get("text") or "")
        elif item_type == "function_call":
            tool_calls.append(
                {
                    "id": item.get("call_id") or item.get("id") or _short_id("call"),
                    "type": "function",
                    "function": {
                        "name": item.get("name") or "",
                        "arguments": item.get("arguments") or "{}",
                    },
                }
            )

    if tool_calls:
        finish_reason = "tool_calls"

    message: dict[str, Any] = {"role": "assistant", "content": "".join(text_parts) or None}
    if tool_calls:
        message["tool_calls"] = tool_calls

    usage_in = resp.get("usage") or {}
    usage_out = {
        "prompt_tokens": usage_in.get("input_tokens", 0),
        "completion_tokens": usage_in.get("output_tokens", 0),
        "total_tokens": usage_in.get("total_tokens")
        or (usage_in.get("input_tokens", 0) + usage_in.get("output_tokens", 0)),
    }

    return {
        "id": resp.get("id") or _short_id("chatcmpl"),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": finish_reason,
            }
        ],
        "usage": usage_out,
    }


# ---------- response: responses SSE stream -> chat completions SSE stream ----------


async def stream_responses_to_chat(
    sse_events: AsyncIterator[dict], *, model: str
) -> AsyncIterator[bytes]:
    """Translate a stream of Responses SSE event dicts into Chat Completions SSE bytes."""
    chunk_id = _short_id("chatcmpl")
    created = int(time.time())
    role_sent = False
    tool_call_index_by_item: dict[str, int] = {}
    next_tool_index = 0
    finish_reason = "stop"
    final_usage: dict | None = None

    def chunk(delta: dict, finish: str | None = None) -> bytes:
        body = {
            "id": chunk_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": delta,
                    "finish_reason": finish,
                }
            ],
        }
        return f"data: {json.dumps(body)}\n\n".encode()

    async for ev in sse_events:
        et = ev.get("type")

        if et == "response.output_text.delta":
            if not role_sent:
                yield chunk({"role": "assistant", "content": ""})
                role_sent = True
            delta = ev.get("delta") or ""
            yield chunk({"content": delta})

        elif et == "response.output_item.added":
            item = ev.get("item") or {}
            if item.get("type") == "function_call":
                if not role_sent:
                    yield chunk({"role": "assistant", "content": None})
                    role_sent = True
                item_id = item.get("id") or item.get("call_id") or _short_id("item")
                idx = next_tool_index
                next_tool_index += 1
                tool_call_index_by_item[item_id] = idx
                finish_reason = "tool_calls"
                yield chunk(
                    {
                        "tool_calls": [
                            {
                                "index": idx,
                                "id": item.get("call_id")
                                or item.get("id")
                                or _short_id("call"),
                                "type": "function",
                                "function": {
                                    "name": item.get("name") or "",
                                    "arguments": "",
                                },
                            }
                        ]
                    }
                )

        elif et == "response.function_call_arguments.delta":
            item_id = ev.get("item_id") or ""
            idx = tool_call_index_by_item.get(item_id, 0)
            yield chunk(
                {
                    "tool_calls": [
                        {
                            "index": idx,
                            "function": {"arguments": ev.get("delta") or ""},
                        }
                    ]
                }
            )

        elif et == "response.completed":
            resp = ev.get("response") or {}
            usage_in = resp.get("usage") or {}
            final_usage = {
                "prompt_tokens": usage_in.get("input_tokens", 0),
                "completion_tokens": usage_in.get("output_tokens", 0),
                "total_tokens": usage_in.get("total_tokens")
                or (
                    usage_in.get("input_tokens", 0) + usage_in.get("output_tokens", 0)
                ),
            }

        elif et in ("response.failed", "response.error", "error"):
            err = ev.get("response", {}).get("error") or ev.get("error") or {"message": "stream error"}
            payload = {"error": {"message": err.get("message", "stream error"), "type": err.get("type", "server_error")}}
            yield f"data: {json.dumps(payload)}\n\n".encode()
            yield b"data: [DONE]\n\n"
            return

    final_chunk: dict = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
    }
    if final_usage is not None:
        final_chunk["usage"] = final_usage
    yield f"data: {json.dumps(final_chunk)}\n\n".encode()
    yield b"data: [DONE]\n\n"


def _short_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:24]}"
