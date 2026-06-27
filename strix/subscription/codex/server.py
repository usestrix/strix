"""FastAPI server exposing an OpenAI-compatible /v1 endpoint backed by Codex."""
from __future__ import annotations

import json
import logging
import time
from typing import AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .auth import CODEX_BASE_URL, BorrowKeyError, borrow_codex_key
from .translator import (
    chat_to_responses,
    responses_to_chat,
    stream_responses_to_chat,
)

log = logging.getLogger("strix.subscription.codex.server")

app = FastAPI(title="strix-subscription-codex", version="0.1.0")

DEFAULT_MODELS = ["gpt-5.4", "gpt-5.4-mini", "gpt-5.4-nano"]


def _auth_headers() -> dict[str, str]:
    token, account_id = borrow_codex_key()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "OpenAI-Beta": "responses=experimental",
    }
    if account_id:
        headers["ChatGPT-Account-ID"] = account_id
    return headers


@app.get("/healthz")
async def healthz():
    try:
        borrow_codex_key()
        return {"ok": True}
    except BorrowKeyError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=503)


@app.get("/v1/models")
async def list_models():
    try:
        headers = _auth_headers()
    except BorrowKeyError as e:
        raise HTTPException(status_code=503, detail=str(e))

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                f"{CODEX_BASE_URL}/models?client_version=1.0.0",
                headers=headers,
            )
        r.raise_for_status()
        data = r.json()
        slugs = [
            m["slug"]
            for m in data.get("models", [])
            if m.get("supported_in_api") and m.get("visibility") == "list"
        ]
    except Exception as e:
        log.warning("failed to fetch codex models, falling back to defaults: %s", e)
        slugs = DEFAULT_MODELS

    return {
        "object": "list",
        "data": [
            {"id": slug, "object": "model", "created": int(time.time()), "owned_by": "openai-codex"}
            for slug in slugs
        ],
    }


@app.post("/v1/chat/completions")
async def chat_completions(req: Request):
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if "messages" not in body or "model" not in body:
        raise HTTPException(status_code=400, detail="`model` and `messages` are required")

    try:
        headers = _auth_headers()
    except BorrowKeyError as e:
        raise HTTPException(status_code=503, detail=str(e))

    responses_body = chat_to_responses(body)
    is_stream = bool(body.get("stream"))
    model = body["model"]

    if is_stream:
        return StreamingResponse(
            _stream(responses_body, headers, model=model),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # non-streaming: still hit the upstream as a stream and accumulate, since
    # the Codex endpoint always streams. We then build a single Chat Completions reply.
    responses_body_streamed = dict(responses_body)
    responses_body_streamed["stream"] = True

    accumulated = await _collect_full_response(responses_body_streamed, headers)
    return responses_to_chat(accumulated, model=model)


async def _stream(
    responses_body: dict, headers: dict, *, model: str
) -> AsyncIterator[bytes]:
    sse_iter = _codex_sse_events(responses_body, headers)
    async for chunk in stream_responses_to_chat(sse_iter, model=model):
        yield chunk


async def _codex_sse_events(
    responses_body: dict, headers: dict
) -> AsyncIterator[dict]:
    """Open an SSE stream against the Codex /responses endpoint and yield event dicts."""
    body = dict(responses_body)
    body["stream"] = True
    payload = json.dumps(body).encode()
    url = f"{CODEX_BASE_URL}/responses"

    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=600.0, write=30.0, pool=10.0)) as client:
        async with client.stream("POST", url, headers=headers, content=payload) as r:
            if r.status_code >= 400:
                error_body = (await r.aread()).decode(errors="replace")
                log.error("codex error %s: %s", r.status_code, error_body)
                yield {
                    "type": "error",
                    "error": {
                        "message": f"upstream error {r.status_code}: {error_body[:500]}",
                        "type": "upstream_error",
                    },
                }
                return

            current_event: str | None = None
            data_buf: list[str] = []
            async for line in r.aiter_lines():
                if line == "":
                    if data_buf:
                        raw = "\n".join(data_buf)
                        data_buf.clear()
                        if raw == "[DONE]":
                            current_event = None
                            continue
                        try:
                            ev = json.loads(raw)
                        except json.JSONDecodeError:
                            current_event = None
                            continue
                        if "type" not in ev and current_event:
                            ev["type"] = current_event
                        yield ev
                    current_event = None
                    continue

                if line.startswith(":"):
                    continue
                if line.startswith("event:"):
                    current_event = line[6:].strip()
                elif line.startswith("data:"):
                    data_buf.append(line[5:].lstrip())


async def _collect_full_response(responses_body: dict, headers: dict) -> dict:
    """Consume the upstream SSE stream and synthesize a complete `response` object.

    The streaming Codex backend delivers text via `response.output_text.delta` events
    and only sends a final `response.completed` envelope. We accumulate locally and
    use the final envelope just for `id` and `usage`.
    """
    text_parts: list[str] = []
    tool_calls_ordered: list[dict] = []
    tool_calls_by_key: dict[str, dict] = {}
    final_envelope: dict | None = None

    async for ev in _codex_sse_events(responses_body, headers):
        et = ev.get("type")
        if et == "response.completed":
            final_envelope = ev.get("response") or {}
        elif et == "response.output_text.delta":
            text_parts.append(ev.get("delta") or "")
        elif et == "response.output_item.added":
            item = ev.get("item") or {}
            if item.get("type") == "function_call":
                key = item.get("id") or item.get("call_id") or f"_{len(tool_calls_ordered)}"
                tc = {
                    "type": "function_call",
                    "id": item.get("id"),
                    "call_id": item.get("call_id"),
                    "name": item.get("name") or "",
                    "arguments": "",
                }
                tool_calls_by_key[key] = tc
                tool_calls_ordered.append(tc)
        elif et == "response.function_call_arguments.delta":
            key = ev.get("item_id") or ""
            tc = tool_calls_by_key.get(key)
            if tc is not None:
                tc["arguments"] += ev.get("delta") or ""
        elif et in ("response.failed", "response.error", "error"):
            err = ev.get("error") or (ev.get("response") or {}).get("error") or {}
            raise HTTPException(
                status_code=502, detail=err.get("message") or "upstream stream error"
            )

    output: list[dict] = []
    full_text = "".join(text_parts)
    if full_text:
        output.append(
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": full_text}],
            }
        )
    for tc in tool_calls_ordered:
        output.append(
            {
                "type": "function_call",
                "id": tc.get("id"),
                "call_id": tc.get("call_id"),
                "name": tc.get("name"),
                "arguments": tc.get("arguments") or "{}",
            }
        )

    return {
        "id": (final_envelope or {}).get("id"),
        "output": output,
        "usage": (final_envelope or {}).get("usage") or {},
    }
