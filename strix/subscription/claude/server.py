"""FastAPI proxy exposing Anthropic-compatible message endpoints backed by
the user's Claude Code subscription (OAuth) instead of an API key.

Strix (via litellm's `anthropic/` provider) POSTs Anthropic Messages requests
here; the proxy swaps the dummy x-api-key for the borrowed Claude Code OAuth
Bearer token (+ required beta/version headers), lightly massages the body, and
forwards to https://api.anthropic.com/v1/messages. Streaming is a raw SSE byte
passthrough — no format translation.
"""
from __future__ import annotations

import json
import logging
import os
import time

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from .auth import ANTHROPIC_BASE_URL, BorrowKeyError, borrow_claude_key
from .payload import build_forward_headers, transform_body

log = logging.getLogger("strix.subscription.claude.server")

app = FastAPI(title="strix-subscription-claude", version="0.1.0")

TIMEOUT = httpx.Timeout(connect=10.0, read=600.0, write=30.0, pool=10.0)

ADVERTISED_MODELS = ["claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5"]


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off", "")


def _transform(body: dict) -> dict:
    return transform_body(
        body,
        default_model=_env("STRIX_SUB_CLAUDE_DEFAULT_MODEL", "claude-opus-4-8"),
        max_tokens=int(_env("STRIX_SUB_CLAUDE_MAX_TOKENS", "32000")),
        inject_system_prompt=_bool_env("STRIX_SUB_CLAUDE_INJECT_SYSTEM_PROMPT", True),
        strip_prefill=_bool_env("STRIX_SUB_CLAUDE_STRIP_PREFILL", True),
        inject_thinking=_bool_env("STRIX_SUB_CLAUDE_INJECT_THINKING", False),
        effort=_env("STRIX_SUB_CLAUDE_EFFORT", "high"),
    )


def _upstream_url() -> str:
    # Claude Code / litellm hit /v1/messages?beta=true.
    return f"{ANTHROPIC_BASE_URL}/v1/messages?beta=true"


@app.get("/healthz")
async def healthz():
    try:
        borrow_claude_key()
        return {"ok": True}
    except BorrowKeyError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=503)


@app.get("/models")
@app.get("/{prefix:path}/models")
async def list_models(prefix: str = ""):
    _ensure_v1_prefix(prefix)
    return {
        "object": "list",
        "data": [
            {"id": m, "object": "model", "created": int(time.time()), "owned_by": "anthropic"}
            for m in ADVERTISED_MODELS
        ],
    }


@app.post("/messages")
@app.post("/{prefix:path}/messages")
async def messages(req: Request, prefix: str = ""):
    _ensure_v1_prefix(prefix)
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    try:
        token = borrow_claude_key()
    except BorrowKeyError as e:
        raise HTTPException(status_code=503, detail=str(e))

    out_body = _transform(body)
    headers = build_forward_headers(req.headers, token)
    payload = json.dumps(out_body).encode()
    url = _upstream_url()

    if bool(out_body.get("stream")):
        return await _proxy_stream(url, headers, payload)
    return await _proxy_once(url, headers, payload)


def _ensure_v1_prefix(prefix: str) -> None:
    """Allow /messages, /v1/messages, /v1/v1/messages, etc.; reject other prefixes."""
    if not prefix:
        return
    if any(part != "v1" for part in prefix.split("/")):
        raise HTTPException(status_code=404, detail="Not Found")


async def _proxy_stream(url: str, headers: dict, payload: bytes) -> Response:
    client = httpx.AsyncClient(timeout=TIMEOUT)
    try:
        r = await client.send(
            client.build_request("POST", url, headers=headers, content=payload),
            stream=True,
        )
    except Exception as e:
        await client.aclose()
        raise HTTPException(status_code=502, detail=f"upstream connection error: {e}")

    # Check status before committing to a streaming response so upstream errors
    # (e.g. the OAuth "out of extra usage" 400) surface with their real body.
    if r.status_code >= 400:
        err = await r.aread()
        ctype = r.headers.get("content-type", "application/json")
        await r.aclose()
        await client.aclose()
        log.error("anthropic error %s: %s", r.status_code, err[:500].decode(errors="replace"))
        return Response(content=err, status_code=r.status_code, media_type=ctype)

    async def gen():
        try:
            async for chunk in r.aiter_raw():
                yield chunk
        finally:
            await r.aclose()
            await client.aclose()

    return StreamingResponse(
        gen(),
        status_code=r.status_code,
        media_type=r.headers.get("content-type", "text/event-stream"),
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def _proxy_once(url: str, headers: dict, payload: bytes) -> Response:
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.post(url, headers=headers, content=payload)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"upstream connection error: {e}")

    if r.status_code >= 400:
        log.error("anthropic error %s: %s", r.status_code, r.text[:500])
    return Response(
        content=r.content,
        status_code=r.status_code,
        media_type=r.headers.get("content-type", "application/json"),
    )
