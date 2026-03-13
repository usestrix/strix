#!/usr/bin/env python3
import asyncio
import logging
import os
import re
from typing import Any

import aiohttp
from aiohttp import WSMsgType, web


logger = logging.getLogger(__name__)

TOKEN = os.environ["TOOL_SERVER_TOKEN"]
LISTEN_PORT = int(os.environ.get("CDP_PORT", "9222"))
UPSTREAM = f"http://127.0.0.1:{os.environ.get('CDP_INTERNAL_PORT', '19222')}"


def _is_authorized(req: web.Request) -> bool:
    auth_header: str = req.headers.get("Authorization", "")
    token_param: str | None = req.query.get("token")
    return auth_header == f"Bearer {TOKEN}" or token_param == TOKEN


def _strip_token(url: str) -> str:
    return re.sub(r"[?&]token=[^&]*", "", url).replace("?&", "?").rstrip("?")


async def _proxy_ws(req: web.Request, url: str, headers: dict[str, Any]) -> web.WebSocketResponse:
    client_ws = web.WebSocketResponse()
    await client_ws.prepare(req)

    async with (
        aiohttp.ClientSession() as session,
        session.ws_connect(url.replace("http", "ws", 1), headers=headers) as upstream_ws,
    ):

        async def relay(src: Any, dst: Any) -> None:
            async for msg in src:
                if msg.type == WSMsgType.TEXT:
                    await dst.send_str(msg.data)
                elif msg.type == WSMsgType.BINARY:
                    await dst.send_bytes(msg.data)
                else:
                    logger.warning("Unexpected WebSocket message type: %s", msg.type)
                    break

        await asyncio.gather(
            relay(upstream_ws, client_ws),
            relay(client_ws, upstream_ws),
            return_exceptions=True,
        )
        return client_ws


async def _proxy_http(req: web.Request, url: str, headers: dict[str, Any]) -> web.StreamResponse:
    async with (
        aiohttp.ClientSession() as session,
        session.request(req.method, url, headers=headers, data=await req.read()) as resp,
    ):
        out = web.StreamResponse(
            status=resp.status,
            headers={k: v for k, v in resp.headers.items() if k.lower() != "transfer-encoding"},
        )
        await out.prepare(req)
        async for chunk in resp.content.iter_any():
            await out.write(chunk)
        return out


async def _handle(req: web.Request) -> web.StreamResponse:
    if not _is_authorized(req):
        return web.Response(status=401, text="Unauthorized")

    url = _strip_token(f"{UPSTREAM}{req.path_qs}")
    headers = {k: v for k, v in req.headers.items() if k.lower() not in ("host", "authorization")}

    if req.headers.get("Upgrade", "").lower() == "websocket":
        return await _proxy_ws(req, url, headers)
    return await _proxy_http(req, url, headers)


app = web.Application()
app.router.add_route("*", "/{path:.*}", _handle)

if __name__ == "__main__":
    logger.info("CDP auth proxy: 0.0.0.0:%s -> %s", LISTEN_PORT, UPSTREAM)
    web.run_app(app, host="0.0.0.0", port=LISTEN_PORT, print=None)
