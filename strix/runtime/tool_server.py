from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from typing import Any

import httpx
import uvicorn
import websockets
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, status
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ValidationError


SANDBOX_MODE = os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "true"
if not SANDBOX_MODE:
    raise RuntimeError("Tool server should only run in sandbox mode (STRIX_SANDBOX_MODE=true)")

parser = argparse.ArgumentParser(description="Start Strix tool server")
parser.add_argument("--token", required=True, help="Authentication token")
parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")  # nosec
parser.add_argument("--port", type=int, required=True, help="Port to bind to")
parser.add_argument(
    "--timeout",
    type=int,
    default=120,
    help="Hard timeout in seconds for each request execution (default: 120)",
)
parser.add_argument(
    "--cdp-upstream",
    default="http://127.0.0.1:19222",
    help="Chromium CDP upstream address (default: http://127.0.0.1:19222)",
)

args = parser.parse_args()
EXPECTED_TOKEN = args.token
REQUEST_TIMEOUT = args.timeout
CDP_UPSTREAM = args.cdp_upstream.rstrip("/")

app = FastAPI()
security = HTTPBearer()
security_dependency = Depends(security)

agent_tasks: dict[str, asyncio.Task[Any]] = {}


def verify_token(credentials: HTTPAuthorizationCredentials) -> str:
    if not credentials or credentials.scheme != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme. Bearer token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if credentials.credentials != EXPECTED_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials


def verify_ws_token(ws: WebSocket) -> None:
    auth = ws.headers.get("Authorization", "")
    token_param = ws.query_params.get("token")
    if auth == f"Bearer {EXPECTED_TOKEN}" or token_param == EXPECTED_TOKEN:
        return
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


class ToolExecutionRequest(BaseModel):
    agent_id: str
    tool_name: str
    kwargs: dict[str, Any]


class ToolExecutionResponse(BaseModel):
    result: Any | None = None
    error: str | None = None


async def _run_tool(agent_id: str, tool_name: str, kwargs: dict[str, Any]) -> Any:
    from strix.tools.argument_parser import convert_arguments
    from strix.tools.context import set_current_agent_id
    from strix.tools.registry import get_tool_by_name

    set_current_agent_id(agent_id)

    tool_func = get_tool_by_name(tool_name)
    if not tool_func:
        raise ValueError(f"Tool '{tool_name}' not found")

    converted_kwargs = convert_arguments(tool_func, kwargs)
    return await asyncio.to_thread(tool_func, **converted_kwargs)


@app.post("/execute", response_model=ToolExecutionResponse)
async def execute_tool(
    request: ToolExecutionRequest, credentials: HTTPAuthorizationCredentials = security_dependency
) -> ToolExecutionResponse:
    verify_token(credentials)

    agent_id = request.agent_id

    if agent_id in agent_tasks:
        old_task = agent_tasks[agent_id]
        if not old_task.done():
            old_task.cancel()

    task = asyncio.create_task(
        asyncio.wait_for(
            _run_tool(agent_id, request.tool_name, request.kwargs), timeout=REQUEST_TIMEOUT
        )
    )
    agent_tasks[agent_id] = task

    try:
        result = await task
        return ToolExecutionResponse(result=result)

    except asyncio.CancelledError:
        return ToolExecutionResponse(error="Cancelled by newer request")

    except TimeoutError:
        return ToolExecutionResponse(error=f"Tool timed out after {REQUEST_TIMEOUT}s")

    except ValidationError as e:
        return ToolExecutionResponse(error=f"Invalid arguments: {e}")

    except (ValueError, RuntimeError, ImportError) as e:
        return ToolExecutionResponse(error=f"Tool execution error: {e}")

    except Exception as e:  # noqa: BLE001
        return ToolExecutionResponse(error=f"Unexpected error: {e}")

    finally:
        if agent_tasks.get(agent_id) is task:
            del agent_tasks[agent_id]


@app.post("/register_agent")
async def register_agent(
    agent_id: str, credentials: HTTPAuthorizationCredentials = security_dependency
) -> dict[str, str]:
    verify_token(credentials)
    return {"status": "registered", "agent_id": agent_id}


async def _check_cdp_health() -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
            resp = await client.get(f"{CDP_UPSTREAM}/json/version")
            if resp.status_code == 200:
                return {"status": "healthy"}
            return {"status": "unhealthy"}
    except Exception:  # noqa: BLE001
        return {"status": "unhealthy"}


@app.get("/health")
async def health_check() -> dict[str, Any]:
    cdp_health = await _check_cdp_health()
    return {
        "status": "healthy",
        "sandbox_mode": str(SANDBOX_MODE),
        "environment": "sandbox" if SANDBOX_MODE else "main",
        "auth_configured": "true" if EXPECTED_TOKEN else "false",
        "active_agents": len(agent_tasks),
        "agents": list(agent_tasks.keys()),
        "chromium_cdp": cdp_health,
    }


# -- CDP auth proxy ----------------------------------------------------------
# Proxies HTTP and WebSocket traffic to the container-local Chromium CDP.


def _cdp_upstream_url(path: str) -> str:
    # Strip the /cdp/proxy prefix to get the upstream path
    suffix = path.removeprefix("/cdp/proxy")
    return f"{CDP_UPSTREAM}{suffix}"


@app.websocket("/cdp/proxy/{path:path}")
async def cdp_proxy_ws(ws: WebSocket, path: str) -> None:  # noqa: ARG001
    verify_ws_token(ws)
    url = _cdp_upstream_url(ws.url.path).replace("http", "ws", 1)
    await ws.accept()

    async with websockets.connect(url) as upstream:

        async def relay_client_to_upstream() -> None:
            async for msg in ws.iter_text():
                await upstream.send(msg)

        async def relay_upstream_to_client() -> None:
            async for msg in upstream:
                if isinstance(msg, str):
                    await ws.send_text(msg)
                else:
                    await ws.send_bytes(msg)

        _, pending = await asyncio.wait(
            [
                asyncio.create_task(relay_client_to_upstream()),
                asyncio.create_task(relay_upstream_to_client()),
            ],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()


@app.api_route(
    "/cdp/proxy/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def cdp_proxy_http(
    request: Request,
    path: str,  # noqa: ARG001
    credentials: HTTPAuthorizationCredentials = security_dependency,
) -> Response:
    verify_token(credentials)
    url = _cdp_upstream_url(request.url.path)
    headers = {
        k: v for k, v in request.headers.items() if k.lower() not in ("host", "authorization")
    }

    async with httpx.AsyncClient() as client:
        resp = await client.request(
            request.method,
            url,
            headers=headers,
            content=await request.body(),
        )

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers={k: v for k, v in resp.headers.items() if k.lower() != "transfer-encoding"},
    )


def signal_handler(_signum: int, _frame: Any) -> None:
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    for task in agent_tasks.values():
        task.cancel()
    sys.exit(0)


if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
