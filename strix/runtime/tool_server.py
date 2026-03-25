from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ValidationError

from strix.config import Config
from strix.runtime.context import configure_runtime_context


security = HTTPBearer()
security_dependency = Depends(security)


class ToolExecutionRequest(BaseModel):
    agent_id: str
    tool_name: str
    kwargs: dict[str, Any]


class ToolExecutionResponse(BaseModel):
    result: Any | None = None
    error: str | None = None


def build_parser() -> argparse.ArgumentParser:
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
        "--config",
        type=str,
        help="Path to the runtime config file used inside the sandbox",
    )
    parser.add_argument(
        "--sandbox-mode",
        action="store_true",
        help="Mark this tool server as running inside sandbox mode",
    )
    parser.add_argument(
        "--caido-api-token",
        type=str,
        help="Internal Caido API token for proxy tooling inside the sandbox",
    )
    return parser


def verify_token(
    credentials: HTTPAuthorizationCredentials,
    expected_token: str,
) -> str:
    if not credentials or credentials.scheme != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme. Bearer token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if credentials.credentials != expected_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials


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


def create_app(
    expected_token: str,
    request_timeout: int,
    sandbox_mode: bool,
) -> FastAPI:
    app = FastAPI()
    app.state.expected_token = expected_token
    app.state.request_timeout = request_timeout
    app.state.sandbox_mode = sandbox_mode
    app.state.agent_tasks = {}

    @app.on_event("shutdown")
    async def shutdown_event() -> None:
        for task in list(app.state.agent_tasks.values()):
            task.cancel()

    @app.post("/execute", response_model=ToolExecutionResponse)
    async def execute_tool(
        request: ToolExecutionRequest,
        http_request: Request,
        credentials: HTTPAuthorizationCredentials = security_dependency,
    ) -> ToolExecutionResponse:
        verify_token(credentials, http_request.app.state.expected_token)

        agent_id = request.agent_id
        agent_tasks: dict[str, asyncio.Task[Any]] = http_request.app.state.agent_tasks

        if agent_id in agent_tasks:
            old_task = agent_tasks[agent_id]
            if not old_task.done():
                old_task.cancel()

        task = asyncio.create_task(
            asyncio.wait_for(
                _run_tool(agent_id, request.tool_name, request.kwargs),
                timeout=http_request.app.state.request_timeout,
            )
        )
        agent_tasks[agent_id] = task

        try:
            result = await task
            return ToolExecutionResponse(result=result)
        except asyncio.CancelledError:
            return ToolExecutionResponse(error="Cancelled by newer request")
        except TimeoutError:
            return ToolExecutionResponse(
                error=f"Tool timed out after {http_request.app.state.request_timeout}s"
            )
        except ValidationError as exc:
            return ToolExecutionResponse(error=f"Invalid arguments: {exc}")
        except (ValueError, RuntimeError, ImportError) as exc:
            return ToolExecutionResponse(error=f"Tool execution error: {exc}")
        except Exception as exc:  # noqa: BLE001
            return ToolExecutionResponse(error=f"Unexpected error: {exc}")
        finally:
            if agent_tasks.get(agent_id) is task:
                del agent_tasks[agent_id]

    @app.post("/register_agent")
    async def register_agent(
        agent_id: str,
        http_request: Request,
        credentials: HTTPAuthorizationCredentials = security_dependency,
    ) -> dict[str, str]:
        verify_token(credentials, http_request.app.state.expected_token)
        return {"status": "registered", "agent_id": agent_id}

    @app.get("/health")
    async def health_check(http_request: Request) -> dict[str, Any]:
        agent_tasks: dict[str, asyncio.Task[Any]] = http_request.app.state.agent_tasks
        return {
            "status": "healthy",
            "sandbox_mode": str(http_request.app.state.sandbox_mode).lower(),
            "environment": "sandbox" if http_request.app.state.sandbox_mode else "main",
            "auth_configured": "true" if http_request.app.state.expected_token else "false",
            "active_agents": len(agent_tasks),
            "agents": list(agent_tasks.keys()),
        }

    return app


def main() -> None:
    args = build_parser().parse_args()

    if args.config:
        Config.set_config_file(Path(args.config))
    else:
        Config.reload()

    sandbox_mode = args.sandbox_mode
    if not sandbox_mode:
        raise RuntimeError("Tool server should only run in sandbox mode")

    configure_runtime_context(
        sandbox_mode=sandbox_mode,
        caido_api_token=args.caido_api_token or Config.get_str("caido_api_token"),
    )

    app = create_app(
        expected_token=args.token,
        request_timeout=args.timeout,
        sandbox_mode=sandbox_mode,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
