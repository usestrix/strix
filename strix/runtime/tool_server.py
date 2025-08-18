from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from multiprocessing import Process, Queue
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ValidationError


SANDBOX_MODE = os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "true"
if not SANDBOX_MODE:
    raise RuntimeError("Tool server should only run in sandbox mode (STRIX_SANDBOX_MODE=true)")

parser = argparse.ArgumentParser(description="Start Strix tool server")
parser.add_argument("--token", required=True, help="Authentication token")
parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")  # nosec
parser.add_argument("--port", type=int, required=True, help="Port to bind to")

args = parser.parse_args()
EXPECTED_TOKEN = args.token

app = FastAPI()
security = HTTPBearer()

security_dependency = Depends(security)

agent_processes: dict[str, dict[str, Any]] = {}
agent_queues: dict[str, dict[str, Queue[Any]]] = {}


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


class ToolExecutionRequest(BaseModel):
    agent_id: str
    tool_name: str
    kwargs: dict[str, Any]


class ToolExecutionResponse(BaseModel):
    result: Any | None = None
    error: str | None = None


def agent_worker(_agent_id: str, request_queue: Queue[Any], response_queue: Queue[Any]) -> None:
    null_handler = logging.NullHandler()

    root_logger = logging.getLogger()
    root_logger.handlers = [null_handler]
    root_logger.setLevel(logging.CRITICAL)

    from strix.tools.argument_parser import ArgumentConversionError, convert_arguments
    from strix.tools.registry import get_tool_by_name

    while True:
        try:
            request = request_queue.get()

            if request is None:
                break

            tool_name = request["tool_name"]
            kwargs = request["kwargs"]

            try:
                tool_func = get_tool_by_name(tool_name)
                if not tool_func:
                    response_queue.put({"error": f"Tool '{tool_name}' not found"})
                    continue

                converted_kwargs = convert_arguments(tool_func, kwargs)
                result = tool_func(**converted_kwargs)

                response_queue.put({"result": result})

            except (ArgumentConversionError, ValidationError) as e:
                response_queue.put({"error": f"Invalid arguments: {e}"})
            except (RuntimeError, ValueError, ImportError) as e:
                response_queue.put({"error": f"Tool execution error: {e}"})

        except (RuntimeError, ValueError, ImportError) as e:
            response_queue.put({"error": f"Worker error: {e}"})


def ensure_agent_process(agent_id: str) -> tuple[Queue[Any], Queue[Any]]:
    if agent_id not in agent_processes:
        request_queue: Queue[Any] = Queue()
        response_queue: Queue[Any] = Queue()

        process = Process(
            target=agent_worker, args=(agent_id, request_queue, response_queue), daemon=True
        )
        process.start()

        agent_processes[agent_id] = {"process": process, "pid": process.pid}
        agent_queues[agent_id] = {"request": request_queue, "response": response_queue}

    return agent_queues[agent_id]["request"], agent_queues[agent_id]["response"]


@app.post("/execute", response_model=ToolExecutionResponse)
async def execute_tool(
    request: ToolExecutionRequest, credentials: HTTPAuthorizationCredentials = security_dependency
) -> ToolExecutionResponse:
    verify_token(credentials)

    request_queue, response_queue = ensure_agent_process(request.agent_id)

    request_queue.put({"tool_name": request.tool_name, "kwargs": request.kwargs})

    try:
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(None, response_queue.get)

        if "error" in response:
            return ToolExecutionResponse(error=response["error"])
        return ToolExecutionResponse(result=response.get("result"))

    except (RuntimeError, ValueError, OSError) as e:
        return ToolExecutionResponse(error=f"Worker error: {e}")


@app.post("/register_agent")
async def register_agent(
    agent_id: str, credentials: HTTPAuthorizationCredentials = security_dependency
) -> dict[str, str]:
    verify_token(credentials)

    ensure_agent_process(agent_id)
    return {"status": "registered", "agent_id": agent_id}


@app.get("/health")
async def health_check() -> dict[str, Any]:
    return {
        "status": "healthy",
        "sandbox_mode": str(SANDBOX_MODE),
        "environment": "sandbox" if SANDBOX_MODE else "main",
        "auth_configured": "true" if EXPECTED_TOKEN else "false",
        "active_agents": len(agent_processes),
        "agents": list(agent_processes.keys()),
    }


def cleanup_all_agents() -> None:
    for agent_id in list(agent_processes.keys()):
        try:
            agent_queues[agent_id]["request"].put(None)
            process = agent_processes[agent_id]["process"]

            process.join(timeout=1)

            if process.is_alive():
                process.terminate()
                process.join(timeout=1)

            if process.is_alive():
                process.kill()

        except (BrokenPipeError, EOFError, OSError):
            pass
        except (RuntimeError, ValueError) as e:
            logging.getLogger(__name__).debug(f"Error during agent cleanup: {e}")


def signal_handler(_signum: int, _frame: Any) -> None:
    signal.signal(signal.SIGPIPE, signal.SIG_IGN) if hasattr(signal, "SIGPIPE") else None
    cleanup_all_agents()
    sys.exit(0)


if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    finally:
        cleanup_all_agents()
