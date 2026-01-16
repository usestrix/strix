from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import queue as stdlib_queue
import signal
import sys
import threading
from multiprocessing import Process, Queue
from typing import Any
from uuid import uuid4

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
parser.add_argument(
    "--timeout",
    type=int,
    default=120,
    help="Hard timeout in seconds for each request execution (default: 120)",
)

args = parser.parse_args()
EXPECTED_TOKEN = args.token
REQUEST_TIMEOUT = args.timeout

app = FastAPI()
security = HTTPBearer()

security_dependency = Depends(security)

agent_processes: dict[str, dict[str, Any]] = {}
agent_queues: dict[str, dict[str, Queue[Any]]] = {}
pending_responses: dict[str, dict[str, asyncio.Future[Any]]] = {}
agent_listeners: dict[str, dict[str, Any]] = {}


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

    from concurrent.futures import ThreadPoolExecutor

    from strix.tools.argument_parser import ArgumentConversionError, convert_arguments
    from strix.tools.registry import get_tool_by_name

    def _execute_request(request: dict[str, Any]) -> None:
        request_id = request.get("request_id", "")
        tool_name = request["tool_name"]
        kwargs = request["kwargs"]

        try:
            tool_func = get_tool_by_name(tool_name)
            if not tool_func:
                response_queue.put(
                    {"request_id": request_id, "error": f"Tool '{tool_name}' not found"}
                )
                return

            converted_kwargs = convert_arguments(tool_func, kwargs)
            result = tool_func(**converted_kwargs)

            response_queue.put({"request_id": request_id, "result": result})

        except (ArgumentConversionError, ValidationError) as e:
            response_queue.put({"request_id": request_id, "error": f"Invalid arguments: {e}"})
        except (RuntimeError, ValueError, ImportError) as e:
            response_queue.put({"request_id": request_id, "error": f"Tool execution error: {e}"})
        except Exception as e:  # noqa: BLE001
            response_queue.put({"request_id": request_id, "error": f"Unexpected error: {e}"})

    with ThreadPoolExecutor() as executor:
        while True:
            try:
                request = request_queue.get()

                if request is None:
                    break

                executor.submit(_execute_request, request)

            except (RuntimeError, ValueError, ImportError) as e:
                response_queue.put({"error": f"Worker error: {e}"})


def _ensure_response_listener(agent_id: str, response_queue: Queue[Any]) -> None:
    if agent_id in agent_listeners:
        return

    stop_event = threading.Event()
    loop = asyncio.get_event_loop()

    def _listener() -> None:
        while not stop_event.is_set():
            try:
                item = response_queue.get(timeout=0.5)
            except stdlib_queue.Empty:
                continue
            except (BrokenPipeError, EOFError):
                break

            request_id = item.get("request_id")
            if not request_id or agent_id not in pending_responses:
                continue

            future = pending_responses[agent_id].pop(request_id, None)
            if future and not future.done():
                with contextlib.suppress(RuntimeError):
                    loop.call_soon_threadsafe(future.set_result, item)

    listener_thread = threading.Thread(target=_listener, daemon=True)
    listener_thread.start()

    agent_listeners[agent_id] = {"thread": listener_thread, "stop_event": stop_event}


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
        pending_responses[agent_id] = {}

        _ensure_response_listener(agent_id, response_queue)

    return agent_queues[agent_id]["request"], agent_queues[agent_id]["response"]


@app.post("/execute", response_model=ToolExecutionResponse)
async def execute_tool(
    request: ToolExecutionRequest, credentials: HTTPAuthorizationCredentials = security_dependency
) -> ToolExecutionResponse:
    verify_token(credentials)

    request_queue, _response_queue = ensure_agent_process(request.agent_id)

    loop = asyncio.get_event_loop()
    req_id = uuid4().hex
    future: asyncio.Future[Any] = loop.create_future()
    pending_responses[request.agent_id][req_id] = future

    request_queue.put(
        {
            "request_id": req_id,
            "tool_name": request.tool_name,
            "kwargs": request.kwargs,
        }
    )

    try:
        response = await asyncio.wait_for(future, timeout=REQUEST_TIMEOUT)

        if "error" in response:
            return ToolExecutionResponse(error=response["error"])
        return ToolExecutionResponse(result=response.get("result"))

    except TimeoutError:
        pending_responses[request.agent_id].pop(req_id, None)
        return ToolExecutionResponse(error=f"Request timed out after {REQUEST_TIMEOUT} seconds")
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
            if agent_id in agent_listeners:
                agent_listeners[agent_id]["stop_event"].set()

            agent_queues[agent_id]["request"].put(None)
            process = agent_processes[agent_id]["process"]

            process.join(timeout=1)

            if process.is_alive():
                process.terminate()
                process.join(timeout=1)

            if process.is_alive():
                process.kill()

            if agent_id in agent_listeners:
                listener_thread = agent_listeners[agent_id]["thread"]
                listener_thread.join(timeout=0.5)

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
