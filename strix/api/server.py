from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import AsyncIterator

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from strix.api.models import ScanTaskRecord, ScanTaskRequest, ScanTaskResult
from strix.api.task_manager import TaskManager
from strix.config import Config


security = HTTPBearer(auto_error=False)
DEMO_PAGE_PATH = Path(__file__).resolve().parent / "demo" / "index.html"


def create_app(task_manager: TaskManager | None = None) -> FastAPI:
    manager = task_manager or TaskManager()
    auth_token = Config.get_str("api_auth_token")
    enable_docs = Config.get_bool("api_enable_docs")
    poll_interval_ms = Config.get_int("api_stream_poll_interval_ms") or 500

    app = FastAPI(
        title="Strix API",
        version="1.0.0",
        docs_url="/docs" if enable_docs is not False else None,
        redoc_url="/redoc" if enable_docs is not False else None,
        openapi_url="/openapi.json" if enable_docs is not False else None,
    )
    app.state.task_manager = manager
    app.state.auth_token = auth_token
    app.state.poll_interval_ms = poll_interval_ms

    def _get_task_or_404(task_id: str) -> ScanTaskRecord:
        try:
            task = app.state.task_manager.get_task(task_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found") from exc
        if task is None:
            raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found")
        return task

    def _get_result_or_404(task_id: str) -> ScanTaskResult:
        try:
            result = app.state.task_manager.get_result(task_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found") from exc
        if result is None:
            raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found")
        return result

    async def require_auth(
        credentials: HTTPAuthorizationCredentials | None = Depends(security),
    ) -> None:
        expected = app.state.auth_token
        if not expected:
            return
        if (
            credentials is None
            or credentials.scheme.lower() != "bearer"
            or credentials.credentials != expected
        ):
            raise HTTPException(status_code=401, detail="Invalid or missing API token")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/demo", include_in_schema=False)
    async def demo() -> HTMLResponse:
        return HTMLResponse(DEMO_PAGE_PATH.read_text(encoding="utf-8"))

    @app.post("/api/v1/tasks", status_code=201, dependencies=[Depends(require_auth)])
    async def create_task(request: ScanTaskRequest) -> dict[str, object]:
        try:
            record = app.state.task_manager.create_task(request)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"task": record.model_dump(mode="python")}

    @app.get("/api/v1/tasks", dependencies=[Depends(require_auth)])
    async def list_tasks() -> dict[str, object]:
        tasks = [record.model_dump(mode="python") for record in app.state.task_manager.list_tasks()]
        return {"tasks": tasks}

    @app.get("/api/v1/tasks/{task_id}", dependencies=[Depends(require_auth)])
    async def get_task(task_id: str) -> dict[str, object]:
        result = _get_result_or_404(task_id)
        return result.model_dump(mode="python")

    @app.get("/api/v1/tasks/{task_id}/result", dependencies=[Depends(require_auth)])
    async def get_task_result(task_id: str) -> dict[str, object]:
        result = _get_result_or_404(task_id)
        return {
            "task": result.task.model_dump(mode="python"),
            "scan_state": result.scan_state,
            "artifacts": result.artifacts,
        }

    @app.get("/api/v1/tasks/{task_id}/results", dependencies=[Depends(require_auth)])
    async def get_task_results_alias(task_id: str) -> dict[str, object]:
        return await get_task_result(task_id)

    @app.post("/api/v1/tasks/{task_id}/cancel", dependencies=[Depends(require_auth)])
    async def cancel_task(task_id: str) -> dict[str, object]:
        try:
            record = app.state.task_manager.cancel_task(task_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found") from exc
        if record is None:
            raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found")
        return {"task": record.model_dump(mode="python")}

    @app.get("/api/v1/tasks/{task_id}/events", dependencies=[Depends(require_auth)])
    async def get_task_events(
        task_id: str,
        limit: int = Query(default=200, ge=1, le=5000),
    ) -> dict[str, object]:
        try:
            events = app.state.task_manager.get_events(task_id, limit=limit)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found") from exc
        if events is None:
            raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found")
        return {"task_id": task_id, "events": events}

    @app.get("/api/v1/tasks/{task_id}/stream", dependencies=[Depends(require_auth)])
    async def stream_task_events(
        task_id: str,
        follow: bool = Query(default=True),
        from_offset: int = Query(default=0, ge=0),
    ) -> StreamingResponse:
        _get_task_or_404(task_id)

        return StreamingResponse(
            _stream_events(
                app.state.task_manager,
                task_id,
                follow=follow,
                from_offset=from_offset,
                poll_interval_ms=app.state.poll_interval_ms,
            ),
            media_type="text/event-stream",
        )

    @app.get("/api/v1/tasks/{task_id}/artifacts", dependencies=[Depends(require_auth)])
    async def get_task_artifacts(task_id: str) -> dict[str, object]:
        try:
            artifacts = app.state.task_manager.get_artifacts(task_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found") from exc
        if artifacts is None:
            raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found")
        return {"task_id": task_id, "artifacts": artifacts}

    @app.get("/api/v1/tasks/{task_id}/report", dependencies=[Depends(require_auth)])
    async def get_task_report(task_id: str) -> PlainTextResponse:
        try:
            report = app.state.task_manager.get_report_text(task_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Task '{task_id}' report not found") from exc
        if report is None:
            raise HTTPException(status_code=404, detail=f"Task '{task_id}' report not found")
        return PlainTextResponse(report)

    return app


async def _stream_events(
    task_manager: TaskManager,
    task_id: str,
    *,
    follow: bool,
    from_offset: int,
    poll_interval_ms: int,
) -> AsyncIterator[str]:
    events_path = task_manager.store.events_file(task_id)
    offset = from_offset
    sent_terminal = False
    yield (
        "event: stream.connected\n"
        f"data: {json.dumps({'task_id': task_id, 'offset': offset}, ensure_ascii=False)}\n\n"
    )

    while True:
        if events_path.exists():
            with events_path.open("r", encoding="utf-8") as file_obj:
                file_obj.seek(offset)
                while True:
                    line = file_obj.readline()
                    if not line:
                        break
                    offset = file_obj.tell()
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        payload = json.loads(stripped)
                    except json.JSONDecodeError:
                        payload = {"raw": stripped}
                    yield (
                        f"event: {payload.get('event_type', 'message')}\n"
                        f"data: {json.dumps({'offset': offset, 'payload': payload}, ensure_ascii=False)}\n\n"
                    )

        try:
            task = task_manager.get_task(task_id)
        except KeyError:
            break
        if task is None:
            break
        try:
            status = task.status.value
        except AttributeError:
            status = str(task.status)
        if status in {"completed", "failed", "cancelled"}:
            if not sent_terminal:
                payload = task.model_dump(mode="python") if hasattr(task, "model_dump") else task
                yield "event: task.finished\n" f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
                sent_terminal = True
            if not follow:
                break
            await asyncio.sleep(poll_interval_ms / 1000)
            if events_path.exists() and offset < events_path.stat().st_size:
                continue
            break

        if not follow:
            break

        yield ": keep-alive\n\n"
        await asyncio.sleep(poll_interval_ms / 1000)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Start the Strix API server")
    parser.add_argument("--config", type=str, help="Path to a Strix config JSON file")
    parser.add_argument("--host", type=str, help="Override server host")
    parser.add_argument("--port", type=int, help="Override server port")
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.config:
        config_path = Path(args.config).expanduser().resolve()
        Config.validate_file(config_path)
        Config.set_config_file(config_path)
    else:
        Config.reload()

    host = args.host or Config.get_str("api_host") or "127.0.0.1"
    port = args.port or Config.get_int("api_port") or 8787

    uvicorn.run(create_app(), host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
