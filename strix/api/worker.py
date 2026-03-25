from __future__ import annotations

import argparse
import asyncio
import signal
import traceback
from pathlib import Path
from typing import Any

from strix.agents.StrixAgent import StrixAgent
from strix.api.common import ScanRequest, prepare_scan
from strix.api.models import TaskStatus, utc_now_iso
from strix.api.task_store import TaskStore
from strix.config import Config
from strix.interface.main import (
    check_docker_installed,
    pull_docker_image,
    validate_environment,
    warm_up_llm,
)
from strix.runtime import cleanup_runtime
from strix.runtime.context import configure_runtime_context
from strix.telemetry import posthog
from strix.telemetry.tracer import Tracer, get_global_tracer, set_global_tracer
from strix.tools.agents_graph.agents_graph_actions import reset_agent_graph_state


_CURRENT_AGENT: StrixAgent | None = None
_CANCEL_REQUESTED = False


def _handle_termination(_signum: int, _frame: Any) -> None:
    global _CANCEL_REQUESTED
    _CANCEL_REQUESTED = True
    if _CURRENT_AGENT is not None:
        _CURRENT_AGENT.cancel_current_execution()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a Strix scan worker")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--config", required=True)
    return parser


async def _run_worker(task_id: str, config_path: Path) -> int:
    global _CANCEL_REQUESTED, _CURRENT_AGENT

    _CANCEL_REQUESTED = False

    store = TaskStore()
    record = store.load(task_id)
    if record is None:
        raise ValueError(f"Task '{task_id}' not found")

    Config.set_config_file(config_path)
    configure_runtime_context(
        sandbox_mode=False,
        caido_api_token=Config.get_str("caido_api_token"),
    )

    check_docker_installed()
    pull_docker_image()
    validate_environment()
    await warm_up_llm()

    prepared = prepare_scan(
        ScanRequest(
            targets=record.request.targets,
            instruction=record.request.instruction or "",
            scan_mode=record.request.scan_mode,
            run_name=task_id,
        )
    )

    record.status = TaskStatus.RUNNING
    record.started_at = record.started_at or utc_now_iso()
    store.save(record)

    posthog.start(
        model=Config.get_str("strix_llm"),
        scan_mode=prepared.request.scan_mode,
        is_whitebox=bool(prepared.local_sources),
        interactive=False,
        has_instructions=bool(prepared.request.instruction),
    )

    exit_code = 1
    exit_reason = "finished"
    try:
        reset_agent_graph_state()
        tracer = Tracer(task_id)
        set_global_tracer(tracer)
        tracer.set_scan_config(prepared.build_scan_config())

        _CURRENT_AGENT = StrixAgent(prepared.build_agent_config(interactive=False))
        result = await _CURRENT_AGENT.execute_scan(prepared.build_scan_config())

        if _CANCEL_REQUESTED:
            record.status = TaskStatus.CANCELLED
            record.error = "Task cancelled"
            exit_reason = "cancelled"
            exit_code = 130
            return exit_code

        if isinstance(result, dict) and not result.get("success", True):
            record.status = TaskStatus.FAILED
            record.error = result.get("error", "Scan failed")
            exit_reason = "failed"
            exit_code = 1
            return exit_code

        record.status = TaskStatus.COMPLETED
        record.error = None
        exit_code = 0
        return exit_code
    except asyncio.CancelledError:
        record.status = TaskStatus.CANCELLED
        record.error = "Task cancelled"
        exit_reason = "cancelled"
        exit_code = 130
        return exit_code
    except SystemExit as exc:
        record.status = TaskStatus.FAILED
        record.error = f"Worker bootstrap exited with code {exc.code}"
        exit_reason = "failed"
        exit_code = int(exc.code) if isinstance(exc.code, int) else 1
        return exit_code
    except Exception as exc:  # noqa: BLE001
        record.status = TaskStatus.FAILED
        record.error = "".join(traceback.format_exception_only(type(exc), exc)).strip()
        exit_reason = "failed"
        exit_code = 1
        return exit_code
    finally:
        _CURRENT_AGENT = None
        if record.status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}:
            record.finished_at = utc_now_iso()
        record.exit_code = exit_code
        store.save(record)

        tracer = get_global_tracer()
        if tracer:
            if record.finished_at:
                tracer.end_time = record.finished_at
                tracer.run_metadata["end_time"] = record.finished_at
            tracer.run_metadata["status"] = record.status.value
            tracer.save_run_data(mark_complete=record.status == TaskStatus.COMPLETED)
            posthog.end(tracer, exit_reason=exit_reason)
            set_global_tracer(None)
        reset_agent_graph_state()
        cleanup_runtime()


def main() -> None:
    args = build_parser().parse_args()
    config_path = Path(args.config).expanduser().resolve()

    signal.signal(signal.SIGTERM, _handle_termination)
    signal.signal(signal.SIGINT, _handle_termination)

    exit_code = asyncio.run(_run_worker(args.task_id, config_path))
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
