from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from strix.api.common import build_targets_info, generate_task_id
from strix.api.models import ScanTaskRecord, ScanTaskRequest, ScanTaskResult, TaskStatus
from strix.api.task_store import TERMINAL_TASK_STATUSES, TaskStore
from strix.config import Config


class TaskManager:
    def __init__(self, store: TaskStore | None = None):
        self.store = store or TaskStore()

    def list_tasks(self) -> list[ScanTaskRecord]:
        return [self.store.refresh(record) for record in self.store.list()]

    def get_task(self, task_id: str) -> ScanTaskRecord:
        record = self.store.load(task_id)
        if record is None:
            raise KeyError(task_id)
        return self.store.refresh(record)

    def get_result(self, task_id: str) -> ScanTaskResult:
        record = self.get_task(task_id)

        result = self.store.result(task_id)
        if result is None:
            return ScanTaskResult(
                task=record,
                scan_state=self.store.load_scan_state(task_id),
                artifacts=self.get_artifacts(task_id),
            )

        result.task = record
        return result

    def create_task(self, request: ScanTaskRequest) -> ScanTaskRecord:
        build_targets_info(request.targets)

        max_concurrent_tasks = Config.get_int("api_max_concurrent_tasks") or 1
        active_tasks = [
            task
            for task in self.list_tasks()
            if task.status in {TaskStatus.QUEUED, TaskStatus.RUNNING, TaskStatus.CANCELLING}
        ]
        if len(active_tasks) >= max_concurrent_tasks:
            raise ValueError(
                "Maximum concurrent task limit reached. "
                f"Current limit: {max_concurrent_tasks}"
            )

        task_id = request.task_id or request.run_name or generate_task_id(request.targets)
        if self.store.load(task_id) is not None:
            raise ValueError(f"Task '{task_id}' already exists")

        instruction = request.instruction
        if request.instruction_file:
            instruction_path = Path(request.instruction_file).expanduser().resolve()
            try:
                instruction = instruction_path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ValueError(
                    f"Failed to read instruction file '{instruction_path}': {exc}"
                ) from exc
            if not instruction:
                raise ValueError(f"Instruction file '{instruction_path}' is empty")

        config_path = (
            Path(request.config_path).expanduser().resolve()
            if request.config_path
            else Config.active_config_path().resolve()
        )
        Config.validate_file(config_path)

        request_data = request.model_copy(
            update={
                "task_id": task_id,
                "run_name": request.run_name or task_id,
                "config_path": str(config_path),
                "instruction": instruction,
            }
        )
        record = self.store.create_record(task_id, request_data)
        self.store.save(record)

        worker_log_path = Path(record.worker_log_path)
        worker_log_path.parent.mkdir(parents=True, exist_ok=True)
        with worker_log_path.open("ab") as log_file:
            process = subprocess.Popen(  # noqa: S603
                [
                    sys.executable,
                    "-m",
                    "strix.api.worker",
                    "--task-id",
                    task_id,
                    "--config",
                    str(config_path),
                ],
                cwd=Path.cwd(),
                stdout=log_file,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

        record.pid = process.pid
        record.status = TaskStatus.QUEUED
        return self.store.save(record)

    def cancel_task(self, task_id: str) -> ScanTaskRecord:
        record = self.get_task(task_id)

        if record.status in TERMINAL_TASK_STATUSES:
            return record

        if record.pid:
            try:
                if os.name == "posix":
                    os.killpg(record.pid, signal.SIGTERM)
                else:
                    os.kill(record.pid, signal.SIGTERM)
            except OSError:
                pass

        record.status = TaskStatus.CANCELLING
        record.error = record.error or "Task cancellation requested"
        return self.store.save(record)

    def get_scan_state(self, task_id: str) -> dict[str, Any]:
        self.get_task(task_id)
        return self.store.load_scan_state(task_id) or {}

    def get_events(self, task_id: str, limit: int = 200) -> list[dict[str, Any]]:
        record = self.get_task(task_id)

        events_path = Path(record.events_path)
        if not events_path.exists():
            return []

        events: list[dict[str, Any]] = []
        with events_path.open("r", encoding="utf-8") as file_obj:
            for line in file_obj:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    events.append(json.loads(stripped))
                except ValueError:
                    continue

        return events[-limit:]

    def get_report_text(self, task_id: str) -> str | None:
        record = self.get_task(task_id)
        report_path = Path(record.run_dir) / "penetration_test_report.md"
        if not report_path.exists():
            return None
        return report_path.read_text(encoding="utf-8")

    def get_artifacts(self, task_id: str) -> list[str]:
        record = self.get_task(task_id)
        return sorted(str(path) for path in Path(record.run_dir).glob("**/*") if path.is_file())


ScanTaskManager = TaskManager
