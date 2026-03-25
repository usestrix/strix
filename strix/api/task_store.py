import json
import os
import subprocess
from pathlib import Path
from typing import Any

from strix.api.models import ScanTaskRecord, ScanTaskResult, ScanTaskRequest, TaskStatus, utc_now_iso


ACTIVE_TASK_STATUSES = {TaskStatus.QUEUED, TaskStatus.RUNNING, TaskStatus.CANCELLING}
TERMINAL_TASK_STATUSES = {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}


class TaskStore:
    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir or (Path.cwd() / "strix_runs")
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def run_dir(self, task_id: str) -> Path:
        return self.base_dir / task_id

    def task_file(self, task_id: str) -> Path:
        return self.run_dir(task_id) / "task_state.json"

    def events_file(self, task_id: str) -> Path:
        return self.run_dir(task_id) / "events.jsonl"

    def scan_state_file(self, task_id: str) -> Path:
        return self.run_dir(task_id) / "scan_state.json"

    def worker_log_file(self, task_id: str) -> Path:
        return self.run_dir(task_id) / "worker.log"

    def create_record(self, task_id: str, request: ScanTaskRequest) -> ScanTaskRecord:
        run_dir = self.run_dir(task_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        return ScanTaskRecord(
            task_id=task_id,
            request=request,
            run_dir=str(run_dir),
            worker_log_path=str(self.worker_log_file(task_id)),
            scan_state_path=str(self.scan_state_file(task_id)),
            events_path=str(self.events_file(task_id)),
        )

    def save(self, record: ScanTaskRecord) -> ScanTaskRecord:
        record.updated_at = utc_now_iso()
        task_path = self.task_file(record.task_id)
        task_path.parent.mkdir(parents=True, exist_ok=True)
        with task_path.open("w", encoding="utf-8") as file_obj:
            json.dump(record.model_dump(mode="python"), file_obj, indent=2, ensure_ascii=False)
        return record

    def load(self, task_id: str) -> ScanTaskRecord | None:
        task_path = self.task_file(task_id)
        if not task_path.exists():
            return None
        with task_path.open("r", encoding="utf-8") as file_obj:
            data = json.load(file_obj)
        return ScanTaskRecord.model_validate(data)

    def list(self) -> list[ScanTaskRecord]:
        tasks: list[ScanTaskRecord] = []
        for task_file in sorted(self.base_dir.glob("*/task_state.json")):
            try:
                with task_file.open("r", encoding="utf-8") as file_obj:
                    tasks.append(ScanTaskRecord.model_validate(json.load(file_obj)))
            except (OSError, ValueError, json.JSONDecodeError):
                continue

        tasks.sort(key=lambda item: item.created_at, reverse=True)
        return tasks

    def load_scan_state(self, task_id: str) -> dict[str, Any] | None:
        scan_state_path = self.scan_state_file(task_id)
        if not scan_state_path.exists():
            return None
        with scan_state_path.open("r", encoding="utf-8") as file_obj:
            return json.load(file_obj)

    def result(self, task_id: str) -> ScanTaskResult | None:
        record = self.load(task_id)
        if record is None:
            return None

        artifacts = sorted(str(path) for path in self.run_dir(task_id).glob("**/*") if path.is_file())
        return ScanTaskResult(
            task=record,
            scan_state=self.load_scan_state(task_id),
            artifacts=artifacts,
        )

    def refresh(self, record: ScanTaskRecord) -> ScanTaskRecord:
        if record.status in TERMINAL_TASK_STATUSES:
            return record

        scan_state = self.load_scan_state(record.task_id)
        if scan_state and (scan_state.get("run_metadata") or {}).get("status") == "completed":
            record.status = TaskStatus.COMPLETED
            record.finished_at = (scan_state.get("run_metadata") or {}).get("end_time")
            return self.save(record)

        if record.pid:
            exit_code = _poll_process_exit_code(record.pid)
        else:
            exit_code = None

        if exit_code is not None:
            record.finished_at = record.finished_at or utc_now_iso()
            record.exit_code = exit_code
            if record.status == TaskStatus.CANCELLING:
                record.status = TaskStatus.CANCELLED
                record.error = record.error or "Task cancelled"
            else:
                record.status = TaskStatus.FAILED
                if exit_code == 0:
                    record.error = record.error or "Worker exited without producing scan output"
                else:
                    record.error = record.error or f"Worker exited with code {exit_code}"
            return self.save(record)

        return record


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _poll_process_exit_code(pid: int) -> int | None:
    if os.name == "posix":
        try:
            waited_pid, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            waited_pid, status = 0, 0
        except OSError:
            return 1
        else:
            if waited_pid == pid:
                if os.WIFEXITED(status):
                    return os.WEXITSTATUS(status)
                if os.WIFSIGNALED(status):
                    return 128 + os.WTERMSIG(status)
                return 1

        if _is_zombie_process(pid):
            return 1

    if not _process_exists(pid):
        return 1

    return None


def _is_zombie_process(pid: int) -> bool:
    if os.name != "posix":
        return False

    try:
        result = subprocess.run(  # noqa: S603
            ["ps", "-o", "stat=", "-p", str(pid)],
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError:
        return False

    if result.returncode != 0:
        return False

    return "Z" in result.stdout.strip().upper()
