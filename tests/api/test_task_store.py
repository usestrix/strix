from pathlib import Path

from strix.api.models import ScanTaskRequest, TaskStatus
from strix.api.task_store import TaskStore


def test_refresh_marks_exited_worker_failed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = TaskStore(base_dir=tmp_path / "strix_runs")
    record = store.create_record(
        "task_1234",
        ScanTaskRequest(targets=["https://example.com"]),
    )
    record.pid = 4321
    record.status = TaskStatus.QUEUED
    store.save(record)

    monkeypatch.setattr("strix.api.task_store._poll_process_exit_code", lambda _pid: 1)

    refreshed = store.refresh(record)

    assert refreshed.status == TaskStatus.FAILED
    assert refreshed.exit_code == 1
    assert refreshed.finished_at is not None
    assert refreshed.error == "Worker exited with code 1"
