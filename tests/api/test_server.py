import json

from fastapi.testclient import TestClient

from strix.api.models import ScanTaskRecord, ScanTaskRequest, ScanTaskResult, TaskStatus
from strix.api.server import create_app


class FakeStore:
    def __init__(self, events_path: str):
        self._events_path = events_path

    def events_file(self, _task_id: str) -> str:
        from pathlib import Path

        return Path(self._events_path)


class FakeTaskManager:
    def __init__(
        self,
        record: ScanTaskRecord,
        result: ScanTaskResult,
        events: list[dict[str, object]],
    ) -> None:
        self.record = record
        self.result = result
        self.events = events
        self.store = FakeStore(record.events_path)

    def create_task(self, payload: ScanTaskRequest) -> ScanTaskRecord:
        self.record.request = payload
        return self.record

    def list_tasks(self) -> list[ScanTaskRecord]:
        return [self.record]

    def get_task(self, task_id: str) -> ScanTaskRecord | None:
        return self.record if task_id == self.record.task_id else None

    def get_result(self, task_id: str) -> ScanTaskResult | None:
        return self.result if task_id == self.record.task_id else None

    def cancel_task(self, task_id: str) -> ScanTaskRecord | None:
        if task_id != self.record.task_id:
            return None
        self.record.status = TaskStatus.CANCELLED
        return self.record

    def get_events(self, task_id: str, limit: int = 200) -> list[dict[str, object]] | None:
        return self.events[-limit:] if task_id == self.record.task_id else None

    def get_artifacts(self, task_id: str) -> list[str] | None:
        return [self.record.events_path] if task_id == self.record.task_id else None

    def get_report_text(self, task_id: str) -> str | None:
        return "# report" if task_id == self.record.task_id else None


def test_task_endpoints_and_sse_stream(tmp_path, write_config) -> None:
    write_config({})

    run_dir = tmp_path / "strix_runs" / "task_1234"
    run_dir.mkdir(parents=True)
    events_path = run_dir / "events.jsonl"
    events = [
        {
            "event_type": "chat.message",
            "payload": {"content": "hello"},
            "run_id": "task_1234",
        }
    ]
    events_path.write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")

    request = ScanTaskRequest(targets=["https://example.com"])
    record = ScanTaskRecord(
        task_id="task_1234",
        run_name="task_1234",
        status=TaskStatus.COMPLETED,
        created_at="2026-03-25T00:00:00+00:00",
        finished_at="2026-03-25T00:01:00+00:00",
        request=request,
        run_dir=str(run_dir),
        worker_log_path=str(run_dir / "worker.log"),
        scan_state_path=str(run_dir / "scan_state.json"),
        events_path=str(events_path),
    )
    result = ScanTaskResult(
        task=record,
        scan_state={"final_scan_result": "done"},
        artifacts=[str(events_path)],
    )
    fake_manager = FakeTaskManager(record=record, result=result, events=events)

    client = TestClient(create_app(task_manager=fake_manager))

    demo_response = client.get("/demo")
    assert demo_response.status_code == 200
    assert "Strix API Demo" in demo_response.text

    create_response = client.post(
        "/api/v1/tasks",
        json={"targets": ["https://example.com"], "scan_mode": "deep"},
    )
    assert create_response.status_code == 201
    assert create_response.json()["task"]["task_id"] == "task_1234"

    list_response = client.get("/api/v1/tasks")
    assert list_response.status_code == 200
    assert len(list_response.json()["tasks"]) == 1

    task_response = client.get("/api/v1/tasks/task_1234")
    assert task_response.status_code == 200
    assert task_response.json()["task"]["task_id"] == "task_1234"

    result_response = client.get("/api/v1/tasks/task_1234/results")
    assert result_response.status_code == 200
    assert result_response.json()["scan_state"]["final_scan_result"] == "done"

    events_response = client.get("/api/v1/tasks/task_1234/events")
    assert events_response.status_code == 200
    assert events_response.json()["events"][0]["event_type"] == "chat.message"

    artifacts_response = client.get("/api/v1/tasks/task_1234/artifacts")
    assert artifacts_response.status_code == 200
    assert artifacts_response.json()["artifacts"][0].endswith("events.jsonl")

    report_response = client.get("/api/v1/tasks/task_1234/report")
    assert report_response.status_code == 200
    assert "# report" in report_response.text

    with client.stream("GET", "/api/v1/tasks/task_1234/stream") as response:
        body = "".join(response.iter_text())

    assert response.status_code == 200
    assert "event: stream.connected" in body
    assert "event: chat.message" in body
    assert "event: task.finished" in body
