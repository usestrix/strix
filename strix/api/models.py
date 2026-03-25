from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class TaskStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[str] = Field(min_length=1)
    instruction: str | None = None
    instruction_file: str | None = None
    scan_mode: Literal["quick", "standard", "deep"] = "deep"
    task_id: str | None = None
    run_name: str | None = None
    config_path: str | None = None

    @model_validator(mode="after")
    def validate_instruction_inputs(self) -> "ScanTaskRequest":
        if self.instruction and self.instruction_file:
            raise ValueError("instruction and instruction_file cannot be used together")
        return self


class ScanTaskRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    task_id: str
    run_name: str | None = None
    status: TaskStatus = TaskStatus.QUEUED
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)
    started_at: str | None = None
    finished_at: str | None = None
    completed_at: str | None = None
    pid: int | None = None
    exit_code: int | None = None
    error: str | None = None
    request: ScanTaskRequest
    run_dir: str
    worker_log_path: str
    scan_state_path: str
    events_path: str

    @model_validator(mode="after")
    def normalize_record(self) -> "ScanTaskRecord":
        if self.finished_at and not self.completed_at:
            self.completed_at = self.finished_at
        if self.completed_at and not self.finished_at:
            self.finished_at = self.completed_at
        if not self.run_name:
            self.run_name = self.request.run_name or self.task_id
        return self


class ScanTaskResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    task: ScanTaskRecord
    scan_state: dict[str, Any] | None = None
    artifacts: list[str] = Field(default_factory=list)


class TaskCollectionResponse(BaseModel):
    tasks: list[ScanTaskRecord]


class TaskEventsResponse(BaseModel):
    task_id: str
    events: list[dict[str, Any]]


class TaskArtifactsResponse(BaseModel):
    task_id: str
    artifacts: list[Any]


CreateTaskRequest = ScanTaskRequest
TaskRecord = ScanTaskRecord
