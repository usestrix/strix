"""Persist the terminal's settled approval messages for run replay."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from strix.core.paths import runtime_state_dir


if TYPE_CHECKING:
    from pathlib import Path


def record_approval_history(run_dir: Path, agent_id: str, content: str) -> None:
    path = runtime_state_dir(run_dir) / "action_approvals.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"agent_id": agent_id, "content": content, "timestamp": datetime.now(UTC).isoformat()}
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")


def read_approval_history(run_dir: Path) -> list[dict[str, str]]:
    path = runtime_state_dir(run_dir) / "action_approvals.jsonl"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    records: list[dict[str, str]] = []
    for line in lines:
        try:
            value: object = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict):
            continue
        record = cast("dict[str, object]", value)
        agent_id, content, timestamp = (
            record.get(key) for key in ("agent_id", "content", "timestamp")
        )
        if isinstance(agent_id, str) and isinstance(content, str) and isinstance(timestamp, str):
            records.append({"agent_id": agent_id, "content": content, "timestamp": timestamp})
    return records
