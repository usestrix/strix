"""Persist the terminal's settled approval messages for run replay."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from strix.utils.secret_files import SECRET_FILE_MODE


# A run directory can sit inside the workspace the agent writes to, so the record of what a
# person decided is kept with the user's own Strix files, where the sandbox has no mount.
HISTORY_DIR = Path.home() / ".strix" / "approval-history"


def _history_path(run_dir: Path) -> Path:
    name = hashlib.sha256(str(run_dir.resolve()).encode()).hexdigest()[:32]
    return HISTORY_DIR / f"{name}.jsonl"


def record_approval_history(
    run_dir: Path, agent_id: str, content: str, summary: str | None = None
) -> None:
    path = _history_path(run_dir)
    # The record holds whole commands and request bodies: readable by its owner only.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    record = {"agent_id": agent_id, "content": content, "timestamp": datetime.now(UTC).isoformat()}
    if summary is not None:
        record["summary"] = summary
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, SECRET_FILE_MODE)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")


def read_approval_history(run_dir: Path) -> list[dict[str, str]]:
    path = _history_path(run_dir)
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
            entry = {"agent_id": agent_id, "content": content, "timestamp": timestamp}
            if isinstance(record.get("summary"), str):
                entry["summary"] = str(record["summary"])
            records.append(entry)
    return records
