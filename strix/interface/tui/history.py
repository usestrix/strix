"""Historical SDK session loading for the TUI."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from strix.core.paths import runtime_state_dir


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)


def load_session_history(run_dir: Path, agent_ids: Any) -> list[tuple[str, dict[str, Any], str]]:
    agents_db = runtime_state_dir(run_dir) / "agents.db"
    session_ids = [aid for aid in agent_ids if isinstance(aid, str)]
    if not agents_db.exists() or not session_ids:
        return []
    session_id_set = set(session_ids)
    # Open read-only: the scan process may be actively writing this WAL database
    # from another process (the local viewer tails it live), and a reader must
    # never lock or mutate it. mode=ro (not immutable=1) still reads the latest
    # committed WAL state; WAL permits concurrent readers alongside the writer.
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(
            f"file:{agents_db}?mode=ro",
            uri=True,
            check_same_thread=False,
        )
        rows = conn.execute(
            "select id, session_id, message_data, created_at from agent_messages order by id"
        ).fetchall()
    except sqlite3.Error:
        logger.exception("Failed to hydrate TUI history from %s", agents_db)
        return []
    finally:
        if conn is not None:
            conn.close()

    items: list[tuple[str, dict[str, Any], str]] = []
    for row_id, agent_id, message_data, created_at in rows:
        if agent_id not in session_id_set:
            continue
        try:
            item = json.loads(message_data)
        except (TypeError, json.JSONDecodeError):
            logger.debug("Skipping unreadable SDK session item %s for %s", row_id, agent_id)
            continue
        if isinstance(item, dict):
            items.append((str(agent_id), item, _sqlite_timestamp_to_iso(created_at)))
    return items


def _sqlite_timestamp_to_iso(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return datetime.now(UTC).isoformat()
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat()
