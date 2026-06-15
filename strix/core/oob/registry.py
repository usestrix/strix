"""Durable per-engagement token registry for OOB callbacks.

Mirrors the SQLiteSession durability pattern in ``strix/core/sessions.py``:
one SQLite file per registry, schema initialized on open, explicit close.
"""

from __future__ import annotations

import json
import logging
import secrets
import sqlite3
from collections.abc import Generator  # noqa: TC003
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003
from typing import Any, cast

from strix.core.oob.models import MintRecord, OobHit


logger = logging.getLogger(__name__)


class TokenRegistry:
    """SQLite-backed registry of minted tokens and captured OOB hits.

    The registry is scoped to one engagement via the database path; there is
    no cross-engagement read path in the query API.
    """

    _MINT_TABLE = """
        CREATE TABLE IF NOT EXISTS mints (
            token TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL,
            candidate_id TEXT NOT NULL,
            request_ref TEXT NOT NULL,
            injectable_host TEXT NOT NULL,
            created_at TEXT NOT NULL,
            window_seconds INTEGER NOT NULL
        )
    """

    _HIT_TABLE = """
        CREATE TABLE IF NOT EXISTS hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL,
            protocol TEXT NOT NULL,
            full_fqdn TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            raw_request BLOB,
            metadata TEXT
        )
    """

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._cursor() as cur:
            cur.execute(self._MINT_TABLE)
            cur.execute(self._HIT_TABLE)
            self._conn.commit()

    @contextmanager
    def _cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        cur = self._conn.cursor()
        try:
            yield cur
        finally:
            cur.close()

    def close(self) -> None:
        self._conn.close()

    def mint(
        self,
        engagement_id: str,
        candidate_id: str,
        request_ref: str,
        *,
        base_host: str,
        provider_ready: bool,
        window_seconds: int = 60,
    ) -> MintRecord:
        """Mint a unique token bound to one candidate.

        Raises:
            RuntimeError: If ``provider_ready`` is false (live-oracle gate).
        """
        if not provider_ready:
            raise RuntimeError("OOB provider is not ready; mint rejected")

        token = secrets.token_urlsafe(24)
        injectable_host = f"{token}.{base_host}"
        record = MintRecord(
            token=token,
            engagement_id=engagement_id,
            candidate_id=candidate_id,
            request_ref=request_ref,
            injectable_host=injectable_host,
            created_at=datetime.now(UTC),
            window_seconds=window_seconds,
        )
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO mints VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    record.token,
                    record.engagement_id,
                    record.candidate_id,
                    record.request_ref,
                    record.injectable_host,
                    record.created_at.isoformat(),
                    record.window_seconds,
                ),
            )
            self._conn.commit()
        logger.debug("Minted token %s for candidate %s", token, candidate_id)
        return record

    def lookup(self, token: str) -> MintRecord | None:
        """Return the mint record for a token, or ``None`` if unminted."""
        with self._cursor() as cur:
            row = cur.execute("SELECT * FROM mints WHERE token = ?", (token,)).fetchone()
        if row is None:
            return None
        return self._row_to_mint(row)

    def lookup_by_candidate(self, engagement_id: str, candidate_id: str) -> MintRecord | None:
        """Return the most recent mint for a candidate in an engagement."""
        with self._cursor() as cur:
            row = cur.execute(
                "SELECT * FROM mints WHERE engagement_id = ? AND candidate_id = ?"
                " ORDER BY created_at DESC LIMIT 1",
                (engagement_id, candidate_id),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_mint(row)

    def list_mints(self, engagement_id: str) -> list[MintRecord]:
        """Return all mints for a single engagement."""
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT * FROM mints WHERE engagement_id = ? ORDER BY created_at",
                (engagement_id,),
            ).fetchall()
        return [self._row_to_mint(row) for row in rows]

    def list_hits(self, engagement_id: str) -> list[OobHit]:
        """Return all hits whose tokens belong to an engagement."""
        with self._cursor() as cur:
            rows = cur.execute(
                """
                SELECT h.* FROM hits h
                JOIN mints m ON m.token = h.token
                WHERE m.engagement_id = ?
                ORDER BY h.timestamp
                """,
                (engagement_id,),
            ).fetchall()
        return [self._row_to_hit(row) for row in rows]

    def record_hit(self, hit: OobHit) -> int:
        """Persist an inbound OOB hit and return the row id."""
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO hits"
                " (token, protocol, full_fqdn, source_ip, timestamp, raw_request, metadata)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    hit.token,
                    hit.protocol,
                    hit.full_fqdn,
                    hit.source_ip,
                    hit.timestamp.isoformat(),
                    hit.raw_request,
                    self._dump_metadata(hit.metadata),
                ),
            )
            self._conn.commit()
            row_id = cur.lastrowid
        logger.debug("Recorded hit for token %s", hit.token)
        return row_id or 0

    def _row_to_mint(self, row: sqlite3.Row) -> MintRecord:
        return MintRecord(
            token=row["token"],
            engagement_id=row["engagement_id"],
            candidate_id=row["candidate_id"],
            request_ref=row["request_ref"],
            injectable_host=row["injectable_host"],
            created_at=datetime.fromisoformat(row["created_at"]),
            window_seconds=row["window_seconds"],
        )

    def _row_to_hit(self, row: sqlite3.Row) -> OobHit:
        return OobHit(
            protocol=row["protocol"],
            token=row["token"],
            full_fqdn=row["full_fqdn"],
            source_ip=row["source_ip"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            raw_request=row["raw_request"],
            metadata=self._load_metadata(row["metadata"]),
        )

    @staticmethod
    def _dump_metadata(metadata: dict[str, Any]) -> str:
        return json.dumps(metadata, default=str)

    @staticmethod
    def _load_metadata(raw: Any) -> dict[str, Any]:
        if not raw:
            return {}
        try:
            return cast("dict[str, Any]", json.loads(raw))
        except json.JSONDecodeError:
            return {}
