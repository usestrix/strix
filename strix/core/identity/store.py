"""Durable SQLite-backed per-target identity store.

Mirrors the ``SQLiteSession`` pattern from ``strix/core/sessions.py``: a single
SQLite file per run, opened eagerly, with per-target scoping enforced by the
public API.
"""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING, Self

from strix.core.identity.models import Freshness, Identity
from strix.core.paths import runtime_state_dir


if TYPE_CHECKING:
    from pathlib import Path

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS identities (
    target_key TEXT NOT NULL,
    role TEXT NOT NULL,
    cookies TEXT NOT NULL DEFAULT '{}',
    tokens TEXT NOT NULL DEFAULT '{}',
    headers TEXT NOT NULL DEFAULT '{}',
    provenance TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    expires_hint TEXT,
    status TEXT NOT NULL,
    is_reserved_expired INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (target_key, role)
);

CREATE INDEX IF NOT EXISTS idx_identities_target ON identities(target_key);
"""


class IdentityStore:
    """Per-run identity store partitioned by ``target_key``."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.commit()
        self._closed = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("IdentityStore is closed")

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        if not self._closed:
            self._conn.close()
            self._closed = True

    def _ensure_expired(self, target_key: str) -> None:
        """Seed the reserved ``expired`` pseudo-identity if absent."""
        self._ensure_open()
        cursor = self._conn.execute(
            "SELECT 1 FROM identities WHERE target_key = ? AND role = ?",
            (target_key, "expired"),
        )
        if cursor.fetchone() is None:
            expired = Identity.reserved_expired(target_key)
            self._insert_identity(expired, or_replace=True)

    def _insert_identity(self, identity: Identity, *, or_replace: bool = False) -> None:
        self._ensure_open()
        freshness = identity.freshness
        prefix = "INSERT OR REPLACE" if or_replace else "INSERT"
        sql = (
            f"{prefix} INTO identities "
            "(target_key, role, cookies, tokens, headers, provenance, "
            "captured_at, expires_hint, status, is_reserved_expired) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        self._conn.execute(
            sql,
            (
                identity.target_key,
                identity.role,
                json.dumps(identity.cookies, sort_keys=True),
                json.dumps(identity.tokens, sort_keys=True),
                json.dumps(identity.headers, sort_keys=True),
                identity.provenance,
                freshness.captured_at,
                freshness.expires_hint,
                freshness.status,
                1 if identity.is_reserved_expired else 0,
            ),
        )
        self._conn.commit()

    def _row_to_identity(self, row: sqlite3.Row) -> Identity:
        return Identity(
            target_key=row["target_key"],
            role=row["role"],
            cookies=json.loads(row["cookies"]),
            tokens=json.loads(row["tokens"]),
            headers=json.loads(row["headers"]),
            provenance=row["provenance"],
            freshness=Freshness(
                captured_at=row["captured_at"],
                expires_hint=row["expires_hint"],
                status=row["status"],
            ),
            is_reserved_expired=bool(row["is_reserved_expired"]),
        )

    def upsert_identity(self, identity: Identity) -> None:
        """Store or replace an identity. ``(target_key, role)`` is unique."""
        self._ensure_open()
        if identity.is_reserved_expired and identity.role != "expired":
            raise ValueError("Only the 'expired' role may be reserved")
        self._insert_identity(identity, or_replace=True)
        if not identity.is_reserved_expired:
            self._ensure_expired(identity.target_key)

    def get_identity(self, target_key: str, role: str) -> Identity | None:
        """Fetch a single identity by target and role."""
        self._ensure_open()
        self._ensure_expired(target_key)
        cursor = self._conn.execute(
            "SELECT * FROM identities WHERE target_key = ? AND role = ?",
            (target_key, role),
        )
        row = cursor.fetchone()
        return self._row_to_identity(row) if row is not None else None

    def list_targets(self) -> list[str]:
        """Return all target keys with stored identities."""
        self._ensure_open()
        cursor = self._conn.execute(
            "SELECT DISTINCT target_key FROM identities ORDER BY target_key"
        )
        return [row["target_key"] for row in cursor.fetchall()]

    def list_identities(self, target_key: str) -> list[Identity]:
        """Return all identities for a single target, including ``expired``."""
        self._ensure_open()
        self._ensure_expired(target_key)
        cursor = self._conn.execute(
            "SELECT * FROM identities WHERE target_key = ? ORDER BY role",
            (target_key,),
        )
        return [self._row_to_identity(row) for row in cursor.fetchall()]

    def delete_identity(self, target_key: str, role: str) -> bool:
        """Delete an identity. The reserved ``expired`` role cannot be deleted."""
        self._ensure_open()
        if role == "expired":
            return False
        cursor = self._conn.execute(
            "DELETE FROM identities WHERE target_key = ? AND role = ?",
            (target_key, role),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def delete_target(self, target_key: str) -> None:
        """Delete every identity for a target."""
        self._ensure_open()
        self._conn.execute(
            "DELETE FROM identities WHERE target_key = ?",
            (target_key,),
        )
        self._conn.commit()


def identity_store_path(run_dir: Path | None = None) -> Path:
    """Resolve the identity-store SQLite path for a run.

    If ``run_dir`` is omitted, fall back to the active global ``ReportState``.
    For tests or offline contexts, use an explicit ``run_dir``.
    """
    if run_dir is not None:
        return runtime_state_dir(run_dir) / "identities.db"
    # Lazy import: ``strix.report.state`` transitively imports the openai-agents
    # SDK. Tests and offline tooling that pass an explicit ``run_dir`` should
    # not need it installed.
    from strix.report.state import get_global_report_state  # noqa: PLC0415

    report_state = get_global_report_state()
    if report_state is None:
        raise RuntimeError(
            "No active report state and no run_dir provided; cannot resolve identity store path"
        )
    return runtime_state_dir(report_state.get_run_dir()) / "identities.db"


def open_identity_store(run_dir: Path | None = None) -> IdentityStore:
    """Open the identity store for the current or specified run."""
    return IdentityStore(identity_store_path(run_dir))
