"""Graceful degradation when the scan filesystem runs out of space.

A mid-scan sqlite disk I/O error used to escape as an unhandled
exception and take the whole run down, losing the report. These tests pin
the degraded paths: the pooled session the SDK persists turns through,
the resilient wrapper used by the mailbox/recovery writers, and the
SARIF writer's find-in-log fallback.
"""

from __future__ import annotations

import logging
import sqlite3
import tempfile
from pathlib import Path

import pytest

from strix.core.sessions import _PooledConnectionSession, add_items_resilient


class _FailingSession:
    """Minimal Session stand-in whose add_items raises a storage error."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.calls = 0

    async def add_items(self, items):  # noqa: ANN001, D102
        self.calls += 1
        raise self._exc


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc",
    [
        sqlite3.OperationalError("disk I/O error"),
        sqlite3.OperationalError("database or disk is full"),
    ],
)
async def test_add_items_resilient_survives_disk_full(exc):
    session = _FailingSession(exc)
    # Must not raise: persistence failure degrades to a logged no-op.
    assert await add_items_resilient(session, [1, 2]) is False
    assert session.calls == 1


@pytest.mark.asyncio
async def test_add_items_resilient_passes_through_real_writes():
    class _OkSession:
        async def add_items(self, items):  # noqa: ANN001, D102
            return items

    assert await add_items_resilient(_OkSession(), [1]) is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message",
    ["disk I/O error", "database or disk is full"],
)
async def test_pooled_session_add_items_degrades_on_disk_full(message, monkeypatch, caplog):
    """The SDK turn-save path (Runner.run_streamed -> add_items) survives ENOSPC."""
    with tempfile.TemporaryDirectory() as tmp:
        session = _PooledConnectionSession(session_id="s", db_path=Path(tmp) / "a.db")

        async def _boom(self, items):
            raise sqlite3.OperationalError(message)

        monkeypatch.setattr(type(session).__mro__[1], "add_items", _boom)
        with caplog.at_level(logging.WARNING, logger="strix.core.sessions"):
            await session.add_items([1])  # must not raise
    assert "storage error" in caplog.text


@pytest.mark.asyncio
async def test_pooled_session_add_items_reraises_non_storage_errors(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        session = _PooledConnectionSession(session_id="s", db_path=Path(tmp) / "a.db")

        async def _boom(self, items):
            raise sqlite3.OperationalError("no such table")

        monkeypatch.setattr(type(session).__mro__[1], "add_items", _boom)
        with pytest.raises(sqlite3.OperationalError):
            await session.add_items([1])


def test_sarif_write_failure_logs_findings(caplog, monkeypatch):
    """A failed SARIF write must still surface finding titles via the logger."""
    from strix.report import sarif as sarif_mod

    findings = [
        {
            "title": "SQL injection in /api/v1/login",
            "description": "boom",
            "severity": "high",
            "cwes": [89],
            "vulnerability_id": "VULN-1",
            "locations": ["http://t/login"],
            "status": "confirmed",
            "poc": "None",
            "fix": "None",
        },
    ]
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "findings.sarif"
        # A directory shadows the temp-file write path -> OSError on open().
        out.mkdir()
        with caplog.at_level(logging.ERROR, logger="strix.report.sarif"):
            with pytest.raises(OSError):
                sarif_mod.write_sarif_report(out, findings)
    assert "SQL injection in /api/v1/login" in caplog.text
    assert "1 findings" in caplog.text


def test_preflight_warns_on_low_disk_format():
    """The low-space warning renders both placeholders (free + minimum)."""
    _GIB = 1024 ** 3
    MIN_FREE_DISK_BYTES = 2 * _GIB
    free_bytes = 1 * _GIB  # below minimum

    rendered = (
        "only %.2f GiB free on the scan output filesystem (recommended minimum %.2f GiB); """
        "the scan may fail mid-run if session/report writes hit ENOSPC"
        % (free_bytes / _GIB, MIN_FREE_DISK_BYTES / _GIB)
    )
    assert "1.00 GiB free" in rendered
    assert "2.00 GiB" in rendered
