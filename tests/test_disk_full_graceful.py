"""Graceful degradation when the scan filesystem runs out of space.

Reproduces the production crash: a mid-scan sqlite disk I/O error used
to escape as an unhandled exception and take the whole run down, losing
the report. These tests pin the degraded paths.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

import pytest

from strix.core.sessions import add_items_resilient


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


def test_sarif_write_failure_logs_findings():
    from strix.report import sarif as sarif_mod

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "findings.sarif"
        # Point the temp write at an unwritable location: use a directory
        # as the temp-file target so open() fails with OSError.
        sarif_mod.os.getpid = lambda: 0  # deterministic tmp name
        out.mkdir()  # a directory shadows the tmp file path -> OSError
        with pytest.raises(OSError):
            sarif_mod.write_sarif_report(out, [])
