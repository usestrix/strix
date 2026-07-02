"""Regression test for the vulnerability-dedup TOCTOU race (issue #627).

Concurrent child agents call `create_vulnerability_report` as asyncio tasks.
Without synchronization, two agents can both read the same
`get_existing_vulnerabilities()` snapshot, both await the (slow, LLM-backed)
`check_duplicate` call, and both pass it for the same vulnerability before
either has written — producing a duplicate report on disk. `ReportState`
exposes `dedupe_lock` so the read-check-write sequence in
`strix/tools/reporting/tool.py` can be serialized; these tests exercise that
lock directly against the same check-then-write shape used there.
"""

from __future__ import annotations

import asyncio

from strix.report.state import ReportState


async def _check_duplicate_stub(
    candidate: dict[str, str], existing: list[dict[str, str]]
) -> dict[str, object]:
    # Stands in for `strix.report.dedupe.check_duplicate`: a slow async call
    # (in production, an LLM request) that opens the race window.
    await asyncio.sleep(0.05)
    for report in existing:
        if report.get("title") == candidate["title"]:
            return {"is_duplicate": True, "duplicate_id": report["id"]}
    return {"is_duplicate": False}


async def _create_vulnerability_report_locked(report_state: ReportState, title: str) -> str | None:
    async with report_state.dedupe_lock:
        existing = report_state.get_existing_vulnerabilities()
        dedupe = await _check_duplicate_stub({"title": title}, existing)
        if dedupe.get("is_duplicate"):
            return None
        return report_state.add_vulnerability_report(title=title, severity="high")


def test_report_state_exposes_dedupe_lock(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report_state = ReportState(run_name="lock-attr-test")
    assert isinstance(report_state.dedupe_lock, asyncio.Lock)


async def test_concurrent_duplicate_reports_collapse_to_one_with_lock(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    report_state = ReportState(run_name="race-test-locked")

    results = await asyncio.gather(
        _create_vulnerability_report_locked(report_state, "SQL Injection in /login"),
        _create_vulnerability_report_locked(report_state, "SQL Injection in /login"),
        _create_vulnerability_report_locked(report_state, "SQL Injection in /login"),
        _create_vulnerability_report_locked(report_state, "XSS in /search"),
    )

    assert len(report_state.vulnerability_reports) == 2
    titles = sorted(r["title"] for r in report_state.vulnerability_reports)
    assert titles == ["SQL Injection in /login", "XSS in /search"]
    assert sum(r is not None for r in results) == 2
