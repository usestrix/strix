"""Regression test for the vulnerability-dedup TOCTOU race (issue #627).

Concurrent child agents call `create_vulnerability_report` as asyncio tasks.
Without synchronization, two agents can both read the same
`get_existing_vulnerabilities()` snapshot, both await the (slow, LLM-backed)
`check_duplicate` call, and both pass it for the same vulnerability before
either has written — producing a duplicate report on disk.

The fix uses a two-phase pattern instead of holding `dedupe_lock` across the
whole sequence (which would serialize every concurrent report on the LLM
call): snapshot under the lock and release it, run the duplicate check
unlocked, then re-acquire the lock and re-check only the entries written
since the snapshot before writing. These tests exercise that exact shape,
matching `strix/tools/reporting/tool.py`.
"""

from __future__ import annotations

import asyncio
import time

from strix.report.state import ReportState
from strix.telemetry import posthog, scarf


def _disable_telemetry(monkeypatch) -> None:
    # `add_vulnerability_report` calls posthog/scarf synchronously, which make
    # blocking network requests (urllib, 10s timeout) — unrelated to the
    # dedup-lock behavior under test and otherwise dominates/serializes the
    # timing-sensitive throughput test below.
    monkeypatch.setattr(posthog, "finding", lambda *_a, **_kw: None)
    monkeypatch.setattr(scarf, "finding", lambda *_a, **_kw: None)


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


async def _create_vulnerability_report_two_phase(
    report_state: ReportState, title: str
) -> str | None:
    candidate = {"title": title}

    async with report_state.dedupe_lock:
        existing = report_state.get_existing_vulnerabilities()

    dedupe = await _check_duplicate_stub(candidate, existing)
    if dedupe.get("is_duplicate"):
        return None

    # Re-validate against entries written since the snapshot with a cheap
    # exact-title match (not another LLM call), matching tool.py: this closes
    # the race without holding the lock across a second slow duplicate check.
    candidate_title = title.strip().lower()
    async with report_state.dedupe_lock:
        existing_now = report_state.get_existing_vulnerabilities()
        new_entries = existing_now[len(existing) :]
        if any(str(r.get("title", "")).strip().lower() == candidate_title for r in new_entries):
            return None
        return report_state.add_vulnerability_report(title=title, severity="high")


def test_report_state_exposes_dedupe_lock(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report_state = ReportState(run_name="lock-attr-test")
    assert isinstance(report_state.dedupe_lock, asyncio.Lock)


async def test_concurrent_duplicate_reports_collapse_to_one(tmp_path, monkeypatch) -> None:
    # A 5-way collision on the same vulnerability, plus one distinct
    # vulnerability, should collapse to exactly one report each.
    monkeypatch.chdir(tmp_path)
    _disable_telemetry(monkeypatch)
    report_state = ReportState(run_name="race-test-two-phase")

    results = await asyncio.gather(
        _create_vulnerability_report_two_phase(report_state, "SQL Injection in /login"),
        _create_vulnerability_report_two_phase(report_state, "SQL Injection in /login"),
        _create_vulnerability_report_two_phase(report_state, "SQL Injection in /login"),
        _create_vulnerability_report_two_phase(report_state, "SQL Injection in /login"),
        _create_vulnerability_report_two_phase(report_state, "SQL Injection in /login"),
        _create_vulnerability_report_two_phase(report_state, "XSS in /search"),
    )

    assert len(report_state.vulnerability_reports) == 2
    titles = sorted(r["title"] for r in report_state.vulnerability_reports)
    assert titles == ["SQL Injection in /login", "XSS in /search"]
    assert sum(r is not None for r in results) == 2


async def test_distinct_reports_are_not_serialized_on_duplicate_check(
    tmp_path, monkeypatch
) -> None:
    # The whole point of the two-phase design: concurrent agents filing
    # *distinct* vulnerabilities must not block on each other's LLM-backed
    # duplicate check. If the lock were held across `check_duplicate` (the
    # bug this test guards against), N concurrent reports would take
    # roughly N * sleep_duration; with the lock only around the fast
    # read/write, they overlap and take roughly one sleep_duration.
    monkeypatch.chdir(tmp_path)
    _disable_telemetry(monkeypatch)
    report_state = ReportState(run_name="throughput-test")

    n = 6
    start = time.perf_counter()
    await asyncio.gather(
        *(
            _create_vulnerability_report_two_phase(report_state, f"Distinct vuln {i}")
            for i in range(n)
        )
    )
    elapsed = time.perf_counter() - start

    assert len(report_state.vulnerability_reports) == n
    # One stubbed check is 0.05s; serialized-on-the-LLM-call would take
    # ~n * 0.05s = 0.3s. Allow generous headroom while still clearly
    # distinguishing "overlapped" from "serialized".
    assert elapsed < 0.05 * (n / 2)
