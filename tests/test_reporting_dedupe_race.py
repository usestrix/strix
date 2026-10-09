"""Findings filed at the same moment must go through the duplicate check one at a time.

The duplicate check awaits an LLM call and compares the candidate with the findings
stored when it started. Two agents filing the same finding concurrently used to both
pass it, because neither saw the other's report yet, and the run stored it twice.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from strix.report.state import ReportState, set_global_report_state
from strix.tools.reporting.tool import _do_create, _do_create_dependency


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "H",
    "availability": "H",
}


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReportState]:
    monkeypatch.chdir(tmp_path)
    report_state = ReportState(run_name="dedupe-race")
    set_global_report_state(report_state)
    yield report_state
    set_global_report_state(None)


async def _slow_check(candidate: dict[str, Any], existing: list[dict[str, Any]]) -> dict[str, Any]:
    """Stand in for the real check: it judges the candidate against the snapshot it is handed."""
    await asyncio.sleep(0.05)  # the real one is a model call
    for report in existing:
        if report.get("title") == candidate["title"]:
            return {
                "is_duplicate": True,
                "duplicate_id": report["id"],
                "confidence": 0.99,
                "reason": "same title",
            }
    return {"is_duplicate": False, "duplicate_id": "", "confidence": 0.9, "reason": "new"}


@pytest.fixture(autouse=True)
def slow_dedupe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("strix.report.dedupe.check_duplicate", _slow_check)


def _vulnerability(title: str = "SQL injection in /login") -> dict[str, Any]:
    return {
        "title": title,
        "description": "d",
        "impact": "i",
        "target": "http://target.example",
        "technical_analysis": "ta",
        "poc_description": "pd",
        "poc_script_code": "curl http://target.example/login",
        "remediation_steps": "rs",
        "evidence": "ev",
        "assumptions": "as",
        "counterevidence": "none found",
        "confidence": "high",
        "severity_change_conditions": "none",
        "fix_effort": "low",
        "cvss_breakdown": _CVSS,
        "endpoint": "/login",
        "method": "POST",
        "cve": None,
        "cwe": None,
        "code_locations": None,
    }


def _dependency(title: str = "Vulnerable requests release") -> dict[str, Any]:
    return {
        "title": title,
        "description": "d",
        "target": "http://target.example",
        "cve": "CVE-2024-35195",
        "package_name": "requests",
        "installed_version": "2.31.0",
        "impact": "i",
        "remediation_steps": "upgrade",
        "assumptions": "as",
        "package_ecosystem": "pypi",
        "fixed_version": "2.32.0",
        "cwe": None,
        "advisory_cvss": 5.6,
        "technical_analysis": "ta",
        "fix_effort": "low",
        "manifest_path": "requirements.txt",
        "reachability": "unknown",
        "reachability_evidence": "searched the imports; no direct call found",
        "contextual_cvss_breakdown": _CVSS,
        "contextual_cvss_reasoning": "published rating unchanged by the usage seen",
    }


async def test_same_finding_filed_concurrently_is_stored_once(state: ReportState) -> None:
    first, second = await asyncio.gather(
        _do_create(**_vulnerability()), _do_create(**_vulnerability())
    )

    assert sorted([first["success"], second["success"]]) == [False, True]
    rejected = first if not first["success"] else second
    assert rejected["duplicate_of"] == state.vulnerability_reports[0]["id"]
    assert len(state.vulnerability_reports) == 1


async def test_distinct_findings_filed_concurrently_are_all_stored(state: ReportState) -> None:
    results = await asyncio.gather(
        _do_create(**_vulnerability("SQL injection in /login")),
        _do_create(**_vulnerability("Reflected XSS in /search")),
        _do_create(**_vulnerability("IDOR in /orders")),
    )

    assert all(result["success"] for result in results)
    assert len(state.vulnerability_reports) == 3


async def test_same_dependency_finding_filed_concurrently_is_stored_once(
    state: ReportState,
) -> None:
    first, second = await asyncio.gather(
        _do_create_dependency(**_dependency()), _do_create_dependency(**_dependency())
    )

    assert sorted([first["success"], second["success"]]) == [False, True]
    assert len(state.vulnerability_reports) == 1


async def test_a_failing_check_does_not_leave_the_lock_held(
    state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(*_args: object) -> dict[str, Any]:
        raise RuntimeError("dedupe model unreachable")

    monkeypatch.setattr("strix.report.dedupe.check_duplicate", broken)
    failed = await _do_create(**_vulnerability())
    assert failed["success"] is False
    assert not state.dedupe_lock.locked()

    monkeypatch.setattr("strix.report.dedupe.check_duplicate", _slow_check)
    retried = await asyncio.wait_for(_do_create(**_vulnerability()), timeout=5)
    assert retried["success"] is True
