"""Findings filed at the same moment must go through the duplicate check one at a time.

The duplicate check awaits a model call and compares the candidate with the findings
stored when it started. Two agents filing the same finding concurrently used to both
pass it, because neither saw the other's report yet, and the run stored it twice.

These tests drive the real ``check_duplicate``. It only reaches the model when something
is already stored (an empty store returns at once, with nothing to await), so every test
seeds an unrelated finding first, and the model is a stand-in that pauses like a real
call and judges the candidate against the reports in the request it is handed.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

import pytest
from agents.items import ModelResponse
from agents.usage import Usage
from openai.types.responses import ResponseOutputMessage, ResponseOutputText

from strix.config import loader
from strix.report import dedupe
from strix.report.state import ReportState, set_global_report_state
from strix.tools.reporting.tool import _do_create, _do_create_dependency


if TYPE_CHECKING:
    from collections.abc import AsyncIterator
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

_PROMPT_HEAD = "Compare this candidate vulnerability against existing reports:\n\n"
_PROMPT_TAIL = "\n\nRespond with ONLY the JSON object"


class _FakeDedupeModel:
    """A dedupe model that pauses like a real call and judges by title."""

    def __init__(self) -> None:
        self.calls = 0

    async def get_response(self, *, input: str, **_kwargs: Any) -> ModelResponse:  # noqa: A002
        self.calls += 1
        await asyncio.sleep(0.05)
        payload = json.loads(input.split(_PROMPT_HEAD, 1)[1].split(_PROMPT_TAIL, 1)[0])
        verdict = {"is_duplicate": False, "duplicate_id": "", "confidence": 0.9, "reason": "new"}
        for report in payload["existing_reports"]:
            if report.get("title") == payload["candidate"].get("title"):
                verdict = {
                    "is_duplicate": True,
                    "duplicate_id": report["id"],
                    "confidence": 0.99,
                    "reason": "same title",
                }
        message = ResponseOutputMessage(
            id="msg",
            role="assistant",
            status="completed",
            type="message",
            content=[
                ResponseOutputText(type="output_text", text=json.dumps(verdict), annotations=[])
            ],
        )
        return ModelResponse(output=[message], usage=Usage(), response_id=None)


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


def _dependency() -> dict[str, Any]:
    return {
        "title": "Vulnerable example-package dependency",
        "description": "The package is pinned to an affected version.",
        "target": "package-lock.json",
        "cve": "CVE-2024-0001",
        "package_name": "example-package",
        "installed_version": "1.0.0",
        "impact": "The dependency exposes the vulnerable code path.",
        "remediation_steps": "Upgrade to the fixed version.",
        "assumptions": "The lockfile describes the deployed application.",
        "package_ecosystem": "npm",
        "manifest_path": "package-lock.json",
        "fixed_version": "1.0.1",
        "cwe": None,
        "advisory_cvss": 7.5,
        "technical_analysis": "The package is present in the lockfile.",
        "fix_effort": "low",
        "reachability_evidence": "The package is installed; call sites have not been traced.",
        "contextual_cvss_breakdown": _CVSS,
        "contextual_cvss_reasoning": "The fixture retains the advisory impact assumptions.",
    }


@pytest.fixture
def model(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> _FakeDedupeModel:
    fake = _FakeDedupeModel()
    # Settings are memoized and fall back to the developer's stored config, so point
    # them at an empty file and a model name instead of whatever ran before.
    monkeypatch.setattr(loader, "_override", tmp_path / "no-config.json")
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.delenv("STRIX_DEDUPE_MODEL", raising=False)
    monkeypatch.setenv("STRIX_LLM", "openai/fake-dedupe")
    monkeypatch.setattr("strix.report.dedupe.configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr("strix.report.dedupe.resolve_dedupe_model", lambda *_args: fake)
    return fake


@pytest.fixture
async def state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, model: _FakeDedupeModel
) -> AsyncIterator[ReportState]:
    monkeypatch.chdir(tmp_path)
    report_state = ReportState(run_name="dedupe-race")
    set_global_report_state(report_state)
    # With nothing stored the real check returns before it awaits anything, so store one
    # unrelated finding: from here on every check goes to the model.
    seeded = await _do_create(**_vulnerability("Open redirect in /logout"))
    assert seeded["success"] is True
    assert model.calls == 0
    yield report_state
    set_global_report_state(None)


async def test_same_finding_filed_concurrently_is_stored_once(
    state: ReportState, model: _FakeDedupeModel
) -> None:
    first, second = await asyncio.gather(
        _do_create(**_vulnerability()), _do_create(**_vulnerability())
    )

    assert sorted([first["success"], second["success"]]) == [False, True]
    rejected = first if not first["success"] else second
    stored = [r for r in state.vulnerability_reports if r["title"] == "SQL injection in /login"]
    assert rejected["duplicate_of"] == stored[0]["id"]
    assert len(stored) == 1
    assert len(state.vulnerability_reports) == 2
    assert model.calls == 2  # both went through the model, one after the other


async def test_distinct_findings_filed_concurrently_are_all_stored(state: ReportState) -> None:
    results = await asyncio.gather(
        _do_create(**_vulnerability("SQL injection in /login")),
        _do_create(**_vulnerability("Reflected XSS in /search")),
        _do_create(**_vulnerability("IDOR in /orders")),
    )

    assert all(result["success"] for result in results)
    assert len(state.vulnerability_reports) == 4


async def test_dependency_model_fallback_serializes_concurrent_filings(
    state: ReportState, model: _FakeDedupeModel
) -> None:
    # A finding with the same CVE but no package identity makes the real
    # dependency check fall back to the model instead of returning synchronously.
    legacy = await _do_create(
        **{**_vulnerability("Existing application finding"), "cve": "CVE-2024-0001"}
    )
    assert legacy["success"] is True
    calls_before = model.calls

    first, second = await asyncio.gather(
        _do_create_dependency(**_dependency()), _do_create_dependency(**_dependency())
    )

    assert sorted([first["success"], second["success"]]) == [False, True]
    stored = [r for r in state.vulnerability_reports if r.get("finding_class") == "dependency_cve"]
    assert len(stored) == 1
    rejected = first if not first["success"] else second
    assert rejected["duplicate_of"] == stored[0]["id"]
    # The first filing calls the model; the next sees its package identity.
    assert model.calls - calls_before == 1


async def test_dependency_identity_fast_path_still_needs_no_model(
    state: ReportState, model: _FakeDedupeModel
) -> None:
    first, second = await asyncio.gather(
        _do_create_dependency(**_dependency()), _do_create_dependency(**_dependency())
    )

    assert sorted([first["success"], second["success"]]) == [False, True]
    assert len(state.vulnerability_reports) == 2
    assert model.calls == 0


async def test_a_failing_check_does_not_leave_the_lock_held(
    state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(*_args: object) -> dict[str, Any]:
        raise RuntimeError("dedupe model unreachable")

    real_check = dedupe.check_duplicate
    monkeypatch.setattr(dedupe, "check_duplicate", broken)
    failed = await _do_create(**_vulnerability())
    assert failed["success"] is False
    assert not state.dedupe_lock.locked()

    monkeypatch.setattr(dedupe, "check_duplicate", real_check)
    retried = await asyncio.wait_for(_do_create(**_vulnerability()), timeout=5)
    assert retried["success"] is True
