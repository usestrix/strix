"""STRIX_RELAX_FINDING_FIELDS relaxes a subset of create_vulnerability_report's
required analysis fields so a weak model / raw-findings run can still RECORD a
finding (essentials stay required) instead of having it rejected for a missing
analysis field — the create-side cause of findings-detected-but-never-filed
(usestrix/strix#1439). Deterministic: all validators are pure, no LLM.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from strix.tools.reporting.tool import (
    _relaxed_fields,
    _validate_analysis_fields,
    _validate_required_text,
)


if TYPE_CHECKING:
    import pytest

_MINIMAL = {
    "title": "SSTI in /hello",
    "description": "user input into render_template_string",
    "impact": "RCE",
    "target": "/workspace/app",
    "technical_analysis": "",
    "poc_description": "",
    "poc_script_code": "",
    "remediation_steps": "",
    "evidence": "",
    "assumptions": "",
}


def _analysis_errs() -> list[str]:
    return _validate_analysis_fields(
        counterevidence="",
        confidence="high",
        confidence_rationale=None,
        severity_change_conditions="",
    )


def test_relaxed_fields_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_RELAX_FINDING_FIELDS", raising=False)
    assert _relaxed_fields() == frozenset()
    monkeypatch.setenv("STRIX_RELAX_FINDING_FIELDS", "all")
    assert "counterevidence" in _relaxed_fields() and "evidence" in _relaxed_fields()
    monkeypatch.setenv("STRIX_RELAX_FINDING_FIELDS", "counterevidence,assumptions")
    assert _relaxed_fields() == frozenset({"counterevidence", "assumptions"})
    # essentials can never be relaxed (not in the relaxable set)
    monkeypatch.setenv("STRIX_RELAX_FINDING_FIELDS", "title,description,evidence")
    assert _relaxed_fields() == frozenset({"evidence"})


def test_relaxed_fields_warns_on_unknown(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # A typo'd field name must not be silently ignored.
    monkeypatch.setenv("STRIX_RELAX_FINDING_FIELDS", "evidence,technical_analsis")
    with caplog.at_level(logging.WARNING):
        assert _relaxed_fields() == frozenset({"evidence"})
    assert "technical_analsis" in caplog.text
    assert "unrecognized" in caplog.text.lower()


def test_strict_rejects_blank_analysis_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_RELAX_FINDING_FIELDS", raising=False)
    monkeypatch.setenv("STRIX_REQUIRE_POC", "0")
    assert _validate_required_text(_MINIMAL)  # technical_analysis/evidence/... still required
    assert _analysis_errs()  # counterevidence + severity_change_conditions required


def test_relax_all_files_with_essentials_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_REQUIRE_POC", "0")
    monkeypatch.setenv("STRIX_RELAX_FINDING_FIELDS", "all")
    assert _validate_required_text(_MINIMAL) == []  # essentials present, analysis fields relaxed
    assert _analysis_errs() == []


def test_relax_subset_only_drops_named(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_REQUIRE_POC", "0")
    monkeypatch.setenv("STRIX_RELAX_FINDING_FIELDS", "counterevidence,severity_change_conditions")
    # the two analysis-validator fields are relaxed...
    assert _analysis_errs() == []
    # ...but the text analysis fields (evidence/assumptions/...) are still required
    assert _validate_required_text(_MINIMAL)


def test_essentials_still_required_when_blank(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_REQUIRE_POC", "0")
    monkeypatch.setenv("STRIX_RELAX_FINDING_FIELDS", "all")
    blank_title = {**_MINIMAL, "title": ""}
    errs = _validate_required_text(blank_title)
    assert any("Title" in e for e in errs)  # essential not relaxable
