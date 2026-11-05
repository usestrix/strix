"""STRIX_REQUIRE_POC flag: PoC mandatory by default, optional for raw-findings use."""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.tools.reporting import tool as reporting_tool


if TYPE_CHECKING:
    import pytest


def _all_filled_but_poc() -> dict[str, str]:
    fields = dict.fromkeys(reporting_tool._REQUIRED_FIELDS, "x")
    fields["poc_script_code"] = ""  # no runnable exploit
    return fields


def test_poc_required_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_REQUIRE_POC", raising=False)
    assert reporting_tool._poc_required() is True
    errors = reporting_tool._validate_required_text(_all_filled_but_poc())
    assert any("PoC" in e for e in errors)  # blank PoC rejected


def test_poc_optional_when_flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_REQUIRE_POC", "0")
    assert reporting_tool._poc_required() is False
    # blank PoC + everything else present -> no errors (finding is filable)
    assert reporting_tool._validate_required_text(_all_filled_but_poc()) == []


def test_flag_off_still_enforces_other_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_REQUIRE_POC", "off")
    fields = _all_filled_but_poc()
    fields["evidence"] = ""  # a non-PoC required field left blank
    errors = reporting_tool._validate_required_text(fields)
    assert any("Evidence" in e for e in errors)
    assert not any("PoC" in e for e in errors)  # PoC still exempt


def test_flag_falsey_and_truthy_values(monkeypatch: pytest.MonkeyPatch) -> None:
    for off in ("0", "false", "no", "off", "False", "OFF"):
        monkeypatch.setenv("STRIX_REQUIRE_POC", off)
        assert reporting_tool._poc_required() is False, off
    for on in ("1", "true", "yes", ""):  # empty/ambiguous -> safe default (required)
        monkeypatch.setenv("STRIX_REQUIRE_POC", on)
        assert reporting_tool._poc_required() is True, on


# The runtime validators above are the single source of required-ness, because the
# flags are per-run env and the tool schema is built once at import. The schema must
# therefore mark the flag-gated fields OPTIONAL — otherwise a required-in-schema PoC
# forces the model to emit (and fabricate) one even when STRIX_REQUIRE_POC=0. The
# always-required essentials stay schema-required.
_SCHEMA_OPTIONAL = frozenset(
    {
        "poc_script_code",
        "technical_analysis",
        "poc_description",
        "remediation_steps",
        "evidence",
        "assumptions",
        "counterevidence",
        "severity_change_conditions",
    }
)
_SCHEMA_REQUIRED = frozenset(
    {"title", "description", "impact", "target", "confidence", "fix_effort", "cvss_breakdown"}
)


def test_flag_gated_fields_are_schema_optional() -> None:
    required = set(reporting_tool.create_vulnerability_report.params_json_schema["required"])
    # every always-required essential is still schema-required
    assert required >= _SCHEMA_REQUIRED
    # no flag-gated field is schema-required (the model may omit it; the flag-aware
    # runtime validator decides whether the omission is allowed)
    assert not (_SCHEMA_OPTIONAL & required)
