"""Regression tests for Client-Side Path Traversal (CSPT) detection support.

Covers the three in-repo pillars of issue #776 that can run in CI without a live
browser/proxy:

1. The ``client-side-path-traversal`` skill exists, loads, and documents the
   source/sink taxonomy plus the "Not CSPT" boundary the agent relies on.
2. The HTML fixtures encode a real source->sink flow (positives) or a validation
   guard / safe construction (negatives), asserted structurally so they can't
   silently rot.
3. A CSPT finding is categorized separately from server-side path traversal /
   LFI / RFI: the ``finding_class`` param round-trips through the reporting tool
   and report state, and surfaces distinctly in SARIF (both as a property and as
   a distinct vulnerability-class fingerprint) even though both share CWE-22.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from strix.report.sarif import write_sarif
from strix.report.state import ReportState, set_global_report_state
from strix.skills import get_all_skill_names, get_available_skills, load_skills
from strix.tools.reporting.tool import _do_create


FIXTURES = Path(__file__).parent / "fixtures" / "cspt"

POSITIVE_FIXTURES = [
    "positive_direct.html",
    "positive_encoded.html",
    "positive_normalized.html",
    "positive_postmessage.html",
    "positive_storage.html",
]
NEGATIVE_FIXTURES = [
    "negative_validated.html",
    "negative_safe_construction.html",
]

# Browser request sinks whose *path* being tainted constitutes CSPT.
_SINK_MARKERS = ("fetch(", "XMLHttpRequest", ".open(", "axios", "sendBeacon", "EventSource")
# Client-side taint sources.
_SOURCE_MARKERS = (
    "location.hash",
    "location.search",
    "location.pathname",
    "URLSearchParams",
    "postMessage",
    "localStorage",
    "sessionStorage",
    "document.referrer",
)


# --------------------------------------------------------------------------- #
# Skill
# --------------------------------------------------------------------------- #


def test_cspt_skill_is_discoverable() -> None:
    assert "client_side_path_traversal" in get_all_skill_names()
    assert "client_side_path_traversal" in get_available_skills().get("vulnerabilities", [])


def test_cspt_skill_loads_with_frontmatter_stripped() -> None:
    loaded = load_skills(["client_side_path_traversal"])
    body = loaded.get("client_side_path_traversal")
    assert body, "CSPT skill failed to load"
    # Frontmatter must be stripped by the loader.
    assert not body.lstrip().startswith("---")
    assert body.lstrip().startswith("# Client-Side Path Traversal")


def test_cspt_skill_documents_sources_sinks_and_boundary() -> None:
    body = load_skills(["client_side_path_traversal"])["client_side_path_traversal"].lower()

    # It must teach the sources named in the issue.
    for source in ("location.hash", "postmessage", "referrer", "localstorage"):
        assert source in body, f"CSPT skill missing source: {source}"
    # ...and the request sinks.
    for sink in ("fetch", "xmlhttprequest", "axios"):
        assert sink in body, f"CSPT skill missing sink: {sink}"
    # ...and the explicit boundary vs. server-side classes so findings don't get
    # miscategorized.
    assert "not cspt" in body
    for other in ("lfi", "rfi", "server-side"):
        assert other in body, f"CSPT skill missing boundary reference: {other}"


def test_cspt_skill_prescribes_finding_class_and_cwe() -> None:
    body = load_skills(["client_side_path_traversal"])["client_side_path_traversal"]
    # The skill must tell the agent to tag the finding for separation.
    assert "client_side_path_traversal" in body
    assert "CWE-22" in body


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", POSITIVE_FIXTURES + NEGATIVE_FIXTURES)
def test_fixture_exists_and_is_html(name: str) -> None:
    path = FIXTURES / name
    assert path.is_file(), f"missing fixture {name}"
    text = path.read_text(encoding="utf-8")
    assert text.lstrip().lower().startswith("<!doctype html>")


@pytest.mark.parametrize("name", POSITIVE_FIXTURES)
def test_positive_fixture_has_source_flowing_into_a_request_sink(name: str) -> None:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    assert any(s in text for s in _SOURCE_MARKERS), f"{name}: no client-side source"
    assert any(s in text for s in _SINK_MARKERS), f"{name}: no request sink"
    # A positive must join a value into the request *path* (concatenation or a
    # template literal), not merely attach a query parameter.
    joins_into_path = '" + ' in text or "+ '" in text or "${" in text or "this.baseURL + " in text
    assert joins_into_path, f"{name}: no value concatenated into the request path"


@pytest.mark.parametrize("name", NEGATIVE_FIXTURES)
def test_negative_fixture_is_guarded_or_safe(name: str) -> None:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    # Still a real client source + sink (so it's a meaningful negative, not a
    # blank page), but neutralized.
    assert any(s in text for s in _SOURCE_MARKERS), f"{name}: no client-side source"
    assert any(s in text for s in _SINK_MARKERS), f"{name}: no request sink"

    if name == "negative_validated.html":
        # A strict allowlist guard on the segment before it reaches the sink.
        assert "^[a-z0-9-]" in text
        assert ".test(" in text
    elif name == "negative_safe_construction.html":
        # Value used as a query parameter against a constant path, never joined
        # into the path.
        assert "searchParams.set" in text
        assert '"/api/orders/" +' not in text


def test_positive_and_negative_fixtures_are_distinct() -> None:
    # Guard against a copy-paste that would make a "negative" actually vulnerable.
    negatives = {(FIXTURES / n).read_text(encoding="utf-8") for n in NEGATIVE_FIXTURES}
    positives = {(FIXTURES / n).read_text(encoding="utf-8") for n in POSITIVE_FIXTURES}
    assert negatives.isdisjoint(positives)


# --------------------------------------------------------------------------- #
# Categorization separation
# --------------------------------------------------------------------------- #


def _cvss() -> dict[str, str]:
    return {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "R",
        "scope": "U",
        "confidentiality": "H",
        "integrity": "N",
        "availability": "N",
    }


def _create_kwargs(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "title": "Client-Side Path Traversal in order-detail fetch",
        "description": "Fragment segment reaches a fetch path unvalidated.",
        "impact": "Authenticated request steered to a sibling admin endpoint.",
        "target": "https://app.example.com",
        "technical_analysis": "location.hash is concatenated into the fetch path.",
        "poc_description": "Open the app with a crafted fragment.",
        "poc_script_code": "location.hash = '#/orders/../../admin/keys'",
        "remediation_steps": "Validate the segment against an allowlist.",
        "evidence": "Outbound request path was /api/admin/keys with the session cookie.",
        "assumptions": "Assumes the victim opens a crafted link while authenticated.",
        "fix_effort": "low",
        "cvss_breakdown": _cvss(),
        "cwe": "CWE-22",
        "endpoint": None,
        "method": None,
        "cve": None,
        "code_locations": None,
    }
    base.update(overrides)
    return base


def test_do_create_accepts_cspt_finding_class() -> None:
    state = ReportState(run_name="cspt-test")
    set_global_report_state(state)
    try:
        result = asyncio.run(
            _do_create(finding_class="client_side_path_traversal", **_create_kwargs())
        )
    finally:
        set_global_report_state(None)  # type: ignore[arg-type]

    assert result["success"] is True, result
    assert len(state.vulnerability_reports) == 1
    assert state.vulnerability_reports[0]["finding_class"] == "client_side_path_traversal"


def test_do_create_defaults_finding_class_to_dynamic() -> None:
    state = ReportState(run_name="cspt-default")
    set_global_report_state(state)
    try:
        result = asyncio.run(_do_create(**_create_kwargs()))
    finally:
        set_global_report_state(None)  # type: ignore[arg-type]

    assert result["success"] is True, result
    assert state.vulnerability_reports[0]["finding_class"] == "dynamic"


def test_do_create_rejects_unknown_finding_class() -> None:
    result = asyncio.run(_do_create(finding_class="not_a_real_class", **_create_kwargs()))
    assert result["success"] is False
    assert any("finding_class" in e for e in result["errors"])


def test_sarif_surfaces_cspt_finding_class(tmp_path: Path) -> None:
    write_sarif(
        tmp_path,
        [
            {
                "id": "vuln-0001",
                "title": "Client-Side Path Traversal in order-detail fetch",
                "severity": "high",
                "cwe": "CWE-22",
                "finding_class": "client_side_path_traversal",
                "timestamp": "2026-07-16 10:00:00 UTC",
                "code_locations": [{"file": "app.js", "start_line": 12}],
            }
        ],
    )
    doc = json.loads((tmp_path / "findings.sarif").read_text(encoding="utf-8"))
    strix = doc["runs"][0]["results"][0]["properties"]["strix"]
    assert strix["finding_class"] == "client_side_path_traversal"


def test_sarif_omits_default_finding_class(tmp_path: Path) -> None:
    write_sarif(
        tmp_path,
        [
            {
                "id": "vuln-0001",
                "title": "Path Traversal in download handler",
                "severity": "high",
                "cwe": "CWE-22",
                "finding_class": "dynamic",
                "timestamp": "2026-07-16 10:00:00 UTC",
                "code_locations": [{"file": "app.py", "start_line": 4}],
            }
        ],
    )
    doc = json.loads((tmp_path / "findings.sarif").read_text(encoding="utf-8"))
    strix = doc["runs"][0]["results"][0]["properties"]["strix"]
    assert "finding_class" not in strix


def test_sarif_separates_cspt_from_server_side_traversal_class(tmp_path: Path) -> None:
    # Both share CWE-22 (same ruleId), but the class fingerprint must differ so
    # cross-run dismissal tooling doesn't collapse a CSPT alert into a
    # server-side path traversal alert.
    write_sarif(
        tmp_path,
        [
            {
                "id": "vuln-0001",
                "title": "Client-Side Path Traversal in order-detail fetch",
                "severity": "high",
                "cwe": "CWE-22",
                "finding_class": "client_side_path_traversal",
                "timestamp": "2026-07-16 10:00:00 UTC",
                "code_locations": [{"file": "app.js", "start_line": 12}],
            },
            {
                "id": "vuln-0002",
                "title": "Path Traversal in download file parameter",
                "severity": "high",
                "cwe": "CWE-22",
                "finding_class": "dynamic",
                "timestamp": "2026-07-16 10:00:00 UTC",
                "code_locations": [{"file": "server.py", "start_line": 30}],
            },
        ],
    )
    results = json.loads((tmp_path / "findings.sarif").read_text(encoding="utf-8"))["runs"][0][
        "results"
    ]
    hashes = [r["properties"].get("strix_vuln_class_hash") for r in results]
    assert all(hashes), "expected a class fingerprint on both findings"
    assert hashes[0] != hashes[1], "CSPT and server-side traversal share a class fingerprint"
