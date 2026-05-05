import json
from pathlib import Path
from typing import Any

from strix.telemetry.sarif import build_sarif_report, write_sarif_report


def _finding(**overrides: Any) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "id": "vuln-0001",
        "title": "Unsanitized redirect target",
        "severity": "high",
        "description": "A user-controlled redirect target is trusted without validation.",
        "impact": "Attackers can redirect users to phishing pages.",
        "remediation_steps": "Allow-list trusted redirect destinations.",
        "cvss": 8.1,
        "cwe": "CWE-601",
        "cve": "CVE-2026-0001",
        "target": "./demo-app",
        "endpoint": "/login",
        "method": "GET",
        "code_locations": [
            {
                "file": "src/auth/redirects.py",
                "start_line": 42,
                "end_line": 45,
                "snippet": "return redirect(request.args['next'])",
                "label": "User-controlled redirect sink",
            }
        ],
    }
    finding.update(overrides)
    return finding


def test_build_sarif_maps_code_location_and_metadata() -> None:
    sarif = build_sarif_report([_finding()], tool_version="0.8.3")

    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "Strix"
    assert driver["version"] == "0.8.3"
    rule = driver["rules"][0]
    assert rule["id"] == "CWE-601"
    assert rule["fullDescription"]["text"] == (
        "A user-controlled redirect target is trusted without validation."
    )
    assert "Allow-list trusted redirect destinations." in rule["help"]["text"]

    result = run["results"][0]
    assert result["ruleId"] == "CWE-601"
    assert result["level"] == "error"
    assert result["message"]["text"] == "Unsanitized redirect target"
    assert result["properties"]["cvss"] == 8.1
    assert result["properties"]["cve"] == "CVE-2026-0001"
    assert result["properties"]["target"] == "./demo-app"

    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/auth/redirects.py"
    assert location["region"] == {
        "startLine": 42,
        "endLine": 45,
        "snippet": {"text": "return redirect(request.args['next'])"},
    }


def test_build_sarif_maps_severity_levels() -> None:
    findings = [
        _finding(id="vuln-critical", severity="critical"),
        _finding(id="vuln-high", severity="high"),
        _finding(id="vuln-medium", severity="medium"),
        _finding(id="vuln-low", severity="low"),
        _finding(id="vuln-info", severity="info"),
    ]

    levels = [result["level"] for result in build_sarif_report(findings)["runs"][0]["results"]]

    assert levels == ["error", "error", "warning", "note", "note"]


def test_build_sarif_summarizes_locationless_findings_without_code_scanning_results() -> None:
    sarif = build_sarif_report([_finding(code_locations=None, cwe=None, cve=None)])

    run = sarif["runs"][0]
    assert run["results"] == []
    assert run["properties"]["locationlessFindingCount"] == 1
    assert run["properties"]["locationlessFindings"][0]["id"] == "vuln-0001"


def test_build_sarif_drops_unsafe_code_locations() -> None:
    sarif = build_sarif_report(
        [
            _finding(
                code_locations=[
                    {"file": "/tmp/app.py", "start_line": 1, "end_line": 1},
                    {"file": "../app.py", "start_line": 2, "end_line": 2},
                    {"file": "C:\\Users\\app.py", "start_line": 3, "end_line": 3},
                    {"file": "mailto:x", "start_line": 4, "end_line": 4},
                    {"file": "foo:bar.py", "start_line": 5, "end_line": 5},
                    {"file": "src/app.py", "start_line": 0, "end_line": 1},
                    {"file": "src/other.py", "start_line": True, "end_line": True},
                    {"file": "src/reversed.py", "start_line": 5, "end_line": 4},
                ]
            )
        ]
    )

    run = sarif["runs"][0]
    assert run["results"] == []
    assert run["properties"]["locationlessFindingCount"] == 1


def test_build_sarif_summarizes_dropped_unsafe_locations_when_safe_locations_remain() -> None:
    sarif = build_sarif_report(
        [
            _finding(
                code_locations=[
                    {"file": "src/app.py", "start_line": 10, "end_line": 12},
                    {"file": "foo:bar.py", "start_line": 1, "end_line": 1},
                ]
            )
        ]
    )

    run = sarif["runs"][0]
    assert len(run["results"]) == 1
    assert run["properties"]["droppedUnsafeLocationCount"] == 1
    assert run["properties"]["droppedUnsafeLocationFindings"][0] == {
        "id": "vuln-0001",
        "title": "Unsanitized redirect target",
        "droppedLocationCount": 1,
    }


def test_write_sarif_report_creates_parent_directories(tmp_path: Path) -> None:
    output_path = tmp_path / "nested" / "results.sarif"

    write_sarif_report(output_path, [_finding()], tool_version="0.8.3")

    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved["runs"][0]["results"][0]["ruleId"] == "CWE-601"
