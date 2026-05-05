"""Build GitHub-compatible SARIF output from Strix vulnerability reports."""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, cast


if TYPE_CHECKING:
    from pathlib import Path


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Strix"
TOOL_INFORMATION_URI = "https://strix.ai"


def build_sarif_report(
    vulnerability_reports: list[dict[str, Any]],
    *,
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Return a SARIF 2.1.0 document for findings with safe source locations."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    locationless_findings: list[dict[str, Any]] = []
    dropped_unsafe_location_findings: list[dict[str, Any]] = []

    for report in vulnerability_reports:
        locations, dropped_location_count = _build_locations(report.get("code_locations"))
        if not locations:
            locationless_findings.append(_locationless_summary(report))
            continue
        if dropped_location_count:
            dropped_unsafe_location_findings.append(
                _dropped_location_summary(report, dropped_location_count)
            )

        rule_id = _rule_id(report)
        rules_by_id.setdefault(rule_id, _build_rule(rule_id, report))
        results.append(_build_result(rule_id, report, locations))

    driver: dict[str, Any] = {
        "name": TOOL_NAME,
        "informationUri": TOOL_INFORMATION_URI,
        "rules": list(rules_by_id.values()),
    }
    if tool_version:
        driver["version"] = tool_version

    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "results": results,
    }
    if locationless_findings:
        run["properties"] = {
            "locationlessFindingCount": len(locationless_findings),
            "locationlessFindings": locationless_findings,
        }
    if dropped_unsafe_location_findings:
        properties = run.setdefault("properties", {})
        properties["droppedUnsafeLocationCount"] = sum(
            finding["droppedLocationCount"] for finding in dropped_unsafe_location_findings
        )
        properties["droppedUnsafeLocationFindings"] = dropped_unsafe_location_findings

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [run],
    }


def write_sarif_report(
    output_path: Path,
    vulnerability_reports: list[dict[str, Any]],
    *,
    tool_version: str | None = None,
) -> None:
    """Write a SARIF report to disk, creating parent directories first."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    sarif = build_sarif_report(vulnerability_reports, tool_version=tool_version)
    with output_path.open("w", encoding="utf-8") as sarif_file:
        json.dump(sarif, sarif_file, ensure_ascii=False, indent=2)
        sarif_file.write("\n")


def _build_rule(rule_id: str, report: dict[str, Any]) -> dict[str, Any]:
    """Build a SARIF rule descriptor from a Strix finding."""
    title = _string_value(report.get("title")) or rule_id
    full_description = _string_value(report.get("description")) or title
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": title,
        "shortDescription": {"text": title},
        "fullDescription": {"text": full_description},
        "help": {"text": _help_text(report, full_description)},
    }

    tags = [_string_value(report.get(key)) for key in ("cwe", "cve")]
    rule_tags = [tag for tag in tags if tag]
    if rule_tags:
        rule["properties"] = {"tags": rule_tags}

    return rule


def _build_result(
    rule_id: str,
    report: dict[str, Any],
    locations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build one SARIF result using validated physical locations."""
    title = _string_value(report.get("title")) or rule_id
    return {
        "ruleId": rule_id,
        "level": _sarif_level(report.get("severity")),
        "message": {"text": title},
        "locations": locations,
        "properties": _result_properties(report),
    }


def _result_properties(report: dict[str, Any]) -> dict[str, Any]:
    """Return non-empty Strix finding metadata for SARIF properties."""
    properties: dict[str, Any] = {}
    for key in (
        "id",
        "severity",
        "cvss",
        "target",
        "endpoint",
        "method",
        "cve",
        "cwe",
        "impact",
        "remediation_steps",
    ):
        value = report.get(key)
        if value not in (None, ""):
            properties[key] = value
    return properties


def _build_locations(raw_locations: Any) -> tuple[list[dict[str, Any]], int]:
    """Return SARIF locations and a count of dropped unsafe locations."""
    if not isinstance(raw_locations, list):
        return [], 0

    raw_locations_list = cast("list[Any]", raw_locations)  # type: ignore[redundant-cast]
    locations: list[dict[str, Any]] = []
    dropped_location_count = 0
    for raw_location in raw_locations_list:
        if not isinstance(raw_location, dict):
            dropped_location_count += 1
            continue

        location = cast("dict[str, Any]", raw_location)
        file_path = _string_value(location.get("file"))
        start_line = location.get("start_line")
        end_line = location.get("end_line")
        if not file_path or type(start_line) is not int or start_line < 1:
            dropped_location_count += 1
            continue
        uri = _sarif_uri(file_path)
        if uri is None:
            dropped_location_count += 1
            continue

        region: dict[str, Any] = {"startLine": start_line}
        if type(end_line) is int and end_line >= start_line:
            region["endLine"] = end_line

        snippet = _string_value(location.get("snippet"))
        if snippet:
            region["snippet"] = {"text": snippet}

        locations.append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": region,
                }
            }
        )

    return locations, dropped_location_count


def _rule_id(report: dict[str, Any]) -> str:
    """Choose a stable SARIF rule id from CWE, CVE, id, or title."""
    for key in ("cwe", "cve", "id"):
        value = _string_value(report.get(key))
        if value:
            return value

    title = _string_value(report.get("title")) or "strix-finding"
    return _slugify(title)


def _sarif_level(severity: Any) -> str:
    """Map Strix severity labels to SARIF result levels."""
    normalized = (_string_value(severity) or "").lower()
    if normalized in {"critical", "high"}:
        return "error"
    if normalized == "medium":
        return "warning"
    return "note"


def _sarif_uri(file_path: str) -> str | None:
    """Return a safe repo-relative SARIF URI, or None for unsafe paths."""
    uri = PurePosixPath(file_path.replace("\\", "/")).as_posix()
    parts = PurePosixPath(uri).parts
    if not uri or uri.startswith("/") or not parts:
        return None
    if ":" in parts[0] or any(part == ".." for part in parts):
        return None
    return uri


def _string_value(value: Any) -> str | None:
    """Return a stripped non-empty string value, or None."""
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _slugify(value: str) -> str:
    """Convert arbitrary finding text into a stable lowercase slug."""
    chars = [char.lower() if char.isalnum() else "-" for char in value]
    slug = "-".join(part for part in "".join(chars).split("-") if part)
    return slug or "strix-finding"


def _help_text(report: dict[str, Any], fallback: str) -> str:
    """Assemble SARIF help text from finding details and remediation."""
    sections = [
        _string_value(report.get("description")),
        _string_value(report.get("impact")),
        _string_value(report.get("remediation_steps")),
    ]
    help_text = "\n\n".join(section for section in sections if section)
    return help_text or fallback


def _locationless_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Summarize findings that cannot be emitted as code-scanning alerts."""
    summary: dict[str, Any] = {}
    for key in ("id", "title", "severity", "cwe", "cve", "target", "endpoint", "method"):
        value = report.get(key)
        if value not in (None, ""):
            summary[key] = value
    return summary


def _dropped_location_summary(
    report: dict[str, Any],
    dropped_location_count: int,
) -> dict[str, Any]:
    """Summarize unsafe locations dropped from a partially emitted finding."""
    summary: dict[str, Any] = {"droppedLocationCount": dropped_location_count}
    for key in ("id", "title"):
        value = report.get(key)
        if value not in (None, ""):
            summary[key] = value
    return summary
