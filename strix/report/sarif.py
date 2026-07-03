"""SARIF 2.1.0 output for Strix vulnerability reports.

Builds a GitHub code-scanning compatible SARIF document from Strix findings
so CI pipelines can upload findings via ``github/codeql-action/upload-sarif``,
ingest into ASPM platforms, or normalise across scanners.

Schema: SARIF 2.1.0 (OASIS). The output is validated against the official
schema at https://json.schemastore.org/sarif-2.1.0.json in tests.

Integration:
  - ``ReportState._save_artifacts`` calls :func:`write_sarif` to emit a
    ``findings.sarif`` sidecar alongside the existing CSV + markdown + JSON
    artefacts on every save. The call is wrapped in try/except there so a
    SARIF failure never blocks the CSV + markdown + run-record path.

Design notes:
  * Rules are keyed on CWE (``id = CWE-NNN``), falling back to CVE, then
    to finding-id, then to a title slug. CWE values are normalised from
    Strix output variants (``CWE-306``, ``cwe: 306``, ``306``) to the
    canonical ``CWE-NNN`` form so dedup works across runs.
  * SARIF only has three levels (error / warning / note). Strix's five
    severities collapse into them. The raw severity label and CVSS score
    survive in ``result.properties.strix`` for downstream tools that can
    distinguish CRITICAL vs HIGH.
  * GitHub code-scanning uses ``rule.properties['security-severity']``
    (a 0.0-10.0 string) to rank alerts. We populate it from CVSS when
    available, otherwise from a conservative label -> score map.
  * File locations must be repo-relative POSIX paths. Paths that look
    like URIs, absolute paths, or traversal patterns are rejected rather
    than emitted as invalid code-scanning alerts.
  * Findings with a fix suggestion (``code_locations[].fix_before`` +
    ``fix_after``) are emitted as SARIF ``fixes`` so code-scanning can
    render a one-click suggested change.
  * Endpoint / target-only findings (typical of DAST) carry a SARIF
    ``logicalLocations`` entry so the finding keeps a meaningful anchor
    even without a source file + line.
  * When a repository context is supplied (repo URL / commit / branch),
    the run carries ``versionControlProvenance`` + ``automationDetails``
    so code-scanning can bind alerts to the scanned commit and branch.
  * Findings without safe locations still appear in the SARIF output,
    anchored to SECURITY.md and flagged via
    ``properties.synthetic_location`` rather than being dropped silently.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any, cast


logger = logging.getLogger(__name__)


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Strix"
TOOL_INFORMATION_URI = "https://strix.ai"

# Synthetic anchor for findings that have no safe code location. SARIF
# requires every result to carry at least one location, and GitHub
# code-scanning's UI handles locationless results unreliably. Anchoring
# to SECURITY.md keeps the result valid + visible while a
# ``properties.synthetic_location: true`` flag lets downstream tooling
# distinguish synthetic anchors from real source locations. Anchoring
# also lets the partialFingerprints + class-hash code path cover these
# findings instead of re-orphaning them on every run.
_SYNTHETIC_LOCATION_URI = "SECURITY.md"


# SARIF only has three result levels; Strix's five severities collapse here.
# Original label survives in ``result.properties.strix.severity``.
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
}

# GitHub code-scanning reads ``rule.properties['security-severity']`` (a
# 0.0-10.0 string) to rank alerts. We prefer CVSS from the finding; absent
# that we fall back to a conservative label -> score map.
_SEVERITY_TO_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
    "informational": "1.0",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_sarif_report(
    vulnerability_reports: list[dict[str, Any]],
    *,
    tool_version: str | None = None,
    repository_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a SARIF 2.1.0 document for findings.

    ``repository_context`` (optional) supplies VCS provenance for repo
    scans: ``repositoryUri``, ``repositoryFullName``, ``commitSha``,
    ``branch``, ``ref``. When present, the run carries
    ``versionControlProvenance`` + ``automationDetails`` so code-scanning
    can bind alerts to the scanned commit; it is omitted for URL / IP
    (DAST) targets that have no repository.

    Findings without safe source locations are anchored synthetically
    to SECURITY.md and flagged via ``properties.synthetic_location``.
    They're still emitted as proper SARIF results so they (a) flow
    through code-scanning normally rather than being shunted into a
    run-properties summary the UI can't render, and (b) carry the
    partialFingerprints + class hash so cross-run dismissal stickiness
    works for them.
    """
    rules_by_id: dict[str, dict[str, Any]] = {}
    rule_index_by_id: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    synthetic_location_count = 0
    dropped_unsafe_location_findings: list[dict[str, Any]] = []

    for report in vulnerability_reports:
        locations, is_synthetic, dropped_location_count = _build_locations(report)
        if is_synthetic:
            synthetic_location_count += 1

        if dropped_location_count:
            dropped_unsafe_location_findings.append(
                _dropped_location_summary(report, dropped_location_count)
            )

        rule_id = _rule_id(report)
        if rule_id not in rules_by_id:
            rule_index_by_id[rule_id] = len(rules_by_id)
            rules_by_id[rule_id] = _build_rule(rule_id, report)
        results.append(
            _build_result(
                rule_id,
                rule_index_by_id[rule_id],
                report,
                locations,
                is_synthetic=is_synthetic,
            )
        )

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

    run_properties: dict[str, Any] = {}
    if synthetic_location_count:
        # Surface the count for observability without duplicating the
        # findings themselves — they're already in `results[]` with
        # `properties.synthetic_location: true`. Having a top-level count
        # means CI logs / dashboards can bookkeep without parsing the
        # result list.
        run_properties["syntheticLocationCount"] = synthetic_location_count
    if dropped_unsafe_location_findings:
        run_properties["droppedUnsafeLocationCount"] = sum(
            finding["droppedLocationCount"] for finding in dropped_unsafe_location_findings
        )
        run_properties["droppedUnsafeLocationFindings"] = dropped_unsafe_location_findings
    if run_properties:
        run["properties"] = run_properties

    if repository_context:
        _apply_repository_context(run, repository_context)

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
    repository_context: dict[str, Any] | None = None,
) -> None:
    """Write a SARIF report to disk, creating parent directories first.

    Writes to a sibling temp file and atomically replaces the target, so a
    crash or serialization error mid-write can never leave a truncated
    ``findings.sarif`` for CI to upload in place of the last complete snapshot.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    sarif = build_sarif_report(
        vulnerability_reports,
        tool_version=tool_version,
        repository_context=repository_context,
    )
    tmp_path = output_path.with_name(f"{output_path.name}.{os.getpid()}.tmp")
    try:
        with tmp_path.open("w", encoding="utf-8") as sarif_file:
            json.dump(sarif, sarif_file, ensure_ascii=False, indent=2)
            sarif_file.write("\n")
        tmp_path.replace(output_path)  # atomic on the same filesystem
    finally:
        tmp_path.unlink(missing_ok=True)


def write_sarif(
    run_dir: Path,
    reports: list[dict[str, Any]],
    *,
    tool_version: str | None = None,
    repository_context: dict[str, Any] | None = None,
    filename: str = "findings.sarif",
) -> Path:
    """Write ``findings.sarif`` alongside existing outputs in ``run_dir``.

    Returns the output path. This is the ``ReportState`` entry point: SARIF
    writing must never break the CSV + markdown path, so the caller wraps
    it in try/except.
    """
    out = run_dir / filename
    write_sarif_report(
        out,
        reports,
        tool_version=tool_version,
        repository_context=repository_context,
    )
    logger.info(
        "Wrote SARIF 2.1.0 report: %s (%d results)",
        out,
        len(reports),
    )
    return out


# ``build_sarif_document`` is a convenience alias for callers that prefer a
# name mirroring ``write_sarif_report``.
def build_sarif_document(
    reports: list[dict[str, Any]],
    *,
    tool_version: str | None = None,
    repository_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return build_sarif_report(
        reports,
        tool_version=tool_version,
        repository_context=repository_context,
    )


# ---------------------------------------------------------------------------
# Repository provenance
# ---------------------------------------------------------------------------


def _apply_repository_context(run: dict[str, Any], context: dict[str, Any]) -> None:
    """Attach VCS provenance to a run for code-scanning alert binding.

    ``automationDetails.id`` categorises the run (``strix/<owner>/<repo>``)
    so multiple Strix runs against the same repo reconcile rather than pile
    up. ``versionControlProvenance`` records the exact repo + commit + branch
    the findings came from. Both are omitted when the corresponding context
    fields are absent (e.g. DAST-only scans).
    """
    full_name = _string_value(context.get("repositoryFullName"))
    uri = _string_value(context.get("repositoryUri"))
    commit = _string_value(context.get("commitSha"))
    branch = _string_value(context.get("branch"))
    ref = _string_value(context.get("ref"))

    if full_name:
        run["automationDetails"] = {"id": f"strix/{full_name}"}

    if uri:
        provenance: dict[str, Any] = {"repositoryUri": uri}
        if commit:
            provenance["revisionId"] = commit
        if branch:
            provenance["branch"] = branch
        run["versionControlProvenance"] = [provenance]

    properties = run.setdefault("properties", {})
    if full_name:
        properties["repository"] = full_name
    if ref:
        properties["ref"] = ref
    if commit:
        properties["commit_sha"] = commit
    if not properties:
        run.pop("properties", None)


# ---------------------------------------------------------------------------
# Rule + result builders
# ---------------------------------------------------------------------------


def _build_rule(rule_id: str, report: dict[str, Any]) -> dict[str, Any]:
    """Build a SARIF rule descriptor from a Strix finding."""
    title = _string_value(report.get("title")) or rule_id
    full_description = _string_value(report.get("description")) or title
    help_text = _help_text(report, full_description)

    rule: dict[str, Any] = {
        "id": rule_id,
        "name": _rule_name(rule_id, title),
        "shortDescription": {"text": title},
        "fullDescription": {"text": full_description},
        "defaultConfiguration": {"level": _sarif_level(report.get("severity"))},
        "help": {"text": help_text, "markdown": help_text},
    }

    properties: dict[str, Any] = {
        "security-severity": _security_severity(report),
    }
    tags = _rule_tags(rule_id, report)
    if tags:
        properties["tags"] = tags
    rule["properties"] = properties

    help_uri = _help_uri_for(rule_id)
    if help_uri:
        rule["helpUri"] = help_uri

    return rule


def _build_result(
    rule_id: str,
    rule_index: int,
    report: dict[str, Any],
    locations: list[dict[str, Any]],
    *,
    is_synthetic: bool = False,
) -> dict[str, Any]:
    """Build one SARIF result using validated locations.

    ``is_synthetic`` flags results whose location is the SECURITY.md
    anchor rather than a real code location — surfaces as
    ``properties.synthetic_location: true`` so reviewers and downstream
    tooling can distinguish anchored-locationless findings from
    source-linked ones.
    """
    title = _string_value(report.get("title")) or rule_id
    description = _string_value(report.get("description"))
    message_text = f"{title}\n\n{description}" if description else title

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": _sarif_level(report.get("severity")),
        "message": {"text": message_text},
    }
    if locations:
        result["locations"] = locations

    fixes = _build_fixes(report)
    if fixes:
        result["fixes"] = fixes

    # Code-scanning auto-resolution + dismissal-stickiness key on
    # partialFingerprints. Computed from the deterministic primitives
    # this report already carries (CWE, primary code location, route
    # tuple) — NOT from the LLM-authored title or message body, which
    # vary cosmetically across runs of the same finding.
    fp = _primary_fingerprint(rule_id, report, locations, is_synthetic=is_synthetic)
    if fp:
        result["partialFingerprints"] = {"primaryLocationLineHash": fp}
    # File-independent class fingerprint as a sibling property: lets
    # downstream tooling carry "won't fix" / "false positive"
    # determinations across file rename refactors where the primary
    # fingerprint legitimately shifts but the underlying class is
    # unchanged.
    class_fp = _class_fingerprint(rule_id, report)
    result["properties"] = _result_properties(report, class_fp, is_synthetic=is_synthetic)
    return result


def _result_properties(
    report: dict[str, Any],
    class_fingerprint: str | None = None,
    *,
    is_synthetic: bool = False,
) -> dict[str, Any]:
    """Strix-specific metadata for downstream consumers.

    The top-level ``security-severity`` matches GitHub code-scanning's
    expected property. Strix-specific fields are namespaced under
    ``strix`` so generic SARIF consumers don't see them by default.
    """
    properties: dict[str, Any] = {
        "security-severity": _security_severity(report),
    }
    if class_fingerprint:
        # Surfaced at top level so cross-rename dismissal tooling can
        # filter alerts by it without parsing the nested strix.* tree.
        properties["strix_vuln_class_hash"] = class_fingerprint
    if is_synthetic:
        # Top-level so reviewers + downstream automation can filter
        # synthetic-anchored alerts without parsing the nested strix.*
        # tree.
        properties["synthetic_location"] = True

    strix: dict[str, Any] = {}
    for key in (
        "id",
        "severity",
        "cvss",
        "timestamp",
        "target",
        "endpoint",
        "method",
        "cve",
        "cwe",
        "impact",
        "technical_analysis",
        "remediation_steps",
    ):
        value = report.get(key)
        if value not in (None, ""):
            strix[key] = value

    # SARIF is written for external upload (code-scanning / ASPM), so it must
    # NOT carry the weaponized exploit payload — that stays a local run
    # artifact (vulnerabilities.json / the finding MD). We surface the PoC
    # *description* (triage context) and a boolean flag that a script exists,
    # so consumers know to look at the local artifact, but never the script
    # body itself.
    poc_description = _string_value(report.get("poc_description"))
    poc_script = _string_value(report.get("poc_script_code"))
    if poc_description or poc_script:
        poc: dict[str, Any] = {}
        if poc_description:
            poc["description"] = poc_description
        if poc_script:
            poc["script_available"] = True
        strix["poc"] = poc

    if strix:
        properties["strix"] = strix

    return properties


def _build_fixes(report: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Build SARIF ``fixes`` from a finding's code-location fix pairs.

    Strix findings carry the suggested change inline on each code
    location as ``fix_before`` + ``fix_after``. We map every location
    that has both (and a safe repo-relative URI + start line) into a
    SARIF ``artifactChange``, replacing the finding's region with the
    fixed text. Returns None when no location carries a usable fix pair.
    """
    raw_locations = report.get("code_locations")
    if not isinstance(raw_locations, list):
        return None

    artifact_changes: list[dict[str, Any]] = []
    for location in raw_locations:
        if not isinstance(location, dict):
            continue
        file_path = _string_value(location.get("file"))
        fix_before = _string_value(location.get("fix_before"))
        fix_after = _string_value(location.get("fix_after"))
        start_line = location.get("start_line")
        if not (file_path and fix_before and fix_after):
            continue
        if type(start_line) is not int or start_line < 1:
            continue
        uri = _sarif_uri(file_path)
        if uri is None:
            continue

        deleted_region: dict[str, Any] = {"startLine": start_line}
        end_line = location.get("end_line")
        if type(end_line) is int and end_line >= start_line:
            deleted_region["endLine"] = end_line

        artifact_changes.append(
            {
                "artifactLocation": {"uri": uri},
                "replacements": [
                    {
                        "deletedRegion": deleted_region,
                        "insertedContent": {"text": fix_after},
                    }
                ],
            }
        )

    if not artifact_changes:
        return None

    fix: dict[str, Any] = {"artifactChanges": artifact_changes}
    remediation = _string_value(report.get("remediation_steps"))
    if remediation:
        fix["description"] = {"text": remediation, "markdown": remediation}
    return [fix]


# ---------------------------------------------------------------------------
# Location handling
# ---------------------------------------------------------------------------


def _synthetic_location() -> dict[str, Any]:
    """Synthetic anchor for findings with no safe code location.

    SARIF requires every result to carry at least one location, and
    code-scanning's UI handles locationless results unreliably.
    Anchoring to SECURITY.md gives the result a valid + visible
    location; the result's ``properties.synthetic_location: true``
    flag lets reviewers + tooling distinguish synthetic from real.
    """
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": _SYNTHETIC_LOCATION_URI},
        }
    }


def _build_locations(report: dict[str, Any]) -> tuple[list[dict[str, Any]], bool, int]:
    """Return ``(locations, is_synthetic, dropped_count)`` for a finding.

    Physical locations come from validated ``code_locations``. When none
    are safe, the result is anchored to SECURITY.md (``is_synthetic``).
    An ``endpoint`` (typical of DAST findings) is added as a
    ``logicalLocations`` entry; a locationless, endpoint-less finding
    gets a ``resource`` logical location carrying the target so the
    finding keeps a human-meaningful anchor.
    """
    physical, dropped_location_count = _build_physical_locations(report.get("code_locations"))
    is_synthetic = not physical
    locations: list[dict[str, Any]] = list(physical) if physical else [_synthetic_location()]

    endpoint = _string_value(report.get("endpoint"))
    if endpoint:
        locations.append(
            {"logicalLocations": [{"fullyQualifiedName": endpoint, "kind": "endpoint"}]}
        )
    elif is_synthetic:
        resource = _string_value(report.get("target")) or _string_value(report.get("title"))
        if resource:
            locations.append(
                {"logicalLocations": [{"fullyQualifiedName": resource, "kind": "resource"}]}
            )

    return locations, is_synthetic, dropped_location_count


def _build_physical_locations(raw_locations: Any) -> tuple[list[dict[str, Any]], int]:
    """Return SARIF physical locations and a count of dropped unsafe locations."""
    if not isinstance(raw_locations, list):
        return [], 0

    locations: list[dict[str, Any]] = []
    dropped_location_count = 0
    for location in raw_locations:
        if not isinstance(location, dict):
            dropped_location_count += 1
            continue

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

        physical_location: dict[str, Any] = {
            "artifactLocation": {"uri": uri},
            "region": region,
        }
        entry: dict[str, Any] = {"physicalLocation": physical_location}

        label = _string_value(location.get("label"))
        if label:
            entry["message"] = {"text": label}

        locations.append(entry)

    return locations, dropped_location_count


def _sarif_uri(file_path: str) -> str | None:
    """Return a safe repo-relative SARIF URI, or None for unsafe paths."""
    uri = PurePosixPath(file_path.replace("\\", "/")).as_posix()
    parts = PurePosixPath(uri).parts
    if not uri or uri.startswith("/") or not parts:
        return None
    if ":" in parts[0] or any(part == ".." for part in parts):
        return None
    return uri


# ---------------------------------------------------------------------------
# Rule ID resolution + CWE normalisation
# ---------------------------------------------------------------------------


def _rule_id(report: dict[str, Any]) -> str:
    """Choose a stable SARIF rule id, preferring CWE → CVE → finding-id → slug.

    CWE values are normalised from Strix output variants (``CWE-306``,
    ``cwe: 306``, ``306``) to the canonical ``CWE-NNN`` form. Without
    normalisation, the same weakness across runs dedups to separate rules.
    """
    cwe = _string_value(report.get("cwe"))
    if cwe:
        normalised = _normalise_cwe(cwe)
        if normalised:
            return normalised

    cve = _string_value(report.get("cve"))
    if cve:
        return cve

    finding_id = _string_value(report.get("id"))
    if finding_id:
        return finding_id

    title = _string_value(report.get("title")) or "strix-finding"
    return _slugify(title)


def _normalise_cwe(value: str) -> str | None:
    """``CWE-306``, ``cwe:306``, ``306`` → ``CWE-306``."""
    digits = "".join(c for c in value if c.isdigit())
    if not digits:
        return None
    return f"CWE-{digits}"


# Vulnerability-class keywords for the file-independent class
# fingerprint. Order matters — first match wins, so precise terms
# come before fuzzy ones (e.g. "broken access control" before
# "access control"). Keep this list closed and curated; a future
# maintainer adding sloppy entries could collapse distinct findings
# to the same class hash.
_VULN_CLASS_KEYWORDS = (
    "missing authentication",
    "missing authorization",
    "broken access control",
    "incorrect authorization",
    "default credentials",
    "hardcoded credentials",
    "hardcoded secret",
    "hardcoded password",
    "default admin",
    "default password",
    "session fixation",
    "open redirect",
    "path traversal",
    "directory traversal",
    "command injection",
    "sql injection",
    "code injection",
    "template injection",
    "xpath injection",
    "ldap injection",
    "log injection",
    "header injection",
    "csv injection",
    "prompt injection",
    "deserialization",
    "ssrf",
    "xss",
    "csrf",
    "xxe",
    "race condition",
    "toctou",
    "information disclosure",
    "insecure direct object reference",
    "idor",
    "bola",
    "bfla",
    "cross-tenant",
    "cross-project",
    "tenant bypass",
    "auth bypass",
    "rate limiting",
    "rate limit",
    "weak cryptography",
    "weak hash",
    "weak random",
    "insecure random",
    "tls verification",
    "certificate verification",
    "denial of service",
    "regex denial of service",
    "redos",
    "supply chain",
)


def _primary_fingerprint(
    rule_id: str,
    report: dict[str, Any],
    locations: list[dict[str, Any]],
    *,
    is_synthetic: bool = False,
) -> str | None:
    """Deterministic per-finding fingerprint for SARIF auto-resolution.

    Computed from primitives that don't depend on LLM prose stability:

      - rule_id (already CWE-normalised by ``_rule_id``)
      - first SARIF location's URI + startLine — these come from
        Strix's ``code_locations[].file`` and ``start_line`` which
        are sourced from the actual finding evidence, not synthesized
      - HTTP method + endpoint when present (BOLA/IDOR/missing-authz
        findings carry these explicitly in the report dict)

    Synthetic-anchored findings (``is_synthetic=True``) all share
    uri="SECURITY.md" and have no real start_line. Hashing by
    (rule_id, "SECURITY.md") alone would collapse every locationless
    finding of the same CWE into a single alert. To distinguish them,
    the synthetic path adds the class keyword extracted from the title
    (same logic ``_class_fingerprint`` uses). The class keyword
    catalogue is closed and stable, so cross-run identity holds — same
    vulnerability class on the same rule_id always lands on the same
    hash, and two different classes on the same rule_id don't collide.

    Returns None when no anchor is available AND not synthetic.
    """
    primary_physical = _first_physical_location(locations)
    uri = ""
    start_line: int | None = None
    if primary_physical:
        uri = (primary_physical.get("artifactLocation") or {}).get("uri", "") or ""
        region = primary_physical.get("region") or {}
        sl = region.get("startLine")
        if isinstance(sl, int) and sl >= 1:
            start_line = sl

    method = _string_value(report.get("method")) or ""
    endpoint = _string_value(report.get("endpoint")) or ""
    route = f"{method.upper()} {endpoint}".strip() if (method or endpoint) else ""

    if not uri and not route:
        return None

    parts = [f"rule:{rule_id}"]
    if uri:
        parts.append(f"uri:{uri}")
        if start_line is not None:
            # startLine in fingerprint is debatable: line shifts in
            # surrounding code re-fingerprint. The alternative — drop
            # line — collides multiple findings per file. We include
            # line because Strix code_locations carry the SINK line,
            # which moves only when the vulnerable code itself moves;
            # lines surfacing from cosmetic edits in unrelated parts
            # of the file don't shift it.
            parts.append(f"line:{start_line}")
    if route:
        parts.append(f"route:{route}")

    if is_synthetic:
        # Augment with class keyword so locationless findings of
        # different vuln classes don't collide. rule_id is already in
        # the composite so we don't also need to stamp the CWE.
        title = _string_value(report.get("title")) or ""
        if title:
            parts.append(f"synth_class:{_class_keyword(title)}")

    composite = "|".join(parts)
    return hashlib.sha256(composite.encode("utf-8")).hexdigest()


def _first_physical_location(locations: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Return the first location's physicalLocation payload, if any."""
    for location in locations:
        physical = location.get("physicalLocation")
        if physical:
            return cast("dict[str, Any]", physical)
    return None


def _class_fingerprint(rule_id: str, report: dict[str, Any]) -> str | None:
    """File-independent fingerprint for cross-rename dismissal carryover.

    Lets downstream tooling apply prior dismissal determinations to a
    new alert that has the same vulnerability class but a different
    primary fingerprint (typical case: file rename, or a fix that moves
    the vulnerable code to a new module).

    Composite of (rule_id, vuln-class keyword extracted from title).
    Title is LLM-authored so it's stochastic at the prose level, but
    the class keyword extraction picks up the discrete vulnerability
    category, which is much more stable than the full title.

    Falls back to the first 5 lowercased words of the title when no
    curated keyword matches. Acceptable as a fallback because the
    class fingerprint is a tiebreaker, not a primary reconciliation key.
    """
    title = _string_value(report.get("title")) or ""
    keyword = _class_keyword(title) if title else ""
    if not keyword:
        return None
    composite = f"rule:{rule_id}|class:{keyword}"
    return hashlib.sha256(composite.encode("utf-8")).hexdigest()


def _class_keyword(title: str) -> str:
    """Pick the first matching curated keyword in ``title``, or fall
    back to the first 5 lowercased alpha-numeric words.

    Shared between ``_class_fingerprint`` (file-rename carryover) and
    ``_primary_fingerprint`` (synthetic-location distinguisher) so the
    two fingerprints stay aligned on what counts as "the same class".
    Returns empty string when title is empty or whitespace-only.
    """
    if not title:
        return ""
    lower = title.lower()
    for kw in _VULN_CLASS_KEYWORDS:
        if kw in lower:
            return kw
    words = re.findall(r"[a-z0-9]+", lower)[:5]
    return " ".join(words)


def _rule_name(rule_id: str, title: str) -> str:
    """SARIF rule.name must be a free-form string; prefer the finding title
    where available, fall back to a snake_case'd form of the rule id."""
    return title or rule_id.replace("-", "_")


def _rule_tags(rule_id: str, report: dict[str, Any]) -> list[str]:
    tags: list[str] = ["security"]
    if rule_id.startswith("CWE-"):
        tags.append(rule_id)
    cve = _string_value(report.get("cve"))
    if cve and cve not in tags:
        tags.append(cve)
    return tags


def _help_uri_for(rule_id: str) -> str | None:
    if rule_id.startswith("CWE-"):
        return f"https://cwe.mitre.org/data/definitions/{rule_id.removeprefix('CWE-')}.html"
    return None


# ---------------------------------------------------------------------------
# Severity + help text
# ---------------------------------------------------------------------------


def _sarif_level(severity: Any) -> str:
    """Map Strix severity labels to SARIF result levels."""
    normalised = (_string_value(severity) or "").lower()
    return _SEVERITY_TO_LEVEL.get(normalised, "note")


def _security_severity(report: dict[str, Any]) -> str:
    """GitHub-compatible ``security-severity`` string in 0.0-10.0.

    Uses CVSS when present, otherwise falls back to the severity label.
    """
    cvss = report.get("cvss")
    if cvss is not None:
        try:
            return f"{float(cvss):.1f}"
        except (TypeError, ValueError):
            pass
    normalised = (_string_value(report.get("severity")) or "info").lower()
    return _SEVERITY_TO_SCORE.get(normalised, "1.0")


def _help_text(report: dict[str, Any], fallback: str) -> str:
    """Assemble SARIF help text from finding details and remediation."""
    sections = [
        _string_value(report.get("description")),
        _string_value(report.get("impact")),
        _string_value(report.get("remediation_steps")),
    ]
    help_text = "\n\n".join(section for section in sections if section)
    return help_text or fallback


# ---------------------------------------------------------------------------
# Summaries for unsafe-location findings
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


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
