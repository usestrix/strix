"""``create_vulnerability_report`` — file a vuln finding with dedup + CVSS."""

from __future__ import annotations

import json
import logging
import re
from pathlib import PurePosixPath
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


_CVSS_VALID = {
    "attack_vector": ["N", "A", "L", "P"],
    "attack_complexity": ["L", "H"],
    "privileges_required": ["N", "L", "H"],
    "user_interaction": ["N", "R"],
    "scope": ["U", "C"],
    "confidentiality": ["N", "L", "H"],
    "integrity": ["N", "L", "H"],
    "availability": ["N", "L", "H"],
}


_CODE_LOCATION_FIELDS = (
    "file",
    "start_line",
    "end_line",
    "snippet",
    "label",
    "fix_before",
    "fix_after",
)


def _validate_file_path(path: str) -> str | None:
    if not path or not path.strip():
        return "file path cannot be empty"
    p = PurePosixPath(path)
    if p.is_absolute():
        return f"file path must be relative, got absolute: '{path}'"
    if ".." in p.parts:
        return f"file path must not contain '..': '{path}'"
    return None


def _normalize_code_locations(
    raw: list[dict[str, Any]] | None,
) -> list[dict[str, Any]] | None:
    if not raw:
        return None
    cleaned: list[dict[str, Any]] = []
    for loc in raw:
        normalized: dict[str, Any] = {}
        for field in _CODE_LOCATION_FIELDS:
            if field not in loc or loc[field] is None:
                continue
            value = loc[field]
            if field in ("start_line", "end_line"):
                try:
                    normalized[field] = int(value)
                except (TypeError, ValueError):
                    continue
            else:
                text = (
                    str(value).strip("\n")
                    if field in ("snippet", "fix_before", "fix_after")
                    else str(value).strip()
                )
                if text:
                    normalized[field] = text
        if normalized.get("file") and normalized.get("start_line") is not None:
            cleaned.append(normalized)
    return cleaned or None


def _validate_code_locations(locations: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for i, loc in enumerate(locations):
        path_err = _validate_file_path(loc.get("file", ""))
        if path_err:
            errors.append(f"code_locations[{i}]: {path_err}")
        start = loc.get("start_line")
        if not isinstance(start, int) or start < 1:
            errors.append(f"code_locations[{i}]: start_line must be a positive integer")
        end = loc.get("end_line")
        if end is None:
            errors.append(f"code_locations[{i}]: end_line is required")
        elif not isinstance(end, int) or end < 1:
            errors.append(f"code_locations[{i}]: end_line must be a positive integer")
        elif isinstance(start, int) and end < start:
            errors.append(f"code_locations[{i}]: end_line ({end}) must be >= start_line ({start})")
    return errors


def _extract_cve(cve: str) -> str:
    match = re.search(r"CVE-\d{4}-\d{4,}", cve)
    return match.group(0) if match else cve.strip()


def _validate_cve(cve: str) -> str | None:
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        return f"invalid CVE format: '{cve}' (expected 'CVE-YYYY-NNNNN')"
    return None


def _extract_cwe(cwe: str) -> str:
    match = re.search(r"CWE-\d+", cwe)
    return match.group(0) if match else cwe.strip()


def _validate_cwe(cwe: str) -> str | None:
    if not re.match(r"^CWE-\d+$", cwe):
        return f"invalid CWE format: '{cwe}' (expected 'CWE-NNN')"
    return None


def _calculate_cvss(breakdown: dict[str, str]) -> tuple[float, str, str]:
    try:
        from cvss import CVSS3

        vector = (
            f"CVSS:3.1/AV:{breakdown['attack_vector']}/AC:{breakdown['attack_complexity']}/"
            f"PR:{breakdown['privileges_required']}/UI:{breakdown['user_interaction']}/"
            f"S:{breakdown['scope']}/C:{breakdown['confidentiality']}/"
            f"I:{breakdown['integrity']}/A:{breakdown['availability']}"
        )
        c = CVSS3(vector)
        score = c.scores()[0]
        severity = c.severities()[0].lower()
    except Exception:
        logger.exception("Failed to calculate CVSS")
        return 7.5, "high", ""
    else:
        return score, severity, vector


_REQUIRED_FIELDS = {
    "title": "Title cannot be empty",
    "description": "Description cannot be empty",
    "impact": "Impact cannot be empty",
    "target": "Target cannot be empty",
    "technical_analysis": "Technical analysis cannot be empty",
    "poc_description": "PoC description cannot be empty",
    "poc_script_code": "PoC script/code is REQUIRED - provide the actual exploit/payload",
    "remediation_steps": "Remediation steps cannot be empty",
    "evidence": "Evidence cannot be empty - provide concrete proof of the finding",
    "assumptions": "Assumptions cannot be empty - state exploitability prerequisites",
}

_VALID_FIX_EFFORT = frozenset({"trivial", "low", "medium", "high"})


async def _do_create(  # noqa: PLR0912
    *,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    evidence: str,
    assumptions: str,
    fix_effort: str,
    cvss_breakdown: dict[str, str],
    endpoint: str | None,
    method: str | None,
    cve: str | None,
    cwe: str | None,
    code_locations: list[dict[str, Any]] | None,
    fix_pr_body: str | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    fields = {
        "title": title,
        "description": description,
        "impact": impact,
        "target": target,
        "technical_analysis": technical_analysis,
        "poc_description": poc_description,
        "poc_script_code": poc_script_code,
        "remediation_steps": remediation_steps,
        "evidence": evidence,
        "assumptions": assumptions,
    }
    for name, msg in _REQUIRED_FIELDS.items():
        if not str(fields.get(name) or "").strip():
            errors.append(msg)

    fix_effort = (fix_effort or "").strip().lower()
    if fix_effort not in _VALID_FIX_EFFORT:
        errors.append(
            f"Invalid fix_effort: {fix_effort!r}. Must be one of: {sorted(_VALID_FIX_EFFORT)}"
        )

    if not isinstance(cvss_breakdown, dict) or not cvss_breakdown:
        errors.append("cvss_breakdown: must be an object with the 8 CVSS metrics")
        cvss_breakdown = {}
    else:
        for name, valid in _CVSS_VALID.items():
            value = cvss_breakdown.get(name)
            if value not in valid:
                errors.append(f"Invalid {name}: {value}. Must be one of: {valid}")

    parsed_locations = _normalize_code_locations(code_locations)
    if parsed_locations:
        errors.extend(_validate_code_locations(parsed_locations))
    if cve:
        cve = _extract_cve(cve)
        cve_err = _validate_cve(cve)
        if cve_err:
            errors.append(cve_err)
    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            errors.append(cwe_err)

    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    cvss_score, severity, _vector = _calculate_cvss(cvss_breakdown)

    try:
        from strix.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            logger.warning("No global report state; vulnerability report not persisted")
            return {
                "success": True,
                "message": f"Vulnerability report '{title}' created (not persisted)",
                "warning": "Report could not be persisted - report state unavailable",
            }

        from strix.report.dedupe import check_duplicate

        existing = report_state.get_existing_vulnerabilities()
        candidate = {
            "title": title,
            "description": description,
            "impact": impact,
            "target": target,
            "technical_analysis": technical_analysis,
            "poc_description": poc_description,
            "poc_script_code": poc_script_code,
            "endpoint": endpoint,
            "method": method,
        }
        dedupe = await check_duplicate(candidate, existing)
        if dedupe.get("is_duplicate"):
            duplicate_id = dedupe.get("duplicate_id", "")
            duplicate_title = next(
                (r.get("title", "Unknown") for r in existing if r.get("id") == duplicate_id),
                "",
            )
            return {
                "success": False,
                "error": (
                    f"Potential duplicate of '{duplicate_title}' "
                    f"(id={duplicate_id[:8]}...) — do not re-report the same vulnerability"
                ),
                "duplicate_of": duplicate_id,
                "duplicate_title": duplicate_title,
                "confidence": dedupe.get("confidence", 0.0),
                "reason": dedupe.get("reason", ""),
            }

        report_id = report_state.add_vulnerability_report(
            title=title,
            description=description,
            severity=severity,
            impact=impact,
            target=target,
            technical_analysis=technical_analysis,
            poc_description=poc_description,
            poc_script_code=poc_script_code,
            remediation_steps=remediation_steps,
            evidence=evidence,
            assumptions=assumptions,
            fix_effort=fix_effort,
            cvss=cvss_score,
            cvss_breakdown=cvss_breakdown,
            endpoint=endpoint,
            method=method,
            cve=cve,
            cwe=cwe,
            code_locations=parsed_locations,
            fix_pr_body=fix_pr_body,
            agent_id=agent_id if isinstance(agent_id, str) else None,
            agent_name=agent_name if isinstance(agent_name, str) else None,
        )
    except (ImportError, AttributeError) as e:
        logger.exception("create_vulnerability_report persistence failed")
        return {"success": False, "error": f"Failed to create vulnerability report: {e!s}"}
    else:
        logger.info(
            "Vulnerability report created: id=%s severity=%s cvss=%.1f title=%s",
            report_id,
            severity,
            cvss_score,
            title,
        )
        return {
            "success": True,
            "message": f"Vulnerability report '{title}' created successfully",
            "report_id": report_id,
            "severity": severity,
            "cvss_score": cvss_score,
        }


@function_tool(timeout=180, strict_mode=False)
async def create_vulnerability_report(
    ctx: RunContextWrapper,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    evidence: str,
    assumptions: str,
    fix_effort: str,
    cvss_breakdown: dict[str, str],
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    fix_pr_body: str | None = None,
) -> str:
    """File a vulnerability report — one report per fully-verified finding.

    **When to file**: you have a concrete vulnerability with a working
    proof-of-concept and you're 100% sure it's a real issue.

    **When NOT to file**:

    - General security observations without a specific vulnerability.
    - Suspicions you haven't confirmed with a PoC.
    - Tracking multiple vulnerabilities at once — one report per vuln.
    - Re-reporting something you (or another agent) already filed.
    - Known-CVE dependency / supply-chain findings that can't be
      dynamically PoC'd — a vulnerable dependency version pinned in a
      lockfile/manifest that matches a published advisory. File those
      with ``create_dependency_report`` instead, never with this tool.

    Automatic LLM-based **deduplication** rejects reports that describe
    the same root cause on the same asset as an existing report. If you
    get a ``duplicate_of`` response, do NOT retry — move on to other
    areas.

    **Report output rules** (this content may be rendered into generated
    reports):

    - No internal/system details: never mention paths like
      ``/workspace``, internal tools, agents, sandboxes, models, system
      prompts, internal errors / stack traces, or tester environment.
      Never leak internal identifiers (proxy request IDs, internal
      report IDs) into any field.
    - Tone: formal, objective, third-person, vendor-neutral, concise.
      Avoid internal-guidance headings like "QUICK", "Approach", or
      "Techniques" that read like an engineering runbook rather than a
      client deliverable.
    - **Use markdown in every text field**: ``**bold**`` for emphasis,
      ``inline code`` for identifiers/values/parameters, and fenced
      code blocks (```` ```language ````) for any code/payload/HTTP
      excerpt. Never leave code bare/unformatted. When referencing a
      file, annotate the fence, e.g.
      ```` ```python title=app.py startLineNumber=42 endLineNumber=50 ````.
    - Field discipline: ``poc_description`` is steps only — NO code (all
      code goes in ``poc_script_code``); ``remediation_steps`` is prose
      only — NO code/diffs (code fixes go in ``code_locations``).
    - Numbered steps allowed only in PoC and Remediation sections.
    - Avoid hedging language; be precise and non-vague.
    - Follow a standard pentest report structure across the fields:
      (1) overview (``description``), (2) severity & CVSS vector
      (``cvss_breakdown``), (3) affected asset(s) (``target`` /
      ``endpoint``), (4) technical details (``technical_analysis``),
      (5) proof of concept (``poc_description`` + ``poc_script_code``),
      (6) impact (``impact``), (7) evidence (``evidence``), and
      (8) remediation (``remediation_steps``).

    **White-box requirement**: when source is available, you MUST
    populate ``code_locations``. See the ``code_locations`` arg below
    for the full rules around ``fix_before`` / ``fix_after``,
    multi-part fixes, and informational-vs-actionable entries.

    **CVSS breakdown** is an object with all 8 metrics (each a single
    uppercase letter):

    - ``attack_vector``: ``N`` (Network), ``A`` (Adjacent), ``L``
      (Local), ``P`` (Physical)
    - ``attack_complexity``: ``L`` / ``H``
    - ``privileges_required``: ``N`` / ``L`` / ``H``
    - ``user_interaction``: ``N`` / ``R``
    - ``scope``: ``U`` (Unchanged) / ``C`` (Changed)
    - ``confidentiality`` / ``integrity`` / ``availability``: ``N`` /
      ``L`` / ``H``

    Example::

        {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H"
        }

    **CVE / CWE rules**: pass the bare ID only (``CVE-2024-1234``,
    ``CWE-89``) — no name, no parenthetical. Be 100% certain; if
    unsure, use ``web_search`` to verify the ID before passing, or omit
    the field entirely. Always prefer the most specific child CWE over
    a broad parent (CWE-89 not CWE-74; CWE-78 not CWE-77). Do NOT use
    broad/parent CWEs like CWE-74, CWE-20, CWE-200, CWE-284, or
    CWE-693.

    Common CWE references (use the ID only — names are listed here
    just for your lookup):

    - **Injection**: CWE-79 XSS, CWE-89 SQLi, CWE-78 OS Command
      Injection, CWE-94 Code Injection, CWE-77 Command Injection.
    - **Auth / Access**: CWE-287 Improper Authentication, CWE-862
      Missing Authorization, CWE-863 Incorrect Authorization, CWE-306
      Missing Auth for Critical Function, CWE-639 Authz Bypass via
      User-Controlled Key.
    - **Web**: CWE-352 CSRF, CWE-918 SSRF, CWE-601 Open Redirect,
      CWE-434 Unrestricted File Upload.
    - **Memory**: CWE-787 OOB Write, CWE-125 OOB Read, CWE-416 UAF,
      CWE-120 Classic Buffer Overflow.
    - **Data**: CWE-502 Deserialization of Untrusted Data, CWE-22
      Path Traversal, CWE-611 XXE.
    - **Crypto / Config**: CWE-798 Hard-coded Credentials, CWE-327
      Broken / Risky Crypto, CWE-311 Missing Encryption, CWE-916 Weak
      Password Hashing.

    Args:
        title: Specific finding title (e.g.
            ``"SQL Injection in /api/users login parameter"``). Don't
            include the CVE number in the title.
        description: Concise, non-technical TL;DR of the vulnerability
            (1-3 sentences) — it appears first in the report. Deep
            technical detail and root-cause analysis belong in
            ``technical_analysis``, not here.
        impact: What an attacker achieves; business risk; data at risk.
        target: Affected URL / domain / repository.
        technical_analysis: The mechanism and root cause.
        poc_description: Step-by-step reproduction (steps only, no code).
        poc_script_code: Working PoC (Python preferred).
        remediation_steps: Specific, actionable fix (prose, no code).
        evidence: Concrete proof the issue is real and exploitable —
            request/response excerpts, observed behavior, tool output.
            Use fenced code blocks; no internal identifiers/paths.
        assumptions: Short note on the assumptions/prerequisites that
            make this finding impactful or exploitable (e.g. "assumes an
            authenticated low-privilege user").
        fix_effort: One of ``trivial`` / ``low`` / ``medium`` / ``high``.
        cvss_breakdown: 8-metric object per the format above.
        endpoint: API path / Git path (e.g. ``/api/login``).
        method: HTTP method when relevant.
        cve: ``CVE-YYYY-NNNNN`` if certain, else omit.
        cwe: ``CWE-NNN`` (most specific child) if certain, else omit.
        code_locations: White-box findings — list of location objects.

            **How ``fix_before`` / ``fix_after`` work**: they're used as
            literal GitHub/GitLab PR suggestion blocks. When a reviewer
            accepts the suggestion, the platform replaces the **exact
            lines from ``start_line`` to ``end_line``** with
            ``fix_after``. Therefore:

            1. ``fix_before`` must be a **VERBATIM** copy of the source
               at those lines — same whitespace, indentation, line
               breaks. If it doesn't match character-for-character, the
               suggestion will corrupt the code when accepted.
            2. ``fix_after`` is the COMPLETE replacement for that
               entire block (may be more or fewer lines).
            3. ``start_line`` / ``end_line`` must precisely cover the
               lines in ``fix_before`` — no more, no less.

            **Multi-part fixes**: many fixes touch multiple
            non-contiguous parts of a file (e.g. add an import at the
            top AND change code lower down). Since each
            ``fix_before`` / ``fix_after`` pair covers ONE contiguous
            block, create **separate location entries** for each
            non-contiguous part. Use ``label`` to describe each part's
            role (``"Add escape helper import"``, ``"Sanitize input
            before SQL"``). Order primary fix first, supporting
            changes (imports, config) after.

            **Informational vs actionable**:
            - With ``fix_before`` / ``fix_after``: actionable fix
              (renders as a PR suggestion block).
            - Without them: informational context (e.g. showing the
              source of tainted data, or a sink that doesn't need
              direct editing).

            **Per-location fields**:
            - ``file`` (REQUIRED): path **relative** to repo root. No
              leading slash, no ``..``, no ``/workspace/`` prefix.
              Right: ``"src/db/queries.ts"``. Wrong:
              ``"/workspace/repo/src/db/queries.ts"``, ``"./src/x.py"``,
              ``"../../etc/passwd"``.
            - ``start_line`` (REQUIRED): 1-based; positive integer.
              Verify against the actual file — do NOT guess.
            - ``end_line`` (REQUIRED): 1-based; ``>= start_line``.
              Only equal to ``start_line`` when the block truly is one
              line.
            - ``snippet`` (optional): verbatim source at this range.
            - ``label`` (optional): short role description; especially
              important for multi-part fixes.
            - ``fix_before`` (optional): verbatim copy of the
              vulnerable code, lines ``start_line``-``end_line``.
            - ``fix_after`` (optional): complete replacement for that
              block; syntactically valid.

            **Common mistakes to avoid**:
            - Guessing line numbers instead of reading the file.
            - Paraphrasing / reformatting code in ``fix_before``.
            - Setting ``start_line == end_line`` when the vulnerable
              code spans multiple lines.
            - Bundling an import addition and a far-away code change
              into one location — split them.
            - Padding ``fix_before`` with surrounding context lines
              that aren't part of the fix.
            - Duplicating the same change across multiple locations.
        fix_pr_body: Optional. When source is available and you have a
            concrete fix, a markdown PR-description body proposing the
            fix (summary + rationale). Prose/markdown only — the code
            change itself belongs in ``code_locations``. Omit for
            black-box findings.

    Example (abbreviated — mirror this structure)::

        title: "Reflected XSS in /search q parameter"
        description:
            The **`q`** parameter of `/search` reflects user input into
            the HTML response without encoding, allowing script
            injection.
        technical_analysis:
            The handler interpolates `q` directly into the page body:

            ```python title=views.py startLineNumber=42 endLineNumber=44
            html = f"<h2>Results for {q}</h2>"
            return HttpResponse(html)
            ```

            No output encoding is applied, so `<script>` executes.
        poc_description:
            1. Navigate to `/search?q=<payload>`.
            2. Observe the payload executes in the victim's browser.
        poc_script_code:
            ```
            GET /search?q=<script>alert(document.domain)</script>
            ```
        evidence:
            Response echoes the payload verbatim:

            ```html
            <h2>Results for <script>alert(document.domain)</script></h2>
            ```
        assumptions:
            Assumes a victim can be induced to open a crafted link.
        remediation_steps:
            Context-encode all user input rendered into HTML; prefer the
            template engine's auto-escaping over string interpolation.
        fix_effort: "low"
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    agent_name = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw_agent_name = names.get(agent_id)
            agent_name = raw_agent_name if isinstance(raw_agent_name, str) else None

    result = await _do_create(
        title=title,
        description=description,
        impact=impact,
        target=target,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
        evidence=evidence,
        assumptions=assumptions,
        fix_effort=fix_effort,
        cvss_breakdown=cvss_breakdown,
        endpoint=endpoint,
        method=method,
        cve=cve,
        cwe=cwe,
        code_locations=code_locations,
        fix_pr_body=fix_pr_body,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


_DEP_SEVERITY_FROM_CVSS = {
    (9.0, 10.0): "critical",
    (7.0, 9.0): "high",
    (4.0, 7.0): "medium",
    (0.0, 4.0): "low",
}


def _dependency_severity(advisory_cvss: float | None) -> tuple[float, str]:
    if advisory_cvss is None:
        return 0.0, "info"
    score = max(0.0, min(10.0, advisory_cvss))
    for (lo, hi), label in _DEP_SEVERITY_FROM_CVSS.items():
        if lo <= score < hi or (hi == 10.0 and score == 10.0):
            return score, label
    return score, "none"


def _build_dependency_metadata(
    *,
    package_name: str,
    installed_version: str,
    package_ecosystem: str | None,
    fixed_version: str | None,
) -> dict[str, str]:
    metadata = {
        "package_name": package_name.strip(),
        "installed_version": installed_version.strip(),
    }
    if package_ecosystem and package_ecosystem.strip():
        metadata["package_ecosystem"] = package_ecosystem.strip()
    if fixed_version and fixed_version.strip():
        metadata["fixed_version"] = fixed_version.strip()
    return metadata


def _build_dependency_evidence(
    *,
    cve: str,
    package_name: str,
    installed_version: str,
    fixed_version: str | None,
) -> str:
    evidence = (
        f"**Advisory evidence:** `{cve}` applies to `{package_name}` "
        f"at installed version `{installed_version}`."
    )
    if fixed_version and fixed_version.strip():
        evidence += f" The advisory is fixed in `{fixed_version.strip()}`."
    return evidence


async def _do_create_dependency(  # noqa: PLR0912
    *,
    title: str,
    description: str,
    target: str,
    cve: str,
    package_name: str,
    installed_version: str,
    impact: str,
    remediation_steps: str,
    assumptions: str,
    package_ecosystem: str | None,
    fixed_version: str | None,
    cwe: str | None,
    advisory_cvss: float | None,
    technical_analysis: str | None,
    fix_effort: str,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    required = {
        "title": title,
        "description": description,
        "target": target,
        "package_name": package_name,
        "installed_version": installed_version,
        "package_ecosystem": package_ecosystem,
        "impact": impact,
        "remediation_steps": remediation_steps,
        "assumptions": assumptions,
    }
    for name, value in required.items():
        if not str(value or "").strip():
            errors.append(f"{name} cannot be empty")

    parsed_cve = _extract_cve(cve or "")
    cve_err = _validate_cve(parsed_cve)
    if cve_err:
        errors.append(cve_err)

    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            errors.append(cwe_err)

    fix_effort = (fix_effort or "").strip().lower()
    if fix_effort not in _VALID_FIX_EFFORT:
        errors.append(
            f"Invalid fix_effort: {fix_effort!r}. Must be one of: {sorted(_VALID_FIX_EFFORT)}"
        )

    if advisory_cvss is None:
        errors.append(
            "advisory_cvss is required: read the published advisory base score "
            "(0.0-10.0) off the advisory (trivy CVSS / NVD / GHSA). Severity is "
            "derived solely from it — do not omit it or the finding cannot be rated."
        )
    elif not 0.0 <= advisory_cvss <= 10.0:
        errors.append(f"advisory_cvss must be between 0.0 and 10.0, got {advisory_cvss}")

    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    cvss_score, severity = _dependency_severity(advisory_cvss)
    dependency_metadata = _build_dependency_metadata(
        package_name=package_name,
        installed_version=installed_version,
        package_ecosystem=package_ecosystem,
        fixed_version=fixed_version,
    )
    evidence = _build_dependency_evidence(
        cve=parsed_cve,
        package_name=package_name.strip(),
        installed_version=installed_version.strip(),
        fixed_version=fixed_version,
    )

    try:
        from strix.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            logger.warning("No global report state; dependency report not persisted")
            return {
                "success": True,
                "message": f"Dependency finding '{title}' created (not persisted)",
                "warning": "Report could not be persisted - report state unavailable",
            }

        from strix.report.dedupe import check_duplicate

        existing = report_state.get_existing_vulnerabilities()
        candidate = {
            "title": title,
            "description": description,
            "target": target,
            "cve": parsed_cve,
            "dependency_metadata": dependency_metadata,
            "technical_analysis": technical_analysis,
        }
        dedupe = await check_duplicate(candidate, existing)
        if dedupe.get("is_duplicate"):
            duplicate_id = dedupe.get("duplicate_id", "")
            return {
                "success": False,
                "error": (
                    f"Potential duplicate (id={duplicate_id[:8]}...) — "
                    "do not re-report the same dependency finding"
                ),
                "duplicate_of": duplicate_id,
                "confidence": dedupe.get("confidence", 0.0),
                "reason": dedupe.get("reason", ""),
            }

        report_id = report_state.add_vulnerability_report(
            title=title,
            description=description,
            severity=severity,
            impact=impact,
            target=target,
            technical_analysis=technical_analysis,
            remediation_steps=remediation_steps,
            evidence=evidence,
            assumptions=assumptions,
            fix_effort=fix_effort,
            cvss=cvss_score if advisory_cvss is not None else None,
            cve=parsed_cve,
            cwe=cwe,
            finding_class="dependency_cve",
            dependency_metadata=dependency_metadata,
            agent_id=agent_id if isinstance(agent_id, str) else None,
            agent_name=agent_name if isinstance(agent_name, str) else None,
        )
    except (ImportError, AttributeError) as e:
        logger.exception("create_dependency_report persistence failed")
        return {"success": False, "error": f"Failed to create dependency report: {e!s}"}
    else:
        logger.info(
            "Dependency report created: id=%s cve=%s package=%s severity=%s",
            report_id,
            parsed_cve,
            package_name,
            severity,
        )
        return {
            "success": True,
            "message": f"Dependency finding '{title}' created successfully",
            "report_id": report_id,
            "severity": severity,
            "cve": parsed_cve,
        }


@function_tool(timeout=180, strict_mode=False)
async def create_dependency_report(
    ctx: RunContextWrapper,
    title: str,
    description: str,
    target: str,
    cve: str,
    package_name: str,
    installed_version: str,
    advisory_cvss: float,
    impact: str,
    remediation_steps: str,
    assumptions: str,
    package_ecosystem: str,
    fixed_version: str | None = None,
    cwe: str | None = None,
    technical_analysis: str | None = None,
    fix_effort: str = "low",
) -> str:
    """File a known-CVE dependency (SCA) finding — one report per CVE x package.

    Use this instead of ``create_vulnerability_report`` when the finding
    is a **known-CVE supply-chain issue**: a vulnerable third-party
    package/version identified from a lockfile, manifest, or SBOM. Unlike
    a dynamic finding, you do NOT need to trigger the vulnerability with a
    live PoC — a verified advisory + the affected installed version is the
    evidence.

    **When to file**:

    - A dependency is pinned to a version covered by a published CVE.
    - You have verified the CVE ID and the installed version falls in the
      affected range (use ``web_search`` if unsure).

    **When NOT to file**:

    - Dynamically-proven vulnerabilities → use
      ``create_vulnerability_report`` (``finding_class`` dynamic).
    - Outdated-but-not-vulnerable dependencies with no CVE.
    - Re-reporting the same CVE/package already filed.

    **Reachability**: do NOT silently downgrade or suppress a finding
    because the vulnerable code path may be unreachable — instead state
    reachability as an ``assumptions`` / confidence factor. Report the
    finding; let the reader weigh exploitability.

    **Formatting**: use markdown in text fields (``**bold**``, ``inline
    code`` for package/version identifiers, fenced code blocks for
    manifest excerpts). No internal paths/tooling/agent references.

    Args:
        title: e.g. ``"CVE-2024-1234 in lodash 4.17.20 (prototype pollution)"``.
        description: What the CVE is and why the pinned version is affected.
        target: Affected repository / project / manifest.
        cve: ``CVE-YYYY-NNNNN`` — required and must be verified.
        package_name: Affected package name (e.g. ``lodash``).
        installed_version: The version currently pinned/installed.
        impact: What the CVE enables; business risk in this context.
        remediation_steps: How to fix (usually upgrade to a fixed version).
        assumptions: Exploitability/reachability assumptions & confidence.
        package_ecosystem: e.g. ``npm`` / ``pypi`` / ``maven`` / ``go``.
        fixed_version: First non-vulnerable version, if known.
        cwe: ``CWE-NNN`` (most specific) if certain, else omit.
        advisory_cvss: **Required.** Published advisory base score
            (0.0-10.0) — read it off the advisory (trivy CVSS / NVD / GHSA).
            Severity is derived solely from this score, so it must be the
            real published value; do not guess or omit it.
        technical_analysis: Optional deeper mechanism/root-cause detail.
        fix_effort: One of ``trivial`` / ``low`` / ``medium`` / ``high``
            (dependency upgrades are usually ``trivial``/``low``).
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    agent_name = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw_agent_name = names.get(agent_id)
            agent_name = raw_agent_name if isinstance(raw_agent_name, str) else None

    result = await _do_create_dependency(
        title=title,
        description=description,
        target=target,
        cve=cve,
        package_name=package_name,
        installed_version=installed_version,
        impact=impact,
        remediation_steps=remediation_steps,
        assumptions=assumptions,
        package_ecosystem=package_ecosystem,
        fixed_version=fixed_version,
        cwe=cwe,
        advisory_cvss=advisory_cvss,
        technical_analysis=technical_analysis,
        fix_effort=fix_effort,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)
