"""Reporting tools — file vuln findings (with dedup + CVSS) and read them back.

``create_vulnerability_report`` / ``create_dependency_report`` file findings;
``list_reports`` / ``get_report`` let any agent (notably the root orchestrator)
review what's been filed so far across the whole scan.
"""

from __future__ import annotations

import asyncio
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
    from cvss import CVSS3

    vector = (
        f"CVSS:3.1/AV:{breakdown['attack_vector']}/AC:{breakdown['attack_complexity']}/"
        f"PR:{breakdown['privileges_required']}/UI:{breakdown['user_interaction']}/"
        f"S:{breakdown['scope']}/C:{breakdown['confidentiality']}/"
        f"I:{breakdown['integrity']}/A:{breakdown['availability']}"
    )

    try:
        cvss = CVSS3(vector)
        score = cvss.scores()[0]
        base_severity = cvss.severities()[0].lower()
    except Exception as exc:
        msg = f"Failed to calculate CVSS for validated vector: {vector}"
        raise ValueError(msg) from exc

    severity = "info" if base_severity == "none" else base_severity
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

    try:
        cvss_score, severity, _vector = _calculate_cvss(cvss_breakdown)
    except ValueError as exc:
        return {"success": False, "error": "Validation failed", "errors": [str(exc)]}

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


def _caller_identity(ctx: RunContextWrapper) -> tuple[str | None, str | None]:
    """Return the (agent_id, agent_name) of the agent invoking this tool."""
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    agent_name: str | None = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw_agent_name = names.get(agent_id)
            agent_name = raw_agent_name if isinstance(raw_agent_name, str) else None
    return agent_id, agent_name


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

    **Reporting and severity gate**:

    - A reachable endpoint, unusual response, weak configuration, or
      reconnaissance artifact is not by itself a vulnerability. File a
      report only when the PoC demonstrates an unauthorized security
      consequence or a realistic, fully validated path to one.
    - Score only the reasonable final impact supported by the PoC. Do
      not score speculative pivots or consequences that require another
      unverified vulnerability.
    - Network reachability and missing authentication affect
      exploitability; neither creates Confidentiality, Integrity, or
      Availability impact by itself.
    - Public metadata, internal-looking names or addresses, software
      versions, intended client-side code, and source maps without
      secrets or restricted source normally have ``C:N``.
    - Configuration and transport observations require a realistic
      attacker-controlled exploit and direct security impact. Client
      errors, compatibility issues, fingerprinting, and attack-surface
      discovery alone should not be filed as vulnerabilities.
    - Before filing, verify that the impact narrative, PoC, and every
      non-None CVSS impact metric describe the same demonstrated
      consequence. When evidence is incomplete, lower the metric or
      continue validation; never choose a higher value "to be safe."

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

    Derive the vector from the demonstrated attack, not the finding
    category or a scanner/template severity:

    - ``C:L`` requires actual access to some restricted information.
      Reconnaissance value alone is ``C:N``. ``C:H`` requires total
      disclosure or limited disclosure with a direct serious impact,
      such as a usable administrator credential or private key.
    - ``I:L`` requires demonstrated unauthorized, limited modification;
      ``I:H`` requires total or directly serious modification. Otherwise
      use ``I:N``.
    - ``A:L`` requires demonstrated performance degradation or service
      interruption; ``A:H`` requires complete or directly serious
      denial of the affected service. Otherwise use ``A:N``.
    - Use ``S:C`` only when exploitation demonstrably crosses into a
      component governed by a different security authority. A separate
      backend, downstream effect, or third-party name is insufficient.

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

    **CVSS calibration** — score the weakness you actually proved, not a
    hypothetical worst case. Most over-rating comes from these mistakes:

    - **Don't presuppose a separate compromise.** If exploitation
      requires the attacker to already hold a victim secret (a stolen
      session cookie/token, a leaked one-time link, intercepted traffic),
      that acquisition is not free. Do not score it as
      ``privileges_required:N`` with ``attack_complexity:L`` as if
      directly reachable, and do not rate a replay-of-captured-secret
      issue High/Critical unless the *same* finding demonstrates a
      concrete way to obtain that secret. Issues like a session that
      survives logout or a replayable link are session-management /
      defense-in-depth weaknesses — usually Low/Medium on their own.
    - **Reserve ``H`` impact for demonstrated broad impact.** ``C:H`` /
      ``I:H`` require proof of wide or systemic read/write. A single
      user's data, a read-only information leak, or merely confirming
      that an account / domain / software version *exists* (enumeration)
      is ``C:L`` (often ``I:N``) — not ``C:H``.
    - **Model required position and interaction honestly.** An
      adversary-in-the-middle prerequisite (e.g. cleartext transmission)
      or a required victim action is not guaranteed — reflect it in
      ``attack_complexity`` / ``user_interaction`` instead of assuming the
      ideal condition always holds.

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
        impact: The unauthorized result demonstrated by the PoC, the
            affected data or operation, and its scope. Keep plausible
            but unverified follow-on risks separate; do not use them to
            set CVSS metrics.
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
    agent_id, agent_name = _caller_identity(ctx)

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


_VALID_REACHABILITY = frozenset(
    {
        "not_imported",
        "imported",
        "vulnerable_symbol_used",
        "reachable_call_path",
        "unknown",
    }
)


def _validate_manifest_path(manifest_path: str | None) -> str | None:
    """Return an error message when manifest_path is missing or unsafe."""
    path = (manifest_path or "").strip()
    if not path:
        return (
            "manifest_path is required: pass the repo-relative path of the "
            "lockfile/manifest where the vulnerable version was observed "
            "(trivy's Target, e.g. 'package-lock.json' or "
            "'services/api/pom.xml'). It binds the finding to its exact file "
            "so remediation can target the right repository."
        )
    if path.startswith("/") or "\\" in path or path.split("/")[0].endswith(":"):
        return f"manifest_path must be a relative path within the repository, got {path!r}"
    segments = path.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        return f"manifest_path must not contain empty, '.', or '..' segments, got {path!r}"
    return None


def _build_dependency_metadata(
    *,
    package_name: str,
    installed_version: str,
    package_ecosystem: str | None,
    fixed_version: str | None,
    introduced_by: str | None,
    dependency_path: str | None,
    manifest_path: str | None = None,
    reachability: str | None = None,
    reachability_evidence: str | None = None,
) -> dict[str, str]:
    metadata = {
        "package_name": package_name.strip(),
        "installed_version": installed_version.strip(),
    }
    if package_ecosystem and package_ecosystem.strip():
        metadata["package_ecosystem"] = package_ecosystem.strip()
    if manifest_path and manifest_path.strip():
        metadata["manifest_path"] = manifest_path.strip()
    if fixed_version and fixed_version.strip():
        metadata["fixed_version"] = fixed_version.strip()
    if introduced_by and introduced_by.strip():
        metadata["introduced_by"] = introduced_by.strip()
    if dependency_path and dependency_path.strip():
        metadata["dependency_path"] = dependency_path.strip()
    # "unknown" is the absent case — omitting it keeps the jsonb contract clean,
    # and evidence without a level would have nothing to qualify.
    if reachability and reachability.strip() and reachability.strip() != "unknown":
        metadata["reachability"] = reachability.strip()
        if reachability_evidence and reachability_evidence.strip():
            metadata["reachability_evidence"] = reachability_evidence.strip()
    return metadata


_REACHABILITY_EVIDENCE_LABELS = {
    "not_imported": "not imported by application code",
    "imported": "imported by application code; affected API usage unconfirmed",
    "vulnerable_symbol_used": "the advisory's affected API is used in application code",
    "reachable_call_path": (
        "a call path from application code to the vulnerable function was proven"
    ),
}


def _build_dependency_evidence(
    *,
    cve: str,
    package_name: str,
    installed_version: str,
    fixed_version: str | None,
    introduced_by: str | None,
    dependency_path: str | None,
    reachability: str | None = None,
    reachability_evidence: str | None = None,
) -> str:
    evidence = (
        f"**Advisory evidence:** `{cve}` applies to `{package_name}` "
        f"at installed version `{installed_version}`."
    )
    if fixed_version and fixed_version.strip():
        evidence += f" The advisory is fixed in `{fixed_version.strip()}`."
    if introduced_by and introduced_by.strip():
        evidence += (
            f"\n\n**Transitive dependency:** introduced by the direct "
            f"dependency `{introduced_by.strip()}`."
        )
    if dependency_path and dependency_path.strip():
        evidence += f"\n\n**Dependency chain:** `{dependency_path.strip()}`"
    label = _REACHABILITY_EVIDENCE_LABELS.get((reachability or "").strip().lower())
    if label:
        evidence += f"\n\n**Usage analysis:** {label}."
        if reachability_evidence and reachability_evidence.strip():
            evidence += f" {reachability_evidence.strip()}"
        evidence += (
            " This is a prioritization signal from static analysis, not a"
            " proof of exploitability or of safety."
        )
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
    introduced_by: str | None = None,
    dependency_path: str | None = None,
    manifest_path: str | None = None,
    reachability: str = "unknown",
    reachability_evidence: str | None = None,
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

    manifest_err = _validate_manifest_path(manifest_path)
    if manifest_err:
        errors.append(manifest_err)

    reachability = (reachability or "unknown").strip().lower()
    if reachability not in _VALID_REACHABILITY:
        errors.append(
            f"Invalid reachability: {reachability!r}. Must be one of: {sorted(_VALID_REACHABILITY)}"
        )
    elif reachability != "unknown" and not (reachability_evidence or "").strip():
        errors.append(
            "reachability_evidence is required when reachability is not 'unknown': "
            "cite the concrete proof (import file:line, matched symbol usage, or "
            "govulncheck call path). Never claim a reachability level without evidence."
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
        introduced_by=introduced_by,
        dependency_path=dependency_path,
        manifest_path=manifest_path,
        reachability=reachability,
        reachability_evidence=reachability_evidence,
    )
    evidence = _build_dependency_evidence(
        cve=parsed_cve,
        package_name=package_name.strip(),
        installed_version=installed_version.strip(),
        fixed_version=fixed_version,
        introduced_by=introduced_by,
        dependency_path=dependency_path,
        reachability=reachability,
        reachability_evidence=reachability_evidence,
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
    manifest_path: str | None = None,
    fixed_version: str | None = None,
    cwe: str | None = None,
    technical_analysis: str | None = None,
    fix_effort: str = "low",
    introduced_by: str | None = None,
    dependency_path: str | None = None,
    reachability: str = "unknown",
    reachability_evidence: str | None = None,
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
    because the vulnerable code path may be unreachable — report it, and
    record what the usage analysis showed via the structured
    ``reachability`` + ``reachability_evidence`` fields (see the
    dependency-cve-scanning skill for the analysis procedure). The level
    is an evidence ladder, never an exploitability verdict:

    - ``not_imported`` — the package is never imported/required by
      application code (strongest de-prioritization signal; still not
      proof of safety — dynamic loading, reflection, or framework wiring
      can evade static search).
    - ``imported`` — application code imports the package, but usage of
      the advisory's affected API was not confirmed.
    - ``vulnerable_symbol_used`` — the advisory's affected
      function/class/API appears in application code.
    - ``reachable_call_path`` — a call-graph tool (e.g. ``govulncheck``)
      proved a path from application code to the vulnerable function.
    - ``unknown`` — usage analysis was not performed or was inconclusive.

    Severity is still derived solely from ``advisory_cvss`` — the
    reachability level never changes the rating, only prioritization.

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
        introduced_by: For a **transitive** dependency, the direct
            dependency (from the project's own manifest) that pulls the
            vulnerable package in, as ``name@version`` (e.g.
            ``express@4.18.1``). Omit when the vulnerable package is
            itself a direct dependency.
        dependency_path: The resolution chain from the direct dependency
            to the vulnerable package, joined with `` > `` (e.g.
            ``express@4.18.1 > body-parser@1.20.0 > qs@6.10.2``). Omit
            for direct dependencies.
        manifest_path: **Required.** The repo-relative path of the
            lockfile/manifest where the vulnerable version was observed —
            trivy's ``Target`` (e.g. ``package-lock.json``,
            ``services/api/pom.xml``). Strip any scan-workspace or repo
            checkout directory prefix so the path is relative to the
            repository root. This binds the finding to its exact file so
            remediation can target the right repository.
        reachability: Usage-evidence level from static analysis — one of
            ``not_imported`` / ``imported`` / ``vulnerable_symbol_used`` /
            ``reachable_call_path`` / ``unknown``. Claim only what the
            evidence proves; when in doubt use ``unknown``.
        reachability_evidence: The concrete proof for the claimed level
            (required for any level other than ``unknown``): repo-relative
            ``file:line`` of the import or symbol usage, the matched
            advisory symbols, or the govulncheck call-path excerpt.
    """
    agent_id, agent_name = _caller_identity(ctx)

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
        introduced_by=introduced_by,
        dependency_path=dependency_path,
        manifest_path=manifest_path,
        reachability=reachability,
        reachability_evidence=reachability_evidence,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "none": 5,
}
_VALID_SEVERITIES = frozenset(_SEVERITY_ORDER)
_VALID_FINDING_CLASSES = frozenset({"dynamic", "dependency_cve"})
_REPORT_DESCRIPTION_PREVIEW_CHARS = 280

# Compact, listing-safe fields — no full bodies / PoC code / evidence.
_REPORT_SUMMARY_FIELDS = (
    "id",
    "title",
    "severity",
    "cvss",
    "finding_class",
    "cve",
    "cwe",
    "target",
    "endpoint",
    "method",
    "fix_effort",
    "agent_name",
    "timestamp",
)


def _report_severity_rank(report: dict[str, Any]) -> int:
    return _SEVERITY_ORDER.get(str(report.get("severity", "")).lower(), 99)


def _report_matches_filters(
    report: dict[str, Any],
    *,
    severity: str | None,
    finding_class: str | None,
    target: str | None,
    search: str | None,
) -> bool:
    if severity and str(report.get("severity", "")).lower() != severity:
        return False
    if finding_class and str(report.get("finding_class", "dynamic")).lower() != finding_class:
        return False
    if target:
        target_lower = target.lower()
        haystack = f"{report.get('target', '')} {report.get('endpoint', '')}".lower()
        if target_lower not in haystack:
            return False
    if search:
        search_lower = search.lower()
        title_match = search_lower in str(report.get("title", "")).lower()
        desc_match = search_lower in str(report.get("description", "")).lower()
        if not (title_match or desc_match):
            return False
    return True


def _mark_authorship(
    entry: dict[str, Any], report: dict[str, Any], caller_agent_id: str | None
) -> dict[str, Any]:
    """Flag whether ``report`` was filed by the agent making this call."""
    if caller_agent_id is not None and report.get("agent_id") == caller_agent_id:
        entry["by_you"] = True
    return entry


def _to_report_summary_entry(
    report: dict[str, Any], caller_agent_id: str | None = None
) -> dict[str, Any]:
    entry = {
        field: report[field] for field in _REPORT_SUMMARY_FIELDS if report.get(field) is not None
    }
    description = str(report.get("description", "")).strip()
    if description:
        if len(description) > _REPORT_DESCRIPTION_PREVIEW_CHARS:
            entry["description_preview"] = (
                f"{description[:_REPORT_DESCRIPTION_PREVIEW_CHARS].rstrip()}..."
            )
        else:
            entry["description_preview"] = description
    return _mark_authorship(entry, report, caller_agent_id)


def _severity_counts(reports: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for report in reports:
        sev = str(report.get("severity", "")).lower() or "none"
        counts[sev] = counts.get(sev, 0) + 1
    return {sev: counts[sev] for sev in _SEVERITY_ORDER if sev in counts}


async def _run_report_reader(fn: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(fn, *args, **kwargs)
    except (ImportError, AttributeError) as e:
        logger.exception("report reader failed")
        return {"success": False, "error": f"Failed to read reports: {e!s}"}


def _do_list_reports(
    *,
    severity: str | None,
    finding_class: str | None,
    target: str | None,
    search: str | None,
    include_details: bool,
    caller_agent_id: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    severity = (severity or "").strip().lower() or None
    if severity and severity not in _VALID_SEVERITIES:
        errors.append(
            f"Invalid severity: {severity!r}. Must be one of: {sorted(_VALID_SEVERITIES)}"
        )
    finding_class = (finding_class or "").strip().lower() or None
    if finding_class and finding_class not in _VALID_FINDING_CLASSES:
        errors.append(
            f"Invalid finding_class: {finding_class!r}. "
            f"Must be one of: {sorted(_VALID_FINDING_CLASSES)}"
        )
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    from strix.report.state import get_global_report_state

    report_state = get_global_report_state()
    if report_state is None:
        return {
            "success": True,
            "reports": [],
            "filtered_count": 0,
            "total_count": 0,
            "severity_counts": {},
            "warning": "Report state unavailable - no reports have been filed yet",
        }

    all_reports = report_state.get_existing_vulnerabilities()
    matched = [
        r
        for r in all_reports
        if _report_matches_filters(
            r,
            severity=severity,
            finding_class=finding_class,
            target=(target or "").strip() or None,
            search=(search or "").strip() or None,
        )
    ]
    matched.sort(key=lambda r: (_report_severity_rank(r), str(r.get("id", ""))))

    reports = [
        _mark_authorship(dict(r), r, caller_agent_id)
        if include_details
        else _to_report_summary_entry(r, caller_agent_id)
        for r in matched
    ]
    return {
        "success": True,
        "reports": reports,
        "filtered_count": len(reports),
        "total_count": len(all_reports),
        "severity_counts": _severity_counts(all_reports),
    }


def _do_get_report(report_id: str, caller_agent_id: str | None = None) -> dict[str, Any]:
    report_id = (report_id or "").strip()
    if not report_id:
        return {"success": False, "error": "report_id cannot be empty", "report": None}

    from strix.report.state import get_global_report_state

    report_state = get_global_report_state()
    if report_state is None:
        return {
            "success": False,
            "error": "Report state unavailable - no reports have been filed yet",
            "report": None,
        }

    for report in report_state.get_existing_vulnerabilities():
        if report.get("id") == report_id:
            return {
                "success": True,
                "report": _mark_authorship(dict(report), report, caller_agent_id),
            }
    return {
        "success": False,
        "error": f"Report with id '{report_id}' not found",
        "report": None,
    }


@function_tool(timeout=30)
async def list_reports(
    ctx: RunContextWrapper,
    severity: str | None = None,
    finding_class: str | None = None,
    target: str | None = None,
    search: str | None = None,
    include_details: bool = False,
) -> str:
    """List vulnerability reports filed so far in this scan — metadata-first.

    **For the orchestrator / root agent.** This is an orchestration tool
    for tracking scan-wide coverage and assembling the final report — leaf
    / specialist agents do their own testing and file findings; they should
    NOT call this. If you are a subagent, ignore it and focus on your task.

    Reports are shared across **every** agent in the scan, so this returns
    findings filed by any agent (root or child), not just your own. As the
    root agent, use it to track progress, avoid dispatching work on
    already-covered ground, reason about attack-chaining across confirmed
    findings, and build the ``finish_scan`` executive summary.

    By default each entry is compact: ``id``, ``title``, ``severity``,
    ``cvss``, ``finding_class``, ``cve`` / ``cwe``, ``target`` /
    ``endpoint``, ``fix_effort``, ``agent_name`` (who filed it), ``timestamp``,
    plus a 280-char ``description_preview``. Entries you filed yourself are
    flagged ``by_you: true``. The response also carries
    ``total_count`` and ``severity_counts`` (counts per severity across all
    reports, ignoring filters). Set ``include_details=True`` for full report
    bodies (PoC, evidence, remediation, code_locations) — token-expensive;
    prefer ``get_report`` to drill into a single finding.

    Filters compose (all must match): ``severity`` and ``finding_class``
    match exactly, ``target`` is a substring match against target/endpoint,
    and ``search`` is a substring match against title/description. Results
    are ordered by severity (critical -> info), then report id.

    This is read-only — it never files or dedupes anything.

    Args:
        severity: Filter to one of ``critical`` / ``high`` / ``medium`` /
            ``low`` / ``info`` / ``none``.
        finding_class: Filter to ``dynamic`` (PoC-backed) or
            ``dependency_cve`` (known-CVE supply-chain).
        target: Substring match against a report's target / endpoint.
        search: Substring match against title and description.
        include_details: When False (default) entries are compact; when
            True full report bodies are returned.
    """
    caller_agent_id, _ = _caller_identity(ctx)
    return json.dumps(
        await _run_report_reader(
            _do_list_reports,
            severity=severity,
            finding_class=finding_class,
            target=target,
            search=search,
            include_details=include_details,
            caller_agent_id=caller_agent_id,
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def get_report(ctx: RunContextWrapper, report_id: str) -> str:
    """Fetch one vulnerability report by its id (e.g. ``vuln-0001``).

    Returns the full report body — description, impact, technical analysis,
    PoC, evidence, remediation, CVSS breakdown, and any ``code_locations``.
    Use ``list_reports`` first to find ids; this is the cheap way to read a
    single finding in full without pulling every body.

    Read-only.

    Args:
        report_id: Report id from ``list_reports`` or a
            ``create_vulnerability_report`` / ``create_dependency_report``
            response (format ``vuln-NNNN``).
    """
    caller_agent_id, _ = _caller_identity(ctx)
    return json.dumps(
        await _run_report_reader(_do_get_report, report_id, caller_agent_id),
        ensure_ascii=False,
        default=str,
    )
