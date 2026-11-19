"""Retest: verify previously-found vulnerabilities against a target again.

A retest is a fresh, tightly-scoped scan, not a ``--resume``: the open findings
for an app are rendered into an instruction file, the agent replays each PoC,
and the outcome is reconciled back onto the findings.

Two independent signals decide a verdict, because neither is sufficient alone:

* the agent re-reporting the vulnerability (strong evidence it still works);
* an explicit per-finding verdict block the instruction asks for (needed
  because *absence* of a re-report may only mean the agent never got to it).

They are combined in :func:`reconcile_retest`, and anything they do not settle
stays ``inconclusive`` rather than being silently called fixed.

A *verify* run is the same machinery for a different question: an analyst
marked one finding as doubtful, and the agent must decide whether it is real
at all (``confirmed`` / ``refuted``), not whether it was fixed. See
:func:`build_verify_instruction` and :func:`reconcile_verify`.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from frontal.app.models import App, Finding, FindingObservation, FindingTriage, Scan
from frontal.app.runfiles import read_report_markdown, read_run_summary


logger = logging.getLogger(__name__)

FINDING_REF_PREFIX = "F-"
_JSON_BLOCK_RE = re.compile(r"```(?:json)?[^\n]*\n(.*?)```", re.DOTALL)
_VALID_VERDICTS = frozenset({"still_vulnerable", "fixed", "inconclusive"})
_VERIFY_VERDICTS = frozenset({"confirmed", "refuted", "inconclusive"})
VERIFY_AUTHOR = "strix"


def finding_ref(finding: Finding) -> str:
    return f"{FINDING_REF_PREFIX}{finding.id}"


def _section(finding: Finding) -> str:
    data = finding.data or {}
    lines = [
        f"### {finding_ref(finding)} — {finding.title}",
        f"- Severity: {finding.severity}"
        + (f" (CVSS {finding.cvss})" if finding.cvss is not None else ""),
    ]
    if finding.cwe:
        lines.append(f"- Weakness: {finding.cwe}")
    if finding.endpoint:
        lines.append(f"- Endpoint: {(finding.method or 'ANY')} {finding.endpoint}")
    if data.get("description"):
        lines.append(f"- What it was: {data['description']}")
    if data.get("poc_description"):
        lines.append(f"- Original reproduction steps: {data['poc_description']}")
    if data.get("evidence"):
        lines.append(f"- Original evidence: {data['evidence']}")
    if data.get("fix_verification"):
        lines.append(f"- How a fix should look: {data['fix_verification']}")
    elif data.get("remediation_steps"):
        lines.append(f"- Recommended remediation was: {data['remediation_steps']}")
    if data.get("poc_script_code"):
        lines.append("- Original PoC:")
        lines.append("```sh")
        lines.append(str(data["poc_script_code"]).strip())
        lines.append("```")
    return "\n".join(lines)


def build_retest_instruction(app: App, findings: list[Finding]) -> str:
    """Render the ``--instruction-file`` body for a retest run."""
    refs = ", ".join(finding_ref(f) for f in findings)
    sections = "\n\n".join(_section(f) for f in findings)
    # Built from the real refs: an example naming a finding that is not in this
    # run invites the agent to invent a verdict for it.
    example = ",\n  ".join(
        json.dumps(
            {
                "finding_id": finding_ref(f),
                "verdict": "still_vulnerable" if index == 0 else "fixed",
                "evidence": "...",
            }
        )
        for index, f in enumerate(findings[:2])
    )
    noun = "vulnerability" if len(findings) == 1 else "vulnerabilities"
    return f"""# RETEST — {app.name}

This run is a RETEST of {len(findings)} previously confirmed {noun} on
{app.target}. It is NOT a discovery engagement.

Your job, for each finding below, in order:

1. Reproduce it exactly as originally described, starting from the original PoC.
2. If the original PoC fails, make a reasonable attempt at variations of it
   before concluding the issue is fixed — a fix that only blocks the literal
   payload is not a fix.
3. Decide a verdict: `still_vulnerable`, `fixed`, or `inconclusive`.
   Use `inconclusive` honestly — if the endpoint is unreachable, needs
   credentials you do not have, or the behaviour is ambiguous, say so instead
   of guessing. A wrong `fixed` is the most expensive mistake you can make here.
4. Call `report_vulnerability` ONLY for findings that are still exploitable,
   with fresh evidence from this run.

Do not spend budget hunting for new, unrelated vulnerabilities. If you do
stumble onto something clearly critical while reproducing, report it, but the
listed findings always come first.

## Findings under retest

{sections}

## Required output

When you call `finish_scan`, end the `executive_summary` argument with a
fenced ```json block, and nothing after it, holding one entry per finding
listed above ({refs}). It is machine-read, so it is required even though the
rest of the report is prose:

```json
[
  {example}
]
```

`evidence` must be what you actually observed in THIS run (a response code, a
response body excerpt, an error), not a restatement of the original finding.
Every finding above must appear exactly once.
"""


def build_verify_instruction(app: App, finding: Finding, doubt: str | None) -> str:
    """Render the ``--instruction-file`` body for verifying one doubtful finding."""
    ref = finding_ref(finding)
    doubt_block = (
        f"""## Why the analyst doubts it

{doubt.strip()}

Address this objection directly: your verdict must say whether it holds.
"""
        if doubt and doubt.strip()
        else ""
    )
    example = json.dumps({"finding_id": ref, "verdict": "refuted", "evidence": "..."})
    return f"""# VERIFY — {app.name} — {ref}

A previous run reported the finding below on {app.target}. A human analyst
reviewed it and is NOT convinced it is real. This run exists only to settle
that: is it a true positive or a false positive?

Scope: ONLY this finding. Do not look for other vulnerabilities, do not
explore unrelated endpoints, and do not report anything else.

How to work:

1. Read the original evidence critically. Assume it may be wrong: a
   reflected value that is never executed, an error that is not exploitable,
   a response that only looks privileged, a payload blocked further down.
2. Reproduce it from the original PoC, then try to prove real impact — the
   concrete thing an attacker gains — not just an anomalous response.
3. Decide a verdict:
   - `confirmed`: you reproduced it AND demonstrated impact in this run.
   - `refuted`: you can show why it is not exploitable (explain the control
     or behaviour that stops it).
   - `inconclusive`: you could not reach it, lacked credentials, or the
     evidence points both ways. Prefer this over guessing either way.
4. Call `report_vulnerability` ONLY if the verdict is `confirmed`, with fresh
   evidence from this run.

{doubt_block}
## Finding under verification

{_section(finding)}

## Required output

When you call `finish_scan`, end the `executive_summary` argument with a
fenced ```json block, and nothing after it, holding exactly one entry for
{ref}. It is machine-read, so it is required even though the rest of the
report is prose:

```json
[
  {example}
]
```

`evidence` must be what you observed in THIS run (requests sent, response
codes, body excerpts) and, for `refuted`, the reason it is not exploitable.
"""


def parse_verdicts(text: str, valid: frozenset[str] = _VALID_VERDICTS) -> dict[str, dict[str, Any]]:
    """Extract the agent's verdict block; keyed by finding ref (``F-12``).

    Scans every fenced block and keeps the last one that looks like a verdict
    list, so prose or an unrelated snippet earlier in the report is ignored.
    """
    verdicts: dict[str, dict[str, Any]] = {}
    for block in _JSON_BLOCK_RE.findall(text or ""):
        try:
            payload = json.loads(block)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, list):
            continue
        parsed: dict[str, dict[str, Any]] = {}
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            ref = str(entry.get("finding_id") or "").strip()
            verdict = str(entry.get("verdict") or "").lower().strip()
            if ref and verdict in valid:
                parsed[ref] = {"verdict": verdict, "evidence": entry.get("evidence")}
        if parsed:
            verdicts = parsed
    return verdicts


def read_agent_verdicts(
    run_dir: Path, valid: frozenset[str] = _VALID_VERDICTS
) -> dict[str, dict[str, Any]]:
    verdicts = parse_verdicts(read_report_markdown(run_dir), valid)
    if verdicts:
        return verdicts
    # The executive summary carries the agent's own wording too; worth a look
    # when the report writer reshaped the markdown.
    summary = read_run_summary(run_dir).get("scan_results")
    if isinstance(summary, dict):
        return parse_verdicts(str(summary.get("executive_summary") or ""), valid)
    return {}


def reconcile_retest(session: Session, scan: Scan, run_dir: Path) -> dict[str, str]:
    """Apply a finished retest run to the findings it was asked to verify."""
    finding_ids = scan.retest_finding_ids or []
    if not finding_ids:
        return {}

    findings = list(session.scalars(select(Finding).where(Finding.id.in_(finding_ids))).all())
    agent_verdicts = read_agent_verdicts(run_dir)
    reobserved = {
        observation.finding_id
        for observation in session.scalars(
            select(FindingObservation).where(FindingObservation.scan_id == scan.id)
        ).all()
    }

    outcome: dict[str, str] = {}
    for finding in findings:
        claimed = agent_verdicts.get(finding_ref(finding), {})
        claimed_verdict = claimed.get("verdict")

        if finding.id in reobserved:
            # Re-reported with fresh evidence: the strongest signal available,
            # and it overrides a contradicting "fixed" claim.
            verdict = "still_vulnerable"
        elif claimed_verdict in {"fixed", "still_vulnerable"}:
            verdict = claimed_verdict
        else:
            verdict = "inconclusive"

        finding.last_retest_scan_id = scan.id
        finding.last_verdict = verdict
        if verdict == "fixed":
            finding.status = "fixed"
        elif verdict == "still_vulnerable" and finding.status == "fixed":
            finding.status = "open"

        _upsert_verdict_observation(session, scan, finding, verdict, claimed.get("evidence"))
        outcome[finding_ref(finding)] = verdict

    logger.info("retest scan %s reconciled %d findings", scan.id, len(outcome))
    return outcome


def reconcile_verify(session: Session, scan: Scan, run_dir: Path) -> dict[str, str]:
    """Apply a finished verify run to the doubtful finding it was asked about.

    ``confirmed`` (re-reported with fresh evidence, or claimed) settles the
    doubt as a true positive. ``refuted`` only *proposes* a false positive: the
    finding stays doubtful until an analyst marks it, with a justification.
    """
    finding_ids = scan.retest_finding_ids or []
    if not finding_ids:
        return {}

    findings = list(session.scalars(select(Finding).where(Finding.id.in_(finding_ids))).all())
    agent_verdicts = read_agent_verdicts(run_dir, _VERIFY_VERDICTS)
    reobserved = {
        observation.finding_id
        for observation in session.scalars(
            select(FindingObservation).where(FindingObservation.scan_id == scan.id)
        ).all()
    }
    fresh_evidence = None
    if len(findings) == 1 and findings[0].id not in reobserved:
        fresh_evidence = _fold_reported_variant(session, scan, findings[0])
        if fresh_evidence is not None:
            reobserved.add(findings[0].id)

    outcome: dict[str, str] = {}
    for finding in findings:
        claimed = agent_verdicts.get(finding_ref(finding), {})
        claimed_verdict = claimed.get("verdict")
        if fresh_evidence and not claimed.get("evidence"):
            claimed = {**claimed, "evidence": fresh_evidence}

        if finding.id in reobserved:
            verdict = "confirmed"
        elif claimed_verdict in {"confirmed", "refuted"}:
            verdict = claimed_verdict
        else:
            verdict = "inconclusive"

        finding.last_retest_scan_id = scan.id
        finding.last_verdict = verdict
        # Only settle what is still waiting on this run: an analyst may have
        # decided by hand while it was running, and that decision wins.
        if verdict == "confirmed" and finding.status == "doubtful":
            finding.status = "open"
            finding.triage = "true_positive"
            session.add(
                FindingTriage(
                    finding_id=finding.id,
                    decision="true_positive",
                    justification=str(claimed.get("evidence") or "")
                    or f"Re-reported with fresh evidence by verify scan #{scan.id}",
                    author=VERIFY_AUTHOR,
                    scan_id=scan.id,
                )
            )

        _upsert_verdict_observation(session, scan, finding, verdict, claimed.get("evidence"))
        outcome[finding_ref(finding)] = verdict

    logger.info("verify scan %s reconciled %d findings", scan.id, len(outcome))
    return outcome


def _fold_reported_variant(session: Session, scan: Scan, target: Finding) -> str | None:
    """Recognise the doubtful finding when the verify run re-reported it under another key.

    A verify run is scoped to one finding and told to report only if it
    confirms it, so a report of the same weakness *is* that finding, even when
    the fingerprint differs (e.g. the original had no endpoint and this one
    does). A duplicate the run itself created is merged into the target, which
    inherits its endpoint and fingerprint so later scans match it directly.

    Returns the fresh evidence (possibly ``""``) when a variant was found.
    """
    observations = session.scalars(
        select(FindingObservation).where(
            FindingObservation.scan_id == scan.id, FindingObservation.finding_id != target.id
        )
    ).all()
    target_cwe = (target.cwe or "").upper().strip()
    for observation in observations:
        variant = observation.finding
        variant_cwe = (variant.cwe or "").upper().strip()
        if target_cwe and variant_cwe and variant_cwe != target_cwe:
            continue
        evidence = observation.evidence or ""
        if variant.first_seen_scan_id == scan.id:
            fingerprint, endpoint, method = variant.fingerprint, variant.endpoint, variant.method
            session.delete(variant)
            session.flush()
            if endpoint and not target.endpoint:
                target.endpoint, target.method, target.fingerprint = endpoint, method, fingerprint
        target.last_seen_scan_id = scan.id
        logger.info("verify scan %s: report %s counted as F-%s", scan.id, variant.id, target.id)
        return evidence
    return None


def _upsert_verdict_observation(
    session: Session,
    scan: Scan,
    finding: Finding,
    verdict: str,
    evidence: Any,
) -> None:
    observation = session.scalar(
        select(FindingObservation).where(
            FindingObservation.finding_id == finding.id,
            FindingObservation.scan_id == scan.id,
        )
    )
    if observation is None:
        observation = FindingObservation(
            finding_id=finding.id,
            scan_id=scan.id,
            raw={},
        )
        session.add(observation)
    observation.verdict = verdict
    if evidence:
        observation.evidence = str(evidence)
