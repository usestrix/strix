"""Dedupe against known / disclosed reports so a run targets novel issues.

Bug-bounty payouts go to the first valid report of an issue, so re-reporting a
known one wastes effort and annoys the program. This module ingests the program's
public disclosures (HackerOne Hacktivity, Bugcrowd Crowdstream, or a saved file) as
:class:`KnownReport` records and scores a prospective finding against them.

Report titles are free text, so exact matching is useless; :func:`similarity` uses
token overlap on the title plus asset and vuln-type signals to produce a ranked
shortlist with a ``likely`` / ``possible`` / ``novel`` verdict. The shortlist is an
aid, not a verdict: the agent reads the candidate reports and makes the call, exactly
as a human hunter checks Hacktivity before writing up a bug.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, ValidationError

from strix.bounty.loaders.errors import BountyLoadError
from strix.candidates.schema import normalize_target


if TYPE_CHECKING:
    from collections.abc import Iterable


_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    {
        "the", "a", "an", "in", "on", "of", "to", "and", "or", "via", "for", "with",
        "at", "is", "are", "be", "by", "from", "into", "using", "that", "this", "it",
        "vulnerability", "issue", "bug", "security", "allows", "allow", "can", "could",
    }
)

# Common security abbreviations expanded to their canonical words, so "SQLi" matches
# "SQL injection" and "XSS" matches "cross-site scripting" in title overlap.
_ABBREVIATIONS: dict[str, set[str]] = {
    "sqli": {"sql", "injection"},
    "xss": {"cross", "site", "scripting"},
    "ssrf": {"server", "side", "request", "forgery"},
    "csrf": {"cross", "site", "request", "forgery"},
    "rce": {"remote", "code", "execution"},
    "idor": {"insecure", "direct", "object", "reference"},
    "lfi": {"local", "file", "inclusion"},
    "rfi": {"remote", "file", "inclusion"},
    "xxe": {"xml", "external", "entity"},
    "ssti": {"server", "side", "template", "injection"},
    "ato": {"account", "takeover"},
}

LIKELY_THRESHOLD = 0.6
POSSIBLE_THRESHOLD = 0.35
_FLOOR = 0.2


class KnownReport(BaseModel):
    """A disclosed / known report to dedupe against."""

    model_config = ConfigDict(extra="forbid")

    title: str
    vuln_type: str | None = None
    asset: str | None = None
    state: str | None = None
    severity: str | None = None
    url: str | None = None
    reported_at: str | None = None
    source: str | None = None


def _tokens(text: str | None) -> set[str]:
    if not text:
        return set()
    base = {t for t in _TOKEN_RE.findall(text.lower()) if len(t) > 1 and t not in _STOPWORDS}
    expanded = set(base)
    for token in base:
        expanded |= _ABBREVIATIONS.get(token, set())
    return expanded


def _assets_overlap(a: str, b: str) -> bool:
    na, nb = normalize_target(a), normalize_target(b)
    if not na or not nb:
        return False
    host_a, host_b = na.split("/", 1)[0], nb.split("/", 1)[0]
    return na == nb or host_a == host_b or na.startswith(nb) or nb.startswith(na)


def similarity(
    report: KnownReport,
    *,
    title: str,
    asset: str | None = None,
    vuln_type: str | None = None,
) -> float:
    """Score a prospective finding against one known report, in ``[0, 1]``."""
    probe_title = _tokens(title)
    report_title = _tokens(report.title)
    score = 0.0
    if probe_title and report_title:
        jaccard = len(probe_title & report_title) / len(probe_title | report_title)
        score += 0.6 * jaccard

    if vuln_type:
        probe_vuln = _tokens(vuln_type)
        if report.vuln_type and probe_vuln & _tokens(report.vuln_type):
            score += 0.2
        elif probe_vuln & report_title:
            score += 0.1

    if asset and report.asset and _assets_overlap(asset, report.asset):
        score += 0.2

    return min(score, 1.0)


def _verdict(score: float) -> str:
    if score >= LIKELY_THRESHOLD:
        return "likely_duplicate"
    if score >= POSSIBLE_THRESHOLD:
        return "possible_duplicate"
    return "novel"


class KnownReportsStore:
    """Holds the run's known/disclosed reports and ranks matches against them."""

    def __init__(self, reports: Iterable[KnownReport] | None = None) -> None:
        self.reports: list[KnownReport] = list(reports or [])

    def check(
        self,
        *,
        title: str,
        asset: str | None = None,
        vuln_type: str | None = None,
        top: int = 5,
    ) -> dict[str, Any]:
        """Return the best-matching known reports and an overall verdict."""
        scored = [
            (similarity(r, title=title, asset=asset, vuln_type=vuln_type), r) for r in self.reports
        ]
        matches = sorted(
            ((s, r) for s, r in scored if s >= _FLOOR), key=lambda pair: pair[0], reverse=True
        )[:top]
        best = matches[0][0] if matches else 0.0
        return {
            "known_report_count": len(self.reports),
            "verdict": _verdict(best),
            "best_score": round(best, 3),
            "matches": [
                {
                    "score": round(score, 3),
                    "verdict": _verdict(score),
                    "title": r.title,
                    "asset": r.asset,
                    "state": r.state,
                    "url": r.url,
                }
                for score, r in matches
            ],
        }


# ---- global store (bound once per run, read-only during it) -----------------

_global_known_reports: KnownReportsStore | None = None


def get_known_reports() -> KnownReportsStore | None:
    return _global_known_reports


def reset_known_reports(reports: Iterable[KnownReport] | None) -> KnownReportsStore:
    """Bind the run's known reports (or ``None`` to clear)."""
    global _global_known_reports  # noqa: PLW0603
    _global_known_reports = KnownReportsStore(reports) if reports is not None else None
    return _global_known_reports or KnownReportsStore()


# ---- parsers / loaders ------------------------------------------------------


def known_reports_from_mapping(raw: object) -> list[KnownReport]:
    """Validate a list (or ``{"reports": [...]}``) of report dicts."""
    items = raw.get("reports") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise BountyLoadError("known-reports data must be a list or {'reports': [...]}")
    try:
        return [KnownReport.model_validate(item) for item in items]
    except ValidationError as exc:
        raise BountyLoadError(f"invalid known-reports data:\n{exc}") from exc


def load_known_reports_file(path: str | Path) -> list[KnownReport]:
    """Load known reports from a saved JSON file (Hacktivity/Crowdstream export)."""
    source = Path(path).expanduser()
    if not source.is_file():
        raise BountyLoadError(f"known-reports file not found: {source}")
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BountyLoadError(f"could not read known-reports file {source}: {exc}") from exc
    return known_reports_from_mapping(raw)


def parse_hackerone_hacktivity(payload: dict[str, Any]) -> list[KnownReport]:
    """Parse a HackerOne Hacktivity API payload into known reports (best-effort)."""
    out: list[KnownReport] = []
    for item in payload.get("data") or []:
        if not isinstance(item, dict):
            continue
        attrs = item.get("attributes") or {}
        title = (attrs.get("title") or "").strip()
        if not title:
            continue
        out.append(
            KnownReport(
                title=title,
                state=attrs.get("state") or attrs.get("substate"),
                severity=attrs.get("severity_rating"),
                url=attrs.get("report_url") or (item.get("links") or {}).get("self"),
                reported_at=attrs.get("latest_disclosable_activity_at")
                or attrs.get("disclosed_at"),
                source="hackerone",
            )
        )
    return out


def parse_bugcrowd_disclosures(payload: dict[str, Any]) -> list[KnownReport]:
    """Parse a Bugcrowd disclosures payload into known reports (best-effort)."""
    items = payload.get("disclosures")
    if not isinstance(items, list):
        items = payload.get("data") or []
    out: list[KnownReport] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        attrs = item.get("attributes") or item
        title = (attrs.get("title") or attrs.get("name") or "").strip()
        if not title:
            continue
        out.append(
            KnownReport(
                title=title,
                vuln_type=attrs.get("vrt") or attrs.get("bug_type"),
                asset=attrs.get("target") or attrs.get("asset"),
                state=attrs.get("state") or attrs.get("substate"),
                severity=attrs.get("severity") or attrs.get("priority"),
                url=attrs.get("url") or (item.get("links") or {}).get("self"),
                source="bugcrowd",
            )
        )
    return out


def render_dedupe_md(reports: Iterable[KnownReport]) -> str:
    """Render the known-reports list for the agent briefing."""
    rows = list(reports)
    lines = ["## Known / disclosed reports (avoid duplicates)", ""]
    if not rows:
        lines.append("_No disclosed reports were loaded for this program._")
        lines.append("")
        lines.append(
            "Still check the program's Hacktivity / Crowdstream before submitting; "
            "the absence of a loaded list is not proof an issue is novel."
        )
        return "\n".join(lines) + "\n"
    lines.append(f"{len(rows)} report(s) loaded. Do not re-report these; confirm novelty first.")
    lines.append("")
    for r in rows:
        bits = [f"**{r.title}**"]
        if r.asset:
            bits.append(f"asset: {r.asset}")
        if r.state:
            bits.append(f"state: {r.state}")
        if r.severity:
            bits.append(f"severity: {r.severity}")
        lines.append("- " + " · ".join(bits))
    return "\n".join(lines) + "\n"
