"""Bug-bounty agent tools: read the engagement, and check a finding for duplicates.

``bounty_scope_status`` gives an agent the program's scope and rules of engagement in
one place (what is in scope, what is explicitly excluded, the ROE constraints it must
obey, and whether intrusive proofs are permitted). ``check_duplicate`` ranks a
prospective finding against the program's known/disclosed reports so the agent avoids
re-reporting a known issue. Both are read-only; scope is still enforced at the tool
boundaries.

This module intentionally omits ``from __future__ import annotations`` so the SDK can
resolve the ``RunContextWrapper`` context annotation at registration.
"""

import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.bounty.dedupe import get_known_reports
from strix.bounty.runtime import get_bounty_context


def _status_payload() -> dict[str, Any]:
    """Build the bounty scope/ROE briefing. Pure, so it is directly testable."""
    context = get_bounty_context()
    if context is None:
        return {"bounty_active": False, "note": "No bug-bounty program is loaded for this run."}
    program = context.program
    policy = context.compiled.policy
    gate = context.gate
    known = get_known_reports()
    return {
        "bounty_active": True,
        "platform": program.platform,
        "handle": program.handle,
        "name": program.name,
        "url": program.url,
        "scope": {
            "web_domains": policy.web.domains,
            "api_base_urls": policy.api.base_urls,
            "network_hosts": policy.network.hosts,
            "network_cidrs": policy.network.cidrs,
            "aws_account_ids": policy.cloud.aws_account_ids,
            "exclusions": {
                "hosts": policy.exclusions.hosts,
                "urls": policy.exclusions.urls,
                "cidrs": policy.exclusions.cidrs,
            },
        },
        "unmapped_in_scope_assets": context.compiled.unmapped,
        "allow_intrusive": policy.allow_intrusive,
        "rules_of_engagement": {
            "mode": gate.mode,
            "active_tools_allowed": gate.active_tools_allowed,
            "rate_limit_rps": program.roe.rate_limit_rps,
            "required_headers": program.roe.required_headers,
            "constraints": gate.constraints,
        },
        "known_report_count": len(known.reports) if known is not None else 0,
        "reminder": (
            "Stay within scope (enforced at tool boundaries), obey the rules of "
            "engagement, and check every finding with check_duplicate before you "
            "treat it as submittable."
        ),
    }


def _duplicate_payload(title: str, asset: str, vuln_type: str) -> dict[str, Any]:
    """Rank a prospective finding against known reports. Pure, so it is testable."""
    known = get_known_reports()
    if known is None:
        return {
            "known_report_count": 0,
            "verdict": "novel",
            "note": (
                "No disclosed reports were loaded for this program; this is not proof "
                "the issue is novel. Check the program's Hacktivity / Crowdstream "
                "manually before submitting."
            ),
        }
    return known.check(
        title=title,
        asset=asset.strip() or None,
        vuln_type=vuln_type.strip() or None,
    )


@function_tool(timeout=15)
async def bounty_scope_status(ctx: RunContextWrapper) -> str:
    """Show the bug-bounty engagement: authorized scope + rules of engagement.

    Read this first in a bounty run. It tells you which assets are in scope, which
    are explicitly out of scope, the hard rules you must obey (rate limit, prohibited
    techniques, ineligible bug classes, intrusive posture), and which in-scope assets
    could not be auto-gated (mobile apps, source, binaries) so you test those with
    extra care. Read-only.
    """
    del ctx
    return json.dumps(_status_payload(), ensure_ascii=False, default=str)


@function_tool(timeout=15)
async def check_duplicate(
    ctx: RunContextWrapper,
    title: str,
    asset: str = "",
    vuln_type: str = "",
) -> str:
    """Check a prospective finding against the program's known / disclosed reports.

    Call this before you treat a finding as submittable. It returns the closest known
    reports with a similarity score and a verdict (``likely_duplicate`` /
    ``possible_duplicate`` / ``novel``). The verdict is guidance, not a decision: open
    the matched reports and judge for yourself, exactly as a human hunter checks
    Hacktivity / Crowdstream first. A ``novel`` verdict with no loaded reports only
    means nothing was loaded — still verify against the program's disclosures.

    Args:
        title: The finding title you would submit (e.g. "SQLi in /search").
        asset: The affected asset (URL/host), if known — improves matching.
        vuln_type: The vulnerability class (e.g. "SQL injection", "IDOR"), if known.
    """
    del ctx
    return json.dumps(_duplicate_payload(title, asset, vuln_type), ensure_ascii=False, default=str)
