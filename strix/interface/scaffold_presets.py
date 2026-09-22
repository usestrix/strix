"""Built-in tactical framings for ``--scaffold-variants`` multi-pass scans.

Composes primitives Strix already has — same-run-name resume (``is_resume``
in ``strix.core.runner.run_strix_scan``) and the existing LLM-based
vulnerability dedupe (``strix.report.dedupe``) — rather than inventing new
state-sharing. Each variant is a full sequential pass against the same
target(s) under the same ``scan_id``, biased toward a different vuln-class
family via a root-agent instruction; overlapping findings across passes
collapse automatically through the dedupe every finding already goes through.

This mirrors the "blackboard" pattern CAI's successor architecture describes
(composing more than one agent strategy against the same target beats any
single strategy alone) using only machinery this codebase already ships and
already tests, instead of a new orchestration engine.
"""

from __future__ import annotations


SCAFFOLD_PRESETS: dict[str, str] = {
    "injection": (
        "For this pass, prioritize server-side injection and execution vulnerability "
        "classes over other categories: SQL/NoSQL injection, OS command injection, "
        "SSTI, XXE, insecure deserialization, and RCE chains (media pipeline, SSRF-to-"
        "internal-service, container escalation). Spawn specialist subagents loaded with "
        "the sql_injection, rce, ssti, xxe, and insecure_deserialization skills before "
        "anything else. Still record coverage and file any other class of finding you "
        "encounter along the way — this is a priority ordering, not an exclusion list."
    ),
    "business-logic": (
        "For this pass, prioritize business-logic and access-control vulnerability "
        "classes over other categories: IDOR, broken function-level authorization, "
        "authentication/authorization bypass, race conditions, mass assignment, and "
        "workflow-order or state-machine bypasses (skipping a required step, replaying "
        "a stale state, price/quantity/role tampering). Spawn specialist subagents "
        "loaded with the idor, broken_function_level_authorization, business_logic, "
        "race_conditions, and authentication_jwt skills before anything else. Still "
        "record coverage and file any other class of finding you encounter along the "
        "way — this is a priority ordering, not an exclusion list."
    ),
    "infra-cloud": (
        "For this pass, prioritize infrastructure and configuration vulnerability "
        "classes over other categories: cloud misconfiguration (AWS/Azure/GCP/"
        "Kubernetes), exposed admin/debug panels, subdomain takeover, CI/CD pipeline "
        "weaknesses, source/secret leakage (.git, .env, backup files, exposed API "
        "keys), and dependency/supply-chain CVEs. Spawn specialist subagents loaded "
        "with the aws, azure, gcp, kubernetes, subdomain_takeover, information_"
        "disclosure, and dependency_cve_scanning skills before anything else. Still "
        "record coverage and file any other class of finding you encounter along the "
        "way — this is a priority ordering, not an exclusion list."
    ),
    "client-side": (
        "For this pass, prioritize client-side and browser-context vulnerability "
        "classes over other categories: XSS (reflected/stored/DOM), CSRF, "
        "clickjacking, prototype pollution, postMessage/CORS/cross-origin trust-"
        "boundary issues, and client-side-only authorization (route guards or state "
        "checks enforced only in JS, not on the server). Spawn specialist subagents "
        "loaded with the xss, csrf, prototype_pollution, and "
        "browser_security skills before anything else. Still record coverage and "
        "file any other class of finding you encounter along the way — this is a "
        "priority ordering, not an exclusion list."
    ),
}


def validate_scaffold_variants(names: list[str]) -> str | None:
    """Return an error message for any unknown preset name, else ``None``."""
    unknown = [n for n in names if n not in SCAFFOLD_PRESETS]
    if unknown:
        known = ", ".join(sorted(SCAFFOLD_PRESETS))
        return (
            f"Unknown --scaffold-variants preset(s): {', '.join(unknown)}. "
            f"Known presets: {known}"
        )
    return None
