"""Agent tools for Target Complexity Index (TCI) and dynamic scan planning."""

from __future__ import annotations

import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.agents.planner import ScanPlanner
from strix.core.tci import TargetFingerprint, calculate_tci
from strix.modules.registry import default_registry


logger = logging.getLogger(__name__)


def _parse_fingerprint_arg(raw: Any) -> dict[str, Any]:
    """Parse JSON string or dict into fingerprint dictionary.

    Raises:
        ValueError: If raw is invalid JSON.
        TypeError: If raw is not a JSON string, dict, or parsed value is not a dict.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return {}
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            msg = f"Invalid fingerprint JSON: {exc}"
            raise ValueError(msg) from exc
        if not isinstance(parsed, dict):
            msg = f"Fingerprint JSON must be an object/dict, got {type(parsed).__name__}"
            raise TypeError(msg)
        return parsed
    msg = f"Fingerprint argument must be a JSON string or dict, got {type(raw).__name__}"
    raise TypeError(msg)


@function_tool(timeout=30)
async def calculate_target_complexity(
    ctx: RunContextWrapper,
    target: str,
    fingerprint: str = "{}",
) -> str:
    """Calculate the Target Complexity Index (TCI: 0.0 .. 100.0) from fingerprint observables.

    TCI measures the complexity and attack surface of a target based on:
    - Open ports and protocols
    - Authentication mechanisms (JWT, OAuth, SAML, session cookies, MFA, RBAC)
    - API surface size (endpoint count, GraphQL vs REST, parameter count)
    - Technology stack (front-end SPA, back-end polyglot/frameworks, databases)
    - WAF and CDN presence (Cloudflare, AWS WAF, etc.)
    - Data sensitivity (PII, financial, admin panels)
    - Patch posture / legacy indicators

    Args:
        target: The target URL, domain, or identifier.
        fingerprint: JSON object string containing fingerprint metadata:
            - ``open_ports`` (list of int): e.g. ``[80, 443, 8080]``
            - ``protocols`` (list of str): e.g. ``["https", "grpc"]``
            - ``auth_patterns`` (list of str): e.g. ``["jwt", "oauth2"]``
            - ``api_surface`` (dict): e.g. ``{"endpoints_count": 25, "api_types": ["rest"]}``
            - ``frontend_technologies`` (list of str): e.g. ``["react"]``
            - ``backend_technologies`` (list of str): e.g. ``["fastapi", "postgres"]``
            - ``waf_cdn`` (list of str): e.g. ``["cloudflare"]``
            - ``data_sensitivity`` (str): e.g. ``"high"`` or ``"standard"``
            - ``patch_posture`` (str): e.g. ``"current"`` or ``"outdated"``

    Returns:
        JSON object containing ``target``, ``tci`` (0..100), ``level``,
        ``sub_scores``, and descriptive ``breakdown``.
    """
    del ctx  # Unused by calculation
    try:
        fp_dict = _parse_fingerprint_arg(fingerprint)
        if target and "target" not in fp_dict:
            fp_dict["target"] = target

        fp = TargetFingerprint(**fp_dict)
        res = calculate_tci(fp)
    except (ValueError, TypeError) as exc:
        logger.warning("Error calculating target complexity: %s", exc)
        return json.dumps({"error": str(exc)}, ensure_ascii=False, indent=2)

    payload = {
        "target": target or fp.target,
        "tci": res.score,
        "level": res.level.value,
        "sub_scores": res.sub_scores,
        "breakdown": res.breakdown,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


@function_tool(timeout=30)
async def create_scan_plan(
    ctx: RunContextWrapper,
    target: str,
    fingerprint: str = "{}",
    scan_mode: str = "deep",
    safe_mode: bool | None = None,
) -> str:
    """Generate a dynamic, context-aware scan plan from fingerprint and TCI.

    Maps target fingerprint to a prioritized sequence of tactical testing modules,
    eliminating irrelevant tests and optimizing resource allocation.

    Args:
        target: Target URL, API endpoint, or hostname to assess.
        fingerprint: JSON string describing target observables.
        scan_mode: Scan mode ('quick', 'standard', 'deep', 'diff').
            - ``quick``: critical/high priority tests only with constrained quotas.
            - ``standard``: balanced coverage of critical, high, and medium vectors.
            - ``deep``: thorough assessment across all applicable modules.
        safe_mode: Optional boolean override for safe mode (cautious, evasive rate-limiting).
            If omitted, safe_mode is automatically decided based on WAF presence and TCI.

    Returns:
        JSON payload containing ``target``, ``fingerprint``, ``tci``, and ``plan``:
        ```json
        {
          "target": "https://api.example.local",
          "fingerprint": { ... },
          "tci": 78.3,
          "plan": [
            {"step": 1, "module": "auth-enum", "priority": "high", "safe_mode": true},
            {"step": 2, "module": "id_or", "priority": "high", "safe_mode": true},
            {"step": 3, "module": "sqli-fuzz", "priority": "medium", "safe_mode": true}
          ]
        }
        ```
    """
    del ctx
    try:
        fp_dict = _parse_fingerprint_arg(fingerprint)
        if target and "target" not in fp_dict:
            fp_dict["target"] = target

        planner = ScanPlanner()
        plan = planner.generate_plan(
            target=target,
            fingerprint=fp_dict,
            scan_mode=scan_mode,
            safe_mode_override=safe_mode,
        )
        return plan.to_json(compact=False, indent=2)
    except (ValueError, TypeError) as exc:
        logger.warning("Error creating scan plan: %s", exc)
        return json.dumps({"error": str(exc)}, ensure_ascii=False, indent=2)


@function_tool(timeout=30)
async def list_scan_modules(
    ctx: RunContextWrapper,
    category: str = "",
) -> str:
    """List available vulnerability scanning modules in the registry.

    Args:
        category: Optional category filter (e.g. 'authentication', 'injection',
            'authorization', 'api', 'recon', 'logic').

    Returns:
        JSON list of registered modules with description, priority, category,
        safe_mode hints, and associated skills.
    """
    del ctx
    clean_cat = category.strip().lower()
    if clean_cat:
        modules = default_registry.list_by_category(clean_cat)
    else:
        modules = default_registry.list_all()

    items = [
        {
            "name": m.name,
            "category": m.category,
            "description": m.description,
            "default_priority": m.default_priority.value,
            "safe_mode_default": m.safe_mode_default,
            "skills": m.skills,
            "prerequisites": m.prerequisites,
            "tags": m.tags,
            "intrusive": m.intrusive,
        }
        for m in modules
    ]
    return json.dumps(items, ensure_ascii=False, indent=2, default=str)
