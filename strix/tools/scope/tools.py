"""Agent tools to read and check the authorized scope.

``check_scope`` lets an agent verify a target (and whether an intrusive action is
permitted) before acting; ``scope_status`` summarizes the active policy. Both are
read-only. Enforcement itself is applied at the tool boundaries (e.g. ``call_mcp``
and the domain tools) — these tools let the agent reason about scope explicitly and
explain a refusal.

This module omits ``from __future__ import annotations`` so the SDK resolves the
``RunContextWrapper`` context annotation at registration.
"""

import json

from agents import RunContextWrapper, function_tool

from strix.scope.enforcement import get_active_policy


@function_tool(timeout=15)
async def check_scope(ctx: RunContextWrapper, target: str, intrusive: bool = False) -> str:
    """Check whether a target is in the authorized scope before you act on it.

    Use this whenever you are about to touch a host, URL, IP, cloud account, or API
    base you have not already confirmed — especially for network/cloud/API targets.
    A denied result means you must NOT proceed against that target; pick an in-scope
    target or stop.

    Args:
        target: What you want to act on — a URL, hostname, IP/CIDR, API base URL,
            ``aws:<account-id>`` / 12-digit AWS account id / ARN.
        intrusive: Set true if the action would change target state (a write/delete,
            or exploitation that modifies the target). Such actions are refused
            unless the run was authorized with ``--allow-intrusive``.
    """
    del ctx
    policy = get_active_policy()
    if policy is None:
        return json.dumps(
            {
                "scope_active": False,
                "allowed": True,
                "note": (
                    "No scope.yaml is loaded, so no authorized-scope policy is enforced this "
                    "run. Only act on targets you know are authorized."
                ),
            },
            ensure_ascii=False,
        )
    decision = policy.evaluate(target, intrusive=intrusive)
    return json.dumps(
        {
            "scope_active": True,
            "target": target,
            "intrusive": intrusive,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "kind": decision.kind,
            "matched": decision.matched,
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=15)
async def scope_status(ctx: RunContextWrapper) -> str:
    """Summarize the run's authorized scope (what you may touch, and whether
    intrusive actions are allowed). Read-only."""
    del ctx
    policy = get_active_policy()
    if policy is None:
        return json.dumps(
            {"scope_active": False, "note": "No scope.yaml loaded; no policy enforced."},
            ensure_ascii=False,
        )
    return json.dumps(
        {
            "scope_active": True,
            "name": policy.name,
            "allow_intrusive": policy.allow_intrusive,
            "web_domains": policy.web.domains,
            "api_base_urls": policy.api.base_urls,
            "network_hosts": policy.network.hosts,
            "network_cidrs": policy.network.cidrs,
            "network_ports": policy.network.ports,
            "aws_account_ids": policy.cloud.aws_account_ids,
            "azure_subscription_ids": policy.cloud.azure_subscription_ids,
            "gcp_project_ids": policy.cloud.gcp_project_ids,
        },
        ensure_ascii=False,
        default=str,
    )
