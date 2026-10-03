"""Cross-run recon cache tools: reuse an earlier run's recon instead of re-running it.

Recon (port scans, subdomain enumeration, cloud listings) is expensive and often
identical across runs against the same target. Before running such a scan, call
``recon_cache_get(target, tool)``; on a fresh hit, reuse the result instead of
spending the turns to re-run it. After running a scan, call
``recon_cache_put(target, tool, result)`` so later runs can reuse it. A cached result
is a *prior observation* with a timestamp — re-verify time-sensitive state before
acting on it.

Every tool is scope-gated: an out-of-scope target is refused when a ``scope.yaml`` is
loaded, so the cache never serves or stores recon for an unauthorized target.

The ``@function_tool`` wrappers stay thin (identity extraction + delegation) so the
plain ``_do_*`` helpers carry all the logic and are directly unit-testable. This
module omits ``from __future__ import annotations`` so the SDK resolves the
``RunContextWrapper`` context annotation at registration.
"""

import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.cache.store import (
    ReconCache,
    ReconCacheTooLargeError,
    get_recon_cache,
    recon_cache_enabled,
    reset_recon_cache,
)
from strix.scope.enforcement import enforce_target


def _cache() -> ReconCache:
    cache = get_recon_cache()
    if cache is None:  # no run bootstrap (e.g. a stray call); bind the default root now
        cache = reset_recon_cache()
    return cache


def _caller_identity(ctx: RunContextWrapper) -> tuple[str | None, str | None, str | None]:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    raw_run_id = inner.get("run_id") or inner.get("scan_id")
    run_id = raw_run_id if isinstance(raw_run_id, str) else None
    agent_name = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw = names.get(agent_id)
            agent_name = raw if isinstance(raw, str) else None
    return agent_id, agent_name, run_id


def _scope_denial(target: str) -> str | None:
    """A ready-to-return refusal JSON for an out-of-scope target, or ``None`` to allow."""
    decision = enforce_target(target)
    if decision is None:
        return None
    return json.dumps(
        {
            "success": False,
            "refused": "out_of_scope",
            "target": target,
            "reason": getattr(decision, "reason", "target is out of the authorized scope"),
        },
        ensure_ascii=False,
        default=str,
    )


def _do_recon_cache_get(target: str, tool: str, params: str, max_age_hours: float) -> str:
    if not (target or "").strip() or not (tool or "").strip():
        return json.dumps({"success": False, "error": "target and tool are required"})
    denial = _scope_denial(target)
    if denial is not None:
        return denial
    if not recon_cache_enabled():
        return json.dumps(
            {"success": True, "hit": False, "disabled": True, "note": "recon cache disabled"}
        )

    max_age = int(max_age_hours * 3600) if max_age_hours and max_age_hours > 0 else None
    entry = _cache().get(tool, target, params, max_age_seconds=max_age)
    if entry is None:
        return json.dumps({"success": True, "hit": False})
    return json.dumps(
        {
            "success": True,
            "hit": True,
            "tool": entry.tool,
            "target": entry.target,
            "cached_at": entry.created_at,
            "age_hours": round(entry.age_seconds() / 3600, 2),
            "source_run_id": entry.run_id,
            "result": entry.result,
            "note": (
                "Cached recon from a prior run. Re-verify time-sensitive state "
                "(live services, current config) before acting on it."
            ),
        },
        ensure_ascii=False,
        default=str,
    )


def _do_recon_cache_put(
    target: str,
    tool: str,
    result: str,
    ttl_hours: float,
    params: str,
    *,
    agent_id: str | None = None,
    agent_name: str | None = None,
    run_id: str | None = None,
) -> str:
    if not (target or "").strip() or not (tool or "").strip():
        return json.dumps({"success": False, "error": "target and tool are required"})
    if not (result or "").strip():
        return json.dumps({"success": False, "error": "result is empty; nothing to cache"})
    denial = _scope_denial(target)
    if denial is not None:
        return denial
    if not recon_cache_enabled():
        return json.dumps(
            {"success": True, "stored": False, "disabled": True, "note": "recon cache disabled"}
        )

    try:
        entry = _cache().put(
            tool,
            target,
            result,
            params=params,
            ttl_seconds=max(1, int(ttl_hours * 3600)),
            run_id=run_id,
            agent_id=agent_id,
            agent_name=agent_name,
        )
    except ReconCacheTooLargeError as exc:
        return json.dumps({"success": False, "error": str(exc)}, ensure_ascii=False)

    payload: dict[str, Any] = {
        "success": True,
        "stored": True,
        "key": entry.key,
        "size_bytes": entry.size_bytes,
        "expires_in_hours": round(entry.ttl_seconds / 3600, 2),
    }
    return json.dumps(payload, ensure_ascii=False, default=str)


def _do_recon_cache_stats() -> str:
    stats = _cache().stats()
    stats["success"] = True
    stats["enabled"] = recon_cache_enabled()
    return json.dumps(stats, ensure_ascii=False, default=str)


@function_tool(timeout=20)
async def recon_cache_get(
    ctx: RunContextWrapper,
    target: str,
    tool: str,
    params: str = "",
    max_age_hours: float = 0.0,
) -> str:
    """Look up cached recon for a target before running an expensive scan yourself.

    On a fresh hit this returns a prior run's recon output so you can reuse it instead
    of re-running the scan. Treat it as a prior observation: re-verify any
    time-sensitive state (live ports/services, current cloud config) before acting on
    it. On a miss, run the recon and then store it with ``recon_cache_put``.

    Args:
        target: The scanned asset — a URL, hostname, IP/CIDR, bucket, account, or ARN.
        tool: The recon tool/source (e.g. ``nmap``, ``naabu``, ``subfinder``,
            ``httpx``, ``prowler``). Keep it consistent so lookups match stores.
        params: Optional scan parameters that change the result (e.g. ``-p-`` vs top
            ports). Part of the cache key, so pass the same value on get and put.
        max_age_hours: Optional stricter freshness bound (hours). 0 = use the entry's
            own TTL. Set it lower when you need recent recon.
    """
    del ctx
    return _do_recon_cache_get(target, tool, params, max_age_hours)


@function_tool(timeout=20)
async def recon_cache_put(
    ctx: RunContextWrapper,
    target: str,
    tool: str,
    result: str,
    ttl_hours: float = 24.0,
    params: str = "",
) -> str:
    """Store a recon result so later runs can reuse it instead of re-running the scan.

    Call this right after a recon scan completes. Store the raw tool output (or a
    faithful summary) — not a truncated fragment, since a later run may rely on it.
    Large results (> 1 MiB) are rejected; summarize first.

    Args:
        target: The scanned asset — a URL, hostname, IP/CIDR, bucket, account, or ARN.
        tool: The recon tool/source (match what you pass to ``recon_cache_get``).
        result: The recon output to cache.
        ttl_hours: How long the result stays reusable before it is considered stale
            (default 24).
        params: Optional scan parameters that change the result (part of the key).
    """
    agent_id, agent_name, run_id = _caller_identity(ctx)
    return _do_recon_cache_put(
        target,
        tool,
        result,
        ttl_hours,
        params,
        agent_id=agent_id,
        agent_name=agent_name,
        run_id=run_id,
    )


@function_tool(timeout=15)
async def recon_cache_stats(ctx: RunContextWrapper) -> str:
    """Summarize the cross-run recon cache (entry count, total size, root, enabled)."""
    del ctx
    return _do_recon_cache_stats()
