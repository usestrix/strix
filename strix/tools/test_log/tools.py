"""Per-run endpoint test memory — mirrored to {state_dir}/test_log.json.

Tracks which endpoints have been tested for which vulnerability classes,
which payloads were tried, and what the outcome was. Persists across
``--resume`` so spawned agents don't re-test ground other agents already
covered.

Shape on disk::

    {
      "entries": {
        "<entry_id>": {
          "endpoint": "GET /api/v2/orders/{id}",
          "vuln_class": "idor",
          "payloads": ["id=123 -> 200 victim data", ...],
          "outcome": "vulnerable" | "not_vulnerable" | "needs_more_testing",
          "agent_id": "<agent_id_that_recorded>",
          "agent_name": "IDOR Agent",
          "notes": "...",
          "tags": ["auth", "production"],
          "created_at": "...",
          "updated_at": "..."
        }
      },
      "by_endpoint": { "<endpoint>": ["<entry_id>", ...] }
    }
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


_VALID_OUTCOMES = {
    "vulnerable",
    "not_vulnerable",
    "needs_more_testing",
    "inconclusive",
    "blocked",
}

_VALID_VULN_CLASSES = {
    "idor",
    "ssrf",
    "xss",
    "sqli",
    "rce",
    "lfi",
    "rfi",
    "xxe",
    "ssti",
    "auth_bypass",
    "broken_access_control",
    "csrf",
    "open_redirect",
    "file_upload",
    "race_condition",
    "business_logic",
    "mass_assignment",
    "nosql_injection",
    "header_injection",
    "http_smuggling",
    "cache_poison",
    "subdomain_takeover",
    "info_disclosure",
    "secrets_exposure",
    "graphql",
    "oauth",
    "saml",
    "mfa_bypass",
    "prototype_pollution",
    "other",
}


_storage: dict[str, dict[str, Any]] = {"entries": {}, "by_endpoint": {}}
_lock = threading.RLock()
_path: Path | None = None


def hydrate_test_log_from_disk(state_dir: Path) -> None:
    global _path  # noqa: PLW0603
    _path = state_dir / "test_log.json"
    with _lock:
        _storage["entries"] = {}
        _storage["by_endpoint"] = {}
        if not _path.exists():
            return
        try:
            data = json.loads(_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "test_log.json at %s is unreadable; starting empty",
                _path,
            )
            return
        if not isinstance(data, dict):
            return
        entries = data.get("entries")
        if isinstance(entries, dict):
            _storage["entries"] = {
                eid: e
                for eid, e in entries.items()
                if isinstance(eid, str) and isinstance(e, dict)
            }
        by_endpoint = data.get("by_endpoint")
        if isinstance(by_endpoint, dict):
            _storage["by_endpoint"] = {
                ep: list(ids)
                for ep, ids in by_endpoint.items()
                if isinstance(ep, str) and isinstance(ids, list)
            }
        else:
            for eid, entry in _storage["entries"].items():
                ep = entry.get("endpoint")
                if isinstance(ep, str):
                    _storage["by_endpoint"].setdefault(ep, []).append(eid)
        logger.info(
            "test_log hydrated from %s (%d entries)",
            _path,
            len(_storage["entries"]),
        )


def _persist() -> None:
    path = _path
    if path is None:
        return
    try:
        payload = json.dumps(_storage, ensure_ascii=False, default=str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with (
            _lock,
            tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(path.parent),
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp,
        ):
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except Exception:
        logger.exception("test_log persist to %s failed", path)


def _agent_meta_from(ctx: RunContextWrapper) -> tuple[str, str]:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    agent_id = str(inner.get("agent_id") or "unknown")
    agent_name = str(inner.get("agent_name") or agent_id)
    return agent_id, agent_name


def _normalize_endpoint(endpoint: str) -> str:
    return endpoint.strip()


def _record_test_impl(
    endpoint: str,
    vuln_class: str,
    outcome: str,
    payloads: list[str] | None,
    notes: str,
    tags: list[str] | None,
    agent_id: str,
    agent_name: str,
) -> dict[str, Any]:
    with _lock:
        if not endpoint or not endpoint.strip():
            return {"success": False, "error": "endpoint cannot be empty"}
        vc = vuln_class.strip().lower()
        if vc not in _VALID_VULN_CLASSES:
            return {
                "success": False,
                "error": (
                    f"unknown vuln_class '{vuln_class}'. valid: "
                    f"{sorted(_VALID_VULN_CLASSES)}"
                ),
            }
        oc = outcome.strip().lower()
        if oc not in _VALID_OUTCOMES:
            return {
                "success": False,
                "error": (
                    f"unknown outcome '{outcome}'. valid: {sorted(_VALID_OUTCOMES)}"
                ),
            }

        ep = _normalize_endpoint(endpoint)
        timestamp = datetime.now(UTC).isoformat()

        existing_id: str | None = None
        for eid in _storage["by_endpoint"].get(ep, []):
            entry = _storage["entries"].get(eid)
            if entry and entry.get("vuln_class") == vc:
                existing_id = eid
                break

        if existing_id is not None:
            entry = _storage["entries"][existing_id]
            if payloads:
                merged = list(entry.get("payloads") or [])
                for p in payloads:
                    if p and p not in merged:
                        merged.append(p)
                entry["payloads"] = merged
            if notes:
                prior = entry.get("notes") or ""
                if notes not in prior:
                    entry["notes"] = (prior + "\n" + notes).strip() if prior else notes
            if tags:
                merged_tags = list(entry.get("tags") or [])
                for t in tags:
                    if t and t not in merged_tags:
                        merged_tags.append(t)
                entry["tags"] = merged_tags
            entry["outcome"] = oc
            entry["updated_at"] = timestamp
            entry.setdefault("agent_history", []).append(
                {"agent_id": agent_id, "agent_name": agent_name, "at": timestamp}
            )
            _persist()
            return {
                "success": True,
                "entry_id": existing_id,
                "merged": True,
                "endpoint": ep,
                "vuln_class": vc,
                "outcome": oc,
                "total_entries": len(_storage["entries"]),
            }

        entry_id = uuid.uuid4().hex[:8]
        entry = {
            "endpoint": ep,
            "vuln_class": vc,
            "payloads": list(payloads or []),
            "outcome": oc,
            "notes": notes or "",
            "tags": list(tags or []),
            "agent_id": agent_id,
            "agent_name": agent_name,
            "agent_history": [
                {"agent_id": agent_id, "agent_name": agent_name, "at": timestamp}
            ],
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        _storage["entries"][entry_id] = entry
        _storage["by_endpoint"].setdefault(ep, []).append(entry_id)
        _persist()
        return {
            "success": True,
            "entry_id": entry_id,
            "merged": False,
            "endpoint": ep,
            "vuln_class": vc,
            "outcome": oc,
            "total_entries": len(_storage["entries"]),
        }


def _query_tests_impl(
    endpoint: str | None,
    vuln_class: str | None,
    outcome: str | None,
    agent_id: str | None,
    tag: str | None,
    limit: int,
) -> dict[str, Any]:
    with _lock:
        results: list[dict[str, Any]] = []
        ep_norm = _normalize_endpoint(endpoint) if endpoint else None
        vc_norm = vuln_class.strip().lower() if vuln_class else None
        oc_norm = outcome.strip().lower() if outcome else None

        for eid, entry in _storage["entries"].items():
            if ep_norm and ep_norm not in entry.get("endpoint", ""):
                continue
            if vc_norm and entry.get("vuln_class") != vc_norm:
                continue
            if oc_norm and entry.get("outcome") != oc_norm:
                continue
            if agent_id and entry.get("agent_id") != agent_id:
                continue
            if tag and tag not in (entry.get("tags") or []):
                continue
            results.append({"entry_id": eid, **entry})

        results.sort(key=lambda r: r.get("updated_at", ""), reverse=True)
        truncated = len(results) > limit
        return {
            "success": True,
            "entries": results[:limit],
            "returned": min(len(results), limit),
            "matched": len(results),
            "total_in_log": len(_storage["entries"]),
            "truncated": truncated,
        }


def _summary_impl() -> dict[str, Any]:
    with _lock:
        by_class: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        for entry in _storage["entries"].values():
            by_class[entry.get("vuln_class", "?")] = (
                by_class.get(entry.get("vuln_class", "?"), 0) + 1
            )
            by_outcome[entry.get("outcome", "?")] = (
                by_outcome.get(entry.get("outcome", "?"), 0) + 1
            )
        return {
            "success": True,
            "total_entries": len(_storage["entries"]),
            "unique_endpoints": len(_storage["by_endpoint"]),
            "by_vuln_class": by_class,
            "by_outcome": by_outcome,
        }


@function_tool(timeout=30)
async def record_test(
    ctx: RunContextWrapper,
    endpoint: str,
    vuln_class: str,
    outcome: str,
    payloads: list[str] | None = None,
    notes: str = "",
    tags: list[str] | None = None,
) -> str:
    """Record that you tested an endpoint for a vulnerability class.

    Call this **after every meaningful test attempt** so other agents
    (and this same agent after a ``--resume``) can see what's already
    been covered and skip duplicate work.

    If an entry for the same ``endpoint`` + ``vuln_class`` already
    exists, this **merges** into it: payloads and tags are
    de-duplicated and appended, notes are concatenated, and ``outcome``
    is overwritten with the new value (so re-testing can promote
    ``needs_more_testing`` to ``vulnerable``).

    Args:
        endpoint: Canonical request identifier. Prefer
            ``"METHOD /path"`` (e.g. ``"GET /api/v2/orders/{id}"``).
            Keep path-param shapes (``{id}``) instead of concrete
            values so the entry de-duplicates across IDs.
        vuln_class: One of the supported classes (``idor``, ``ssrf``,
            ``xss``, ``sqli``, ``rce``, ``lfi``, ``rfi``, ``xxe``,
            ``ssti``, ``auth_bypass``, ``broken_access_control``,
            ``csrf``, ``open_redirect``, ``file_upload``,
            ``race_condition``, ``business_logic``,
            ``mass_assignment``, ``nosql_injection``,
            ``header_injection``, ``http_smuggling``,
            ``cache_poison``, ``subdomain_takeover``,
            ``info_disclosure``, ``secrets_exposure``, ``graphql``,
            ``oauth``, ``saml``, ``mfa_bypass``,
            ``prototype_pollution``, ``other``).
        outcome: One of ``vulnerable``, ``not_vulnerable``,
            ``needs_more_testing``, ``inconclusive``, ``blocked``.
        payloads: Short list of payload summaries you actually sent,
            each ideally one line including the response signal
            (``"id=2 -> 200 victim PII returned"``). Skip raw
            multi-line HTTP — keep it scannable.
        notes: Free-form notes that the next agent would benefit from
            (auth required, WAF behavior, rate limit observed, etc.).
        tags: Free-form tags for later filtering
            (e.g. ``["auth", "production", "v2-api"]``).
    """
    agent_id, agent_name = _agent_meta_from(ctx)
    return json.dumps(
        await asyncio.to_thread(
            _record_test_impl,
            endpoint,
            vuln_class,
            outcome,
            payloads,
            notes,
            tags,
            agent_id,
            agent_name,
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def query_tests(
    ctx: RunContextWrapper,
    endpoint: str | None = None,
    vuln_class: str | None = None,
    outcome: str | None = None,
    agent_id: str | None = None,
    tag: str | None = None,
    limit: int = 50,
) -> str:
    """Look up prior test attempts before spending time re-testing.

    Call this **before** any vulnerability testing on an endpoint —
    another agent (or yourself in a prior run) may have already covered
    the same surface. Filters compose with AND semantics.

    Args:
        endpoint: Substring match against recorded endpoint strings
            (e.g. ``"/api/v2/orders"`` matches
            ``"GET /api/v2/orders/{id}"``).
        vuln_class: Exact match against vuln class.
        outcome: Exact match against outcome.
        agent_id: Filter to a specific recording agent.
        tag: Match entries that include this tag.
        limit: Cap on returned entries (default 50).
    """
    return json.dumps(
        await asyncio.to_thread(
            _query_tests_impl,
            endpoint,
            vuln_class,
            outcome,
            agent_id,
            tag,
            max(1, min(limit, 500)),
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def test_log_summary(ctx: RunContextWrapper) -> str:
    """Coverage snapshot: how many endpoints have been tested, broken
    down by vuln class and outcome. Useful for the root agent to decide
    where to spawn the next specialist."""
    return json.dumps(
        await asyncio.to_thread(_summary_impl),
        ensure_ascii=False,
        default=str,
    )
