"""Per-run recon ledger — mirrored to {state_dir}/recon_ledger.json.

Recon agents discover far more routes than they can hand off cleanly:
an admin API found while crawling one host, a parameter noticed in a JS
bundle, an endpoint pulled out of an OpenAPI spec buried in a build
artifact. Today that knowledge only survives in the discovering agent's
own conversation, or gets folded into a note or the threat model as
prose. Neither is queryable: a later agent hunting for "does anything
handle DELETE on this resource" has to re-read a wall of text, or more
often just re-discovers the route itself by probing for it — burning
requests on paths recon already confirmed or ruled out.

This ledger gives discovered endpoints the same treatment
``strix.tools.coverage`` gives review coverage: a structured,
deduplicated, shared record that any agent can query by method, path,
or auth requirement instead of re-reading prose or re-guessing at the
attack surface. Record a route here as soon as you find it; look here
before you spend requests hunting for one yourself.

Entries are **agent-reported**: an agent's own account of what it
found and what it believes about it (e.g. whether auth is required).
Nothing here is independently verified by the ledger itself — that is
why a duplicate is rejected rather than overwritten: two agents can
form different conclusions about the same route, and silently
replacing one with the other would hide the disagreement instead of
surfacing it for reconciliation via ``update_endpoint``.
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

from strix.tools.nullish import clean_optional


logger = logging.getLogger(__name__)


_recon_ledger_storage: dict[str, dict[str, Any]] = {}
_recon_ledger_lock = threading.RLock()
_recon_ledger_path: Path | None = None
_ENTRY_ID_GENERATION_ATTEMPTS = 1024
_NOTES_PREVIEW_CHARS = 240

VALID_METHODS: tuple[str, ...] = (
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "OTHER",
)


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


def _generate_entry_id() -> str | None:
    """Allocate an unused entry id. Callers must already hold ``_recon_ledger_lock``."""
    for _ in range(_ENTRY_ID_GENERATION_ATTEMPTS):
        entry_id = uuid.uuid4().hex[:6]
        if entry_id not in _recon_ledger_storage:
            return entry_id
    return None


def hydrate_recon_ledger_from_disk(state_dir: Path) -> None:
    global _recon_ledger_path  # noqa: PLW0603
    _recon_ledger_path = state_dir / "recon_ledger.json"
    with _recon_ledger_lock:
        _recon_ledger_storage.clear()
        if not _recon_ledger_path.exists():
            return
        try:
            data = json.loads(_recon_ledger_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "recon_ledger.json at %s is unreadable; starting with an empty ledger",
                _recon_ledger_path,
            )
            return
        if not isinstance(data, dict):
            return
        _recon_ledger_storage.update(
            {
                eid: entry
                for eid, entry in data.items()
                if isinstance(eid, str) and isinstance(entry, dict)
            }
        )
        logger.info(
            "recon ledger hydrated from %s (%d entr(ies))",
            _recon_ledger_path,
            len(_recon_ledger_storage),
        )


def _persist_locked() -> None:
    """Mirror the ledger to disk. Callers must already hold ``_recon_ledger_lock``.

    Serialization and the rename happen in one critical section. Releasing
    the lock in between would let a writer holding an older serialization win
    the rename and silently roll back a concurrent agent's entry, so the
    ledger would hydrate short on resume.
    """
    path = _recon_ledger_path
    if path is None:
        return
    try:
        payload = json.dumps(_recon_ledger_storage, ensure_ascii=False, default=str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except Exception:
        logger.exception("recon ledger persist to %s failed", path)


def get_recon_ledger_entries() -> list[dict[str, Any]]:
    """Return every recon ledger entry, newest last."""
    with _recon_ledger_lock:
        entries = [{**entry, "entry_id": eid} for eid, entry in _recon_ledger_storage.items()]
    entries.sort(key=lambda e: str(e.get("created_at", "")))
    return entries


def _normalize_method(method: str) -> str:
    normalized = method.strip().upper()
    if normalized in VALID_METHODS:
        return normalized
    return "OTHER" if normalized else ""


def _validate(*, method: str, path: str) -> tuple[str, list[str]]:
    errors: list[str] = []
    normalized_method = _normalize_method(method)
    if not method.strip():
        errors.append("method cannot be empty - e.g. GET, POST, PUT, PATCH, DELETE")
    if not path.strip():
        errors.append("path cannot be empty - name the endpoint or route, e.g. '/api/orders/{id}'")
    return normalized_method, errors


def _duplicate_of_locked(method: str, path: str) -> tuple[str, dict[str, Any]] | None:
    """Find an existing row for this exact method and path.

    Callers must already hold ``_recon_ledger_lock``. The uniqueness check
    and the insertion that depends on it have to be one critical section:
    otherwise two agents recording the same route concurrently both see "no
    duplicate", and the ledger ends up with exactly the parallel rows this
    rejection exists to prevent.
    """
    key = (method.strip().upper(), path.strip().lower())
    for entry_id, entry in _recon_ledger_storage.items():
        existing = (
            str(entry.get("method", "")).strip().upper(),
            str(entry.get("path", "")).strip().lower(),
        )
        if existing == key:
            return entry_id, dict(entry)
    return None


def _record_impl(
    *,
    method: str,
    path: str,
    params: str,
    auth_required: bool | None,
    technology: str,
    notes: str,
    source: str,
    agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    normalized_method, errors = _validate(method=method, path=path)
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    entry: dict[str, Any] = {
        "method": normalized_method,
        "path": path.strip(),
        "created_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    if params.strip():
        entry["params"] = params.strip()
    if auth_required is not None:
        entry["auth_required"] = auth_required
    if technology.strip():
        entry["technology"] = technology.strip()
    if notes.strip():
        entry["notes"] = notes.strip()
    if source.strip():
        entry["source"] = source.strip()
    if agent_id:
        entry["agent_id"] = agent_id
    if agent_name:
        entry["agent_name"] = agent_name

    with _recon_ledger_lock:
        duplicate = _duplicate_of_locked(normalized_method, path)
        if duplicate is not None:
            existing_id, existing = duplicate
            owner = existing.get("agent_name") or "another agent"
            return {
                "success": False,
                "error": (
                    f"'{normalized_method} {path.strip()}' already has recon ledger entry "
                    f"{existing_id}, recorded by {owner}. Two rows for one route leave the "
                    "ledger showing a stale conclusion beside its replacement (for example, "
                    "two different answers to whether auth is required). If your discovery "
                    "adds or corrects information - such as the auth requirement, technology, "
                    "or parameters - move that entry with "
                    f"update_endpoint(entry_id='{existing_id}', ...) instead. If you found a "
                    "genuinely different route, check the method and path are exact."
                ),
                "existing_entry_id": existing_id,
            }

        entry_id = _generate_entry_id()
        if entry_id is None:
            return {"success": False, "error": "Could not allocate a recon ledger entry id"}
        _recon_ledger_storage[entry_id] = entry
        _persist_locked()
    logger.info(
        "Recon ledger entry recorded: id=%s method=%s path=%s",
        entry_id,
        normalized_method,
        entry["path"],
    )
    return {
        "success": True,
        "entry_id": entry_id,
        "message": f"Recorded {normalized_method} {entry['path']}",
    }


def _apply_string_field(existing: dict[str, Any], field: str, value: str | None) -> bool:
    """Set or clear a free-text field on ``existing``. Returns whether it changed."""
    if value is None:
        return False
    if value.strip():
        existing[field] = value.strip()
    else:
        existing.pop(field, None)
    return True


def _update_impl(
    *,
    entry_id: str,
    params: str | None,
    auth_required: bool | None,
    technology: str | None,
    notes: str | None,
    source: str | None,
    agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    key = (entry_id or "").strip()
    with _recon_ledger_lock:
        existing = _recon_ledger_storage.get(key)
        if existing is None:
            return {
                "success": False,
                "error": (
                    f"No recon ledger entry {entry_id!r}. Call list_endpoints to find the "
                    "entry you mean - filter by path if you only know the route."
                ),
            }
        previous: dict[str, Any] = {
            "recorded_at": existing.get("updated_at", existing.get("created_at", "")),
        }
        for field in ("params", "auth_required", "technology", "notes", "source"):
            if field in existing:
                previous[field] = existing[field]
        if existing.get("agent_name"):
            previous["agent_name"] = existing["agent_name"]

        changed = any(
            [
                _apply_string_field(existing, "params", params),
                _apply_string_field(existing, "technology", technology),
                _apply_string_field(existing, "notes", notes),
                _apply_string_field(existing, "source", source),
            ]
        )
        if auth_required is not None:
            existing["auth_required"] = auth_required
            changed = True

        if not changed:
            return {
                "success": False,
                "error": (
                    "No fields to update - pass at least one of params, auth_required, "
                    "technology, notes, or source."
                ),
            }

        history = existing.get("history")
        existing["history"] = [*history, previous] if isinstance(history, list) else [previous]
        existing["updated_at"] = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        if agent_id:
            existing["agent_id"] = agent_id
        if agent_name:
            existing["agent_name"] = agent_name
        _persist_locked()
    logger.info(
        "Recon ledger entry updated: id=%s method=%s path=%s",
        key,
        existing["method"],
        existing["path"],
    )
    message = f"Updated {existing['method']} {existing['path']}. Previous state kept as history."
    return {"success": True, "entry_id": key, "message": message}


def _list_impl(
    *,
    method: str | None,
    path_contains: str | None,
    auth_required: bool | None,
    caller_agent_id: str | None,
) -> dict[str, Any]:
    normalized_method: str | None = None
    if method and method.strip():
        normalized_method = method.strip().upper()
        if normalized_method not in VALID_METHODS:
            return {
                "success": False,
                "error": f"Invalid method: {method!r}. Must be one of: {list(VALID_METHODS)}",
            }

    path_contains = clean_optional(path_contains)

    entries: list[dict[str, Any]] = []
    for entry in get_recon_ledger_entries():
        if normalized_method and entry.get("method") != normalized_method:
            continue
        if path_contains and path_contains.lower() not in str(entry.get("path", "")).lower():
            continue
        if auth_required is not None and entry.get("auth_required") != auth_required:
            continue
        listing = {
            "entry_id": entry.get("entry_id"),
            "method": entry.get("method", ""),
            "path": entry.get("path", ""),
            "created_at": entry.get("created_at", ""),
        }
        for field in ("params", "auth_required", "technology", "source"):
            if field in entry:
                listing[field] = entry[field]
        notes = str(entry.get("notes", ""))
        if notes:
            listing["notes"] = (
                f"{notes[:_NOTES_PREVIEW_CHARS].rstrip()}..."
                if len(notes) > _NOTES_PREVIEW_CHARS
                else notes
            )
        agent_name = entry.get("agent_name")
        if agent_name:
            listing["agent_name"] = agent_name
        history = entry.get("history")
        if isinstance(history, list) and history:
            listing["revision_count"] = len(history)
        if caller_agent_id is not None and entry.get("agent_id") == caller_agent_id:
            listing["by_you"] = True
        entries.append(listing)

    return {
        "success": True,
        "entries": entries,
        "filtered_count": len(entries),
        "total_count": len(_recon_ledger_storage),
    }


@function_tool(timeout=30)
async def record_endpoint(
    ctx: RunContextWrapper,
    method: str,
    path: str,
    params: str = "",
    auth_required: bool | None = None,
    technology: str = "",
    notes: str = "",
    source: str = "",
) -> str:
    """Record a discovered endpoint, route, or parameter in the shared recon ledger.

    Recon turns up far more routes than fit cleanly into a note or the
    threat model, and folding them into prose makes them useless to
    every other agent - a later agent hunting for "does anything handle
    DELETE on this resource" has to re-read a wall of text, or more
    often just re-probes for the route itself. That is expensive: it
    burns requests re-discovering (or 404-ing on) attack surface recon
    already resolved. Use this tool instead of ``create_note`` whenever
    you find something a later agent should be able to query
    structurally: an endpoint, a route, or a parameter.

    Record entries as you go, not in a batch at the end. Entries are
    shared across every agent in the scan; vulnerability-testing agents
    should call ``list_endpoints`` before spending requests guessing at
    routes themselves.

    The ledger is not append-only: if this exact method and path
    already have an entry - yours or another agent's - this call is
    rejected and returns that entry's id, because two rows for one
    route leave the ledger showing a stale conclusion beside its
    replacement (most importantly, two different answers to whether
    auth is required). If you learned something new about an existing
    route, call ``update_endpoint`` on the id it hands you instead.

    Args:
        method: The HTTP method, e.g. ``GET``, ``POST``, ``PUT``,
            ``PATCH``, ``DELETE``, ``HEAD``, ``OPTIONS``. Anything else
            (e.g. a non-HTTP RPC/WebSocket route) is recorded as
            ``OTHER`` - say the real protocol in ``notes``.
        path: The route or endpoint path, e.g.
            ``"/api/orders/{id}"``. Use the templated form with named
            path parameters rather than one entry per concrete id.
        params: Known query/body/path parameters, free-form, e.g.
            ``"id (path), page, filter[status]"``.
        auth_required: Whether this route requires authentication, if
            known. Leave ``None`` when you have not established this -
            do not guess ``False`` just because you reached it
            unauthenticated once; a route can look reachable and still
            enforce checks deeper in the handler.
        technology: Framework, language, or server this route runs on,
            if known (e.g. ``"Express"``, ``"Django REST"``).
        notes: Anything else worth recording - how you found it,
            response shape, unusual behavior.
        source: Where this was discovered, e.g. ``"JS bundle"``,
            ``"OpenAPI spec"``, ``"crawl"``, ``"source code"``.
    """
    agent_id, agent_name = _caller_identity(ctx)
    result = await asyncio.to_thread(
        _record_impl,
        method=method,
        path=path,
        params=params,
        auth_required=auth_required,
        technology=technology,
        notes=notes,
        source=source,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def update_endpoint(
    ctx: RunContextWrapper,
    entry_id: str,
    params: str | None = None,
    auth_required: bool | None = None,
    technology: str | None = None,
    notes: str | None = None,
    source: str | None = None,
) -> str:
    """Change what is known about an already-recorded endpoint.

    The recon ledger is shared across the whole agent tree, and what is
    known about a route is not final when it is first written. Use
    this whenever later work adds to or corrects an existing entry:

    - You confirmed (or ruled out) that a route recorded with
      ``auth_required=None`` actually requires authentication.
    - You found additional parameters, or the real technology behind
      the route.
    - An earlier agent's auth conclusion turns out to be wrong -
      overwrite it here rather than leaving both a wrong and a right
      answer sitting in the ledger.

    The method and path stay fixed - this is the same route, with
    updated information. Do not record a fresh entry for a route that
    already has one; that leaves a stale entry next to its correction.
    Find the id with ``list_endpoints`` (filter by ``path_contains``),
    then update it.

    Pass ``None`` (the default) for any field you are not changing.
    The previous values of any field you do change are kept as
    history, so the ledger still shows what used to be believed about
    the route and who recorded it.

    Args:
        entry_id: The id of the entry to update, from
            ``list_endpoints`` or ``record_endpoint``.
        params: New parameter info, or ``None`` to leave unchanged.
            Pass ``""`` to clear it.
        auth_required: New auth requirement, or ``None`` to leave
            unchanged - note that ``None`` here means "don't touch
            this field", not "auth not required".
        technology: New technology, or ``None`` to leave unchanged.
            Pass ``""`` to clear it.
        notes: New notes, or ``None`` to leave unchanged. Pass ``""``
            to clear it.
        source: New source, or ``None`` to leave unchanged. Pass
            ``""`` to clear it.
    """
    agent_id, agent_name = _caller_identity(ctx)
    result = await asyncio.to_thread(
        _update_impl,
        entry_id=entry_id,
        params=params,
        auth_required=auth_required,
        technology=technology,
        notes=notes,
        source=source,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def list_endpoints(
    ctx: RunContextWrapper,
    method: str | None = None,
    path_contains: str | None = None,
    auth_required: bool | None = None,
) -> str:
    """List discovered endpoints recorded so far in this scan.

    **Call this before probing for routes yourself.** Recon agents
    record what they find here; re-discovering it by brute-forcing or
    guessing paths wastes requests on 404s for routes that are already
    known. Vulnerability-testing agents should check here first, then
    fall back to their own discovery only for gaps the ledger does not
    cover.

    Returns each entry with its ``method``, ``path``, known ``params``,
    ``auth_required``, ``technology``, ``source``, and the agent that
    recorded it.

    Args:
        method: Optional filter - one of ``GET`` / ``POST`` / ``PUT`` /
            ``PATCH`` / ``DELETE`` / ``HEAD`` / ``OPTIONS`` / ``OTHER``.
        path_contains: Optional case-insensitive substring filter on
            the path, e.g. ``"orders"``.
        auth_required: Optional filter - ``True`` for routes known to
            require auth, ``False`` for routes confirmed not to.
            Leave unset to include routes where this is unknown.
    """
    caller_agent_id, _ = _caller_identity(ctx)
    result = await asyncio.to_thread(
        _list_impl,
        method=method,
        path_contains=path_contains,
        auth_required=auth_required,
        caller_agent_id=caller_agent_id,
    )
    return json.dumps(result, ensure_ascii=False, default=str)
