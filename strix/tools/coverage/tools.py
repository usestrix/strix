"""Per-run coverage ledger — mirrored to {state_dir}/coverage.json.

Findings answer "what did we find". Coverage answers "what did we look at,
and how did each one close" — the negative space a client report needs in
order to be trustworthy. Every agent records the surfaces it reviewed; the
root agent reconciles them at the end of the scan.

Entries here are **agent-reported**: an agent's own account of what it
assessed. ``strix.report.coverage`` pairs them with machine-observed facts
(which agents ran, which skills they carried, how the run terminated) and
labels the provenance of each, so a reader can tell a self-report from an
observation. The runtime mirror under ``{state_dir}`` exists for resume; the
client-facing artifact is ``{run_dir}/coverage.json``.
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


_coverage_storage: dict[str, dict[str, Any]] = {}
_coverage_lock = threading.RLock()
_coverage_path: Path | None = None
_ENTRY_ID_GENERATION_ATTEMPTS = 1024
_EVIDENCE_PREVIEW_CHARS = 240

VALID_OUTCOMES: tuple[str, ...] = (
    "reported",
    "no_issue_found",
    "ruled_out",
    "not_applicable",
    "needs_follow_up",
)

_OUTCOMES_REQUIRING_EVIDENCE = frozenset({"ruled_out", "not_applicable", "needs_follow_up"})


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
    """Allocate an unused entry id. Callers must already hold ``_coverage_lock``."""
    for _ in range(_ENTRY_ID_GENERATION_ATTEMPTS):
        entry_id = uuid.uuid4().hex[:6]
        if entry_id not in _coverage_storage:
            return entry_id
    return None


def hydrate_coverage_from_disk(state_dir: Path) -> None:
    global _coverage_path  # noqa: PLW0603
    _coverage_path = state_dir / "coverage.json"
    with _coverage_lock:
        _coverage_storage.clear()
        if not _coverage_path.exists():
            return
        try:
            data = json.loads(_coverage_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "coverage.json at %s is unreadable; starting with empty coverage",
                _coverage_path,
            )
            return
        if not isinstance(data, dict):
            return
        _coverage_storage.update(
            {
                eid: entry
                for eid, entry in data.items()
                if isinstance(eid, str) and isinstance(entry, dict)
            }
        )
        logger.info(
            "coverage hydrated from %s (%d entr(ies))",
            _coverage_path,
            len(_coverage_storage),
        )


def _persist_locked() -> None:
    """Mirror the ledger to disk. Callers must already hold ``_coverage_lock``.

    Serialization and the rename happen in one critical section. Releasing
    the lock in between would let a writer holding an older serialization win
    the rename and silently roll back a concurrent agent's entry, so the
    ledger would hydrate short on resume.
    """
    path = _coverage_path
    if path is None:
        return
    try:
        payload = json.dumps(_coverage_storage, ensure_ascii=False, default=str)
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
        logger.exception("coverage persist to %s failed", path)


def get_coverage_entries() -> list[dict[str, Any]]:
    """Return every coverage entry, newest last. Used by ``finish_scan``."""
    with _coverage_lock:
        entries = [{**entry, "entry_id": eid} for eid, entry in _coverage_storage.items()]
    entries.sort(key=lambda e: str(e.get("created_at", "")))
    return entries


def outcome_counts() -> dict[str, int]:
    """Count coverage entries per outcome, in the canonical outcome order."""
    counts: dict[str, int] = {}
    for entry in get_coverage_entries():
        outcome = str(entry.get("outcome", "")).lower()
        counts[outcome] = counts.get(outcome, 0) + 1
    return {o: counts[o] for o in VALID_OUTCOMES if o in counts}


def _validate(
    *, surface: str, risk_area: str, outcome: str, evidence: str
) -> tuple[str, list[str]]:
    errors: list[str] = []
    if not surface.strip():
        errors.append("surface cannot be empty - name the endpoint, route, file, or component")
    if not risk_area.strip():
        errors.append("risk_area cannot be empty - name what you were testing for")
    normalized = outcome.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized not in VALID_OUTCOMES:
        errors.append(f"Invalid outcome: {outcome!r}. Must be one of: {list(VALID_OUTCOMES)}")
    elif normalized in _OUTCOMES_REQUIRING_EVIDENCE and not evidence.strip():
        errors.append(
            f"evidence is required for outcome '{normalized}' - name the specific control, "
            "the reason it does not apply, or what is still missing"
        )
    return normalized, errors


def _duplicate_of_locked(surface: str, risk_area: str) -> tuple[str, dict[str, Any]] | None:
    """Find an existing row for this exact surface and risk area.

    Callers must already hold ``_coverage_lock``. The uniqueness check and the
    insertion that depends on it have to be one critical section: otherwise
    two agents recording the same surface concurrently both see "no
    duplicate", and the ledger ends up with exactly the parallel rows this
    rejection exists to prevent.
    """
    key = (surface.strip().lower(), risk_area.strip().lower())
    for entry_id, entry in _coverage_storage.items():
        existing = (
            str(entry.get("surface", "")).strip().lower(),
            str(entry.get("risk_area", "")).strip().lower(),
        )
        if existing == key:
            return entry_id, dict(entry)
    return None


def _record_impl(
    *,
    surface: str,
    risk_area: str,
    outcome: str,
    evidence: str,
    agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    normalized, errors = _validate(
        surface=surface, risk_area=risk_area, outcome=outcome, evidence=evidence
    )
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    entry: dict[str, Any] = {
        "surface": surface.strip(),
        "risk_area": risk_area.strip(),
        "outcome": normalized,
        "created_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    if evidence.strip():
        entry["evidence"] = evidence.strip()
    if agent_id:
        entry["agent_id"] = agent_id
    if agent_name:
        entry["agent_name"] = agent_name

    with _coverage_lock:
        duplicate = _duplicate_of_locked(surface, risk_area)
        if duplicate is not None:
            existing_id, existing = duplicate
            owner = existing.get("agent_name") or "another agent"
            return {
                "success": False,
                "error": (
                    f"'{surface.strip()}' ({risk_area.strip()}) already has coverage entry "
                    f"{existing_id}, recorded by {owner} as "
                    f"'{existing.get('outcome', '')}'. Two rows for one surface leave the "
                    "report showing a stale conclusion beside its replacement. If your "
                    "review reached a different conclusion, move that entry with "
                    f"update_coverage(entry_id='{existing_id}', ...) and say in evidence "
                    "what changed. If you reviewed something genuinely different, name the "
                    "surface or risk area more precisely and record it again."
                ),
                "existing_entry_id": existing_id,
                "existing_outcome": existing.get("outcome", ""),
            }

        entry_id = _generate_entry_id()
        if entry_id is None:
            return {"success": False, "error": "Could not allocate a coverage entry id"}
        _coverage_storage[entry_id] = entry
        _persist_locked()
    logger.info(
        "Coverage recorded: id=%s outcome=%s surface=%s",
        entry_id,
        normalized,
        entry["surface"],
    )
    return {
        "success": True,
        "entry_id": entry_id,
        "outcome": normalized,
        "message": f"Coverage recorded for '{entry['surface']}' ({normalized})",
    }


def _update_impl(
    *,
    entry_id: str,
    outcome: str,
    evidence: str,
    agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    key = (entry_id or "").strip()
    with _coverage_lock:
        existing = _coverage_storage.get(key)
        if existing is None:
            return {
                "success": False,
                "error": (
                    f"No coverage entry {entry_id!r}. Call list_coverage to find the "
                    "entry you mean - filter by surface if you only know the name."
                ),
            }
        surface = str(existing.get("surface", ""))
        risk_area = str(existing.get("risk_area", ""))
        normalized, errors = _validate(
            surface=surface, risk_area=risk_area, outcome=outcome, evidence=evidence
        )
        if errors:
            return {"success": False, "error": "Validation failed", "errors": errors}

        previous_outcome = str(existing.get("outcome", ""))
        superseded: dict[str, Any] = {
            "outcome": previous_outcome,
            "recorded_at": existing.get("created_at", ""),
        }
        if existing.get("evidence"):
            superseded["evidence"] = existing["evidence"]
        if existing.get("agent_name"):
            superseded["agent_name"] = existing["agent_name"]
        history = existing.get("history")
        existing["history"] = [*history, superseded] if isinstance(history, list) else [superseded]

        existing["outcome"] = normalized
        existing["updated_at"] = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        if evidence.strip():
            existing["evidence"] = evidence.strip()
        if agent_id:
            existing["agent_id"] = agent_id
        if agent_name:
            existing["agent_name"] = agent_name
        _persist_locked()
    logger.info(
        "Coverage updated: id=%s %s -> %s surface=%s",
        key,
        previous_outcome,
        normalized,
        surface,
    )
    return {
        "success": True,
        "entry_id": key,
        "previous_outcome": previous_outcome,
        "outcome": normalized,
        "message": (
            f"'{surface}' ({risk_area}) moved from {previous_outcome} to {normalized}. "
            "The previous state is kept as history."
        ),
    }


def _list_impl(
    *, outcome: str | None, surface: str | None, caller_agent_id: str | None
) -> dict[str, Any]:
    normalized_outcome: str | None = None
    if outcome and outcome.strip():
        normalized_outcome = outcome.strip().lower().replace("-", "_").replace(" ", "_")
        if normalized_outcome not in VALID_OUTCOMES:
            return {
                "success": False,
                "error": f"Invalid outcome: {outcome!r}. Must be one of: {list(VALID_OUTCOMES)}",
            }

    entries: list[dict[str, Any]] = []
    for entry in get_coverage_entries():
        if normalized_outcome and entry.get("outcome") != normalized_outcome:
            continue
        if surface and surface.strip().lower() not in str(entry.get("surface", "")).lower():
            continue
        listing = {
            "entry_id": entry.get("entry_id"),
            "surface": entry.get("surface", ""),
            "risk_area": entry.get("risk_area", ""),
            "outcome": entry.get("outcome", ""),
            "created_at": entry.get("created_at", ""),
        }
        evidence = str(entry.get("evidence", ""))
        if evidence:
            listing["evidence"] = (
                f"{evidence[:_EVIDENCE_PREVIEW_CHARS].rstrip()}..."
                if len(evidence) > _EVIDENCE_PREVIEW_CHARS
                else evidence
            )
        agent_name = entry.get("agent_name")
        if agent_name:
            listing["agent_name"] = agent_name
        history = entry.get("history")
        if isinstance(history, list) and history:
            listing["previous_outcomes"] = [str(h.get("outcome", "")) for h in history]
        if caller_agent_id is not None and entry.get("agent_id") == caller_agent_id:
            listing["by_you"] = True
        entries.append(listing)

    return {
        "success": True,
        "entries": entries,
        "filtered_count": len(entries),
        "total_count": len(_coverage_storage),
        "outcome_counts": outcome_counts(),
    }


@function_tool(timeout=30)
async def record_coverage(
    ctx: RunContextWrapper,
    surface: str,
    risk_area: str,
    outcome: str,
    evidence: str = "",
) -> str:
    """Record that you reviewed a surface, and how that review closed.

    A scan that only reports findings cannot answer the question every
    client asks: *what did you actually check?* This tool captures that
    negative space. Record an entry whenever you finish assessing a
    surface for a risk — including (especially including) when you found
    nothing.

    Record coverage as you go, not in a batch at the end. Entries are
    shared across every agent in the scan, and the root agent reconciles
    them into the final report.

    Coverage is not append-only bookkeeping: if this surface and risk
    already have an entry — yours or another agent's — this call is
    rejected and returns that entry's id, because two rows for one
    surface leave the report showing a stale conclusion next to its
    replacement. Call ``update_coverage`` on the id it hands you
    instead. Resolving somebody else's ``needs_follow_up`` is exactly
    that case.

    **Outcomes** (pick exactly one):

    - ``reported`` — you confirmed an issue and filed a report for it.
    - ``no_issue_found`` — you tested this properly and found nothing.
    - ``ruled_out`` — you had a specific candidate and disproved it. The
      ``evidence`` must name the control that makes it safe, at a
      location, and confirm it runs on every attacker-reachable path.
      "It looked fine" is not ``ruled_out``.
    - ``not_applicable`` — this risk cannot apply here (e.g. no XML
      parsing on a surface, so no XXE). Say why in ``evidence``.
    - ``needs_follow_up`` — plausible but unresolved: you could not
      confirm it and could not name a control that rules it out. This is
      a legitimate outcome. Use it rather than quietly dropping a
      candidate, and name the gap in ``evidence`` (missing credentials,
      service you could not start, unconfirmed reachability).

    Never use ``no_issue_found`` or ``ruled_out`` to close something you
    were simply unsure about — that is ``needs_follow_up``. Missing
    information is not proof of safety.

    Args:
        surface: What you reviewed — an endpoint, route, parameter,
            file, component, or host (e.g. ``"POST /api/orders/{id}"``,
            ``"src/auth/session.py"``, ``"admin dashboard"``).
        risk_area: What you were testing it for (e.g. ``"IDOR /
            object-level authorization"``, ``"SQL injection"``,
            ``"SSRF"``).
        outcome: One of ``reported`` / ``no_issue_found`` /
            ``ruled_out`` / ``not_applicable`` / ``needs_follow_up``.
        evidence: How you know. Required for ``ruled_out``,
            ``not_applicable``, and ``needs_follow_up``; recommended
            otherwise. Keep it to a sentence or two — name the control,
            the test performed, or the missing piece.
    """
    agent_id, agent_name = _caller_identity(ctx)
    result = await asyncio.to_thread(
        _record_impl,
        surface=surface,
        risk_area=risk_area,
        outcome=outcome,
        evidence=evidence,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def update_coverage(
    ctx: RunContextWrapper,
    entry_id: str,
    outcome: str,
    evidence: str = "",
) -> str:
    """Change how an already-recorded surface closed.

    Coverage is shared across the whole agent tree, and a surface's
    state is not final when it is first written. Use this whenever
    later work changes the answer:

    - You picked up someone's ``needs_follow_up`` and resolved it —
      move it to ``reported``, ``ruled_out``, or ``no_issue_found``.
    - You had the credentials or running service the original agent
      lacked, and could finally test it properly.
    - You found the control that rules a candidate out, at a location,
      on every attacker-reachable path.
    - You went the other way: something recorded ``no_issue_found`` or
      ``ruled_out`` turns out to be exploitable, or the control you see
      does not cover the path you found. Move it back.

    The surface and risk area stay fixed — this is the same review,
    reaching a different conclusion. Do not record a fresh entry for a
    surface that already has one; that leaves a stale open item next to
    its own resolution. Find the id with ``list_coverage`` (filter by
    ``surface``), then update it.

    The previous outcome, evidence, and author are kept as history, so
    the ledger still shows that the surface was once open and who
    closed it.

    Args:
        entry_id: The id of the entry to update, from ``list_coverage``.
        outcome: The new outcome — ``reported`` / ``no_issue_found`` /
            ``ruled_out`` / ``not_applicable`` / ``needs_follow_up``.
        evidence: How you know, now. Required for ``ruled_out``,
            ``not_applicable``, and ``needs_follow_up``. Say what
            changed, not just what you concluded — the reader needs to
            know why this closed differently the second time.
    """
    agent_id, agent_name = _caller_identity(ctx)
    result = await asyncio.to_thread(
        _update_impl,
        entry_id=entry_id,
        outcome=outcome,
        evidence=evidence,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def list_coverage(
    ctx: RunContextWrapper,
    outcome: str | None = None,
    surface: str | None = None,
) -> str:
    """List coverage entries recorded so far in this scan.

    **For the orchestrator / root agent.** Use it to see which surfaces
    have been assessed, spot gaps before finishing, and pull the
    unresolved ``needs_follow_up`` rows into the final report. Leaf
    agents should record their own coverage and get on with testing.

    Returns each entry with its ``surface``, ``risk_area``, ``outcome``,
    evidence preview, and the agent that recorded it, plus
    ``outcome_counts`` across the whole scan.

    Args:
        outcome: Optional filter — one of ``reported`` /
            ``no_issue_found`` / ``ruled_out`` / ``not_applicable`` /
            ``needs_follow_up``. Filter on ``needs_follow_up`` before
            finishing the scan to see what is still open.
        surface: Optional case-insensitive substring filter on the
            surface name.
    """
    caller_agent_id, _ = _caller_identity(ctx)
    result = await asyncio.to_thread(
        _list_impl, outcome=outcome, surface=surface, caller_agent_id=caller_agent_id
    )
    return json.dumps(result, ensure_ascii=False, default=str)
