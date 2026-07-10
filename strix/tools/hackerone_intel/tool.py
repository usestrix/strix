"""``hackerone_intel`` — consult the local HackerOne intelligence engine.

Wraps the already-built KB at ``$H1_KB_HOME`` (default
``~/.claude/skills/hackerone-kb``): a SQLite store of 12,340 disclosed
HackerOne reports plus distilled playbooks, tech/feature intel, chains, and a
ranked hunt planner, all exposed through ``bin/h1_query.py``.

Design note — shell-out, not direct sqlite3
--------------------------------------------
This tool shells out to ``h1_query.py`` rather than querying ``h1_kb.sqlite``
directly. Direct SQL could only reproduce the handful of DB-backed modes
(search/class/show/tech/assets/classes/programs). It could NOT reproduce:

  * ``plan`` — the ranked, evidence-backed hunt planner, which spans
    ``h1_plan.py`` + ``h1_tag`` + ``h1_intel`` + ``h1_outcome`` (hundreds of
    lines of ranking logic), and is the primary "consult-first" use case; and
  * ``playbook``/``profile``/``feature``/``chains``/``recon``/``analysis`` —
    which read curated markdown off disk, not the DB.

Shelling out reuses 100% of that engine as-is and avoids forking logic that
would then rot. The subprocess is always invoked with an argv **list** (never
``shell=True``): there is no shell-injection surface. The 104 MB DB is never
copied into this repo — the tool reads it in place via ``H1_KB_HOME``.

This tool is READ-ONLY: the ``outcome`` subcommand (the KB's write/learning
path) is deliberately not exposed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


_DEFAULT_H1_KB_HOME = "~/.claude/skills/hackerone-kb"
_SUBPROCESS_TIMEOUT_S = 60
_DEFAULT_MAX_CHARS = 16_000

# Modes the agent may invoke, mapped to h1_query.py subcommands. ``outcome`` is
# intentionally absent — it writes to the KB's learning store, and this tool is
# read-only.
_ALLOWED_MODES: frozenset[str] = frozenset(
    {
        "plan",
        "playbook",
        "profile",
        "feature",
        "chains",
        "recon",
        "search",
        "class",
        "show",
        "tech",
        "assets",
        "analysis",
        "classes",
        "programs",
    }
)

# Modes whose primary input (a slug or free-text term) arrives in ``query`` and
# must be non-empty.
_REQUIRES_QUERY: frozenset[str] = frozenset(
    {"playbook", "profile", "feature", "search", "class", "tech", "assets"}
)


def _kb_home() -> Path:
    return Path(os.path.expanduser(os.environ.get("H1_KB_HOME", _DEFAULT_H1_KB_HOME)))


def _build_args(
    mode: str,
    *,
    query: str,
    report_id: int | None,
    tech: str,
    feature: str,
    target: str,
    limit: int,
) -> list[str]:
    """Map the tool's named params to h1_query.py's positional/flag args.

    Raises ``ValueError`` (with an agent-readable message) for an unknown mode
    or a mode missing its required input, before any subprocess is spawned.
    """
    if mode not in _ALLOWED_MODES:
        raise ValueError(
            f"unknown mode {mode!r}. Valid modes: {', '.join(sorted(_ALLOWED_MODES))}"
        )

    if mode in _REQUIRES_QUERY and not query.strip():
        raise ValueError(f"mode {mode!r} requires a non-empty 'query'")

    if mode == "plan":
        if not tech.strip() and not feature.strip():
            raise ValueError("mode 'plan' requires at least one of 'tech' or 'feature'")
        args = ["plan"]
        if tech.strip():
            args += ["--tech", tech]
        if feature.strip():
            args += ["--feature", feature]
        if target.strip():
            args += ["--target", target]
        args += ["--top", str(limit)]
        return args

    if mode == "show":
        if report_id is None:
            raise ValueError("mode 'show' requires 'report_id'")
        return ["show", str(report_id)]

    if mode in ("search", "class"):
        return [mode, query, "--limit", str(limit)]

    if mode == "programs":
        return ["programs", "--limit", str(limit)]

    if mode in ("playbook", "profile", "feature", "tech", "assets"):
        return [mode, query]

    if mode == "analysis":
        # optional name; h1_query.py defaults to the README synthesis
        return ["analysis", query] if query.strip() else ["analysis"]

    # chains, recon, classes — no extra args
    return [mode]


def _run_kb(
    mode: str,
    *,
    query: str,
    report_id: int | None,
    tech: str,
    feature: str,
    target: str,
    limit: int,
    max_chars: int,
) -> dict[str, Any]:
    home = _kb_home()
    db_path = home / "db" / "h1_kb.sqlite"
    if not db_path.is_file():
        logger.warning("hackerone_intel: KB not found at %s", db_path)
        return {"success": False, "error": "HackerOne KB not configured at H1_KB_HOME"}

    script = home / "bin" / "h1_query.py"
    if not script.is_file():
        logger.warning("hackerone_intel: query script missing at %s", script)
        return {"success": False, "error": "HackerOne KB not configured at H1_KB_HOME"}

    try:
        built_args = _build_args(
            mode,
            query=query,
            report_id=report_id,
            tech=tech,
            feature=feature,
            target=target,
            limit=limit,
        )
    except ValueError as exc:
        return {"success": False, "error": str(exc)}

    try:
        proc = subprocess.run(  # noqa: S603 - argv list, never shell=True; no injection surface
            [sys.executable, str(script), *built_args],
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("hackerone_intel: %s timed out", mode)
        return {"success": False, "error": f"HackerOne KB query timed out (mode={mode})"}
    except OSError:
        logger.exception("hackerone_intel: failed to launch query script")
        return {"success": False, "error": "Could not run the HackerOne KB query script"}

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        tail = detail[-1] if detail else f"exit {proc.returncode}"
        return {
            "success": False,
            "error": (
                f"HackerOne KB query failed (mode={mode}): {tail}. "
                "If 'query' is exactly a flag string, see the known-limitation note"
            ),
        }

    output = proc.stdout or ""
    cap = max_chars if max_chars > 0 else _DEFAULT_MAX_CHARS
    result: dict[str, Any] = {"success": True, "mode": mode}
    if len(output) > cap:
        result["output"] = output[:cap]
        result["truncated"] = True
    else:
        result["output"] = output
    return result


@function_tool(timeout=90)
async def hackerone_intel(
    ctx: RunContextWrapper,
    mode: str,
    query: str = "",
    report_id: int | None = None,
    tech: str = "",
    feature: str = "",
    target: str = "",
    limit: int = 20,
    max_chars: int = 16_000,
) -> str:
    """Consult the local HackerOne intelligence engine — 12,340 disclosed
    reports distilled into ranked hunt plans, per-class playbooks, tech/feature
    intel, and real report citations. Use BEFORE proposing a methodology on a
    target, and to ground hypotheses in disclosed-report priors.

    Start with ``mode="plan"`` (pass ``tech=`` / ``feature=`` / ``target=``) for
    a ranked, evidence-backed hypothesis list. Then drill in:
    ``mode="playbook"`` / ``"profile"`` / ``"feature"`` for the how-to, and
    ``mode="class"`` / ``"search"`` / ``"show"`` for the real reports behind it.

    Read-only. Returns the engine's plain-text / markdown output as a JSON
    string: ``{"success": true, "mode": ..., "output": "...", "truncated"?: true}``
    on success, or ``{"success": false, "error": "..."}`` on failure (including
    when the KB isn't configured on this host — it degrades gracefully, never
    crashes).

    Modes and the params each uses:

    - ``plan``     → ``tech``, ``feature``, ``target`` (needs ≥1 of tech/feature);
      ``limit`` caps the number of hypotheses. Ranked hypotheses + chains + order.
    - ``playbook`` → ``query`` = bug-class slug (e.g. ``ssrf``). Hunting playbook.
    - ``profile``  → ``query`` = technology slug (e.g. ``nextjs``, ``aws``).
    - ``feature``  → ``query`` = feature slug (e.g. ``billing``, ``rbac``).
    - ``chains``   → (no args) cross-report bug-chain intelligence.
    - ``recon``    → (no args) recon-value ranking.
    - ``search``   → ``query`` = free text; ``limit``. Full-text report search.
    - ``class``    → ``query`` = bug-class slug; ``limit``. Reports in that class.
    - ``show``     → ``report_id`` = int. Full writeup + metadata (can be long —
      raise ``max_chars`` to read it all).
    - ``tech``     → ``query`` = bug-class slug. Normalized techniques for a class.
    - ``assets``   → ``query`` = host or technology term.
    - ``analysis`` → ``query`` = analysis name (optional; defaults to a synthesis).
    - ``classes``  → (no args) bug-class distribution.
    - ``programs`` → ``limit``. Most-disclosed programs.

    Output is truncated at ``max_chars`` (default 16,000) with
    ``"truncated": true`` set; pass a larger ``max_chars`` when you deliberately
    want a full, long result.

    Known limitation (underlying script, out of scope to patch): a ``query``
    that is *exactly* one of h1_query.py's recognized flag strings —
    ``--class``, ``--program``, ``--severity``, ``--limit``, ``--bounty`` — may
    be misparsed by its positional arg reader (returning no matches or a failed
    query). Ordinary leading-dash text such as ``-test`` is fine. Avoid passing a
    bare flag string as ``query``.

    Args:
        mode: Which KB subcommand to run (see the list above).
        query: Free-text term or slug, per mode.
        report_id: Numeric report id, for ``mode="show"``.
        tech: Comma-separated technology slugs/names, for ``mode="plan"``.
        feature: Comma-separated feature slugs, for ``mode="plan"``.
        target: Label for the plan header, for ``mode="plan"``.
        limit: Result/hypothesis cap for search/class/programs/plan.
        max_chars: Max characters of engine output to return (default 16,000).
    """
    result = await asyncio.to_thread(
        _run_kb,
        mode,
        query=query,
        report_id=report_id,
        tech=tech,
        feature=feature,
        target=target,
        limit=limit,
        max_chars=max_chars,
    )
    return json.dumps(result, ensure_ascii=False, default=str)
