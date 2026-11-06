"""Read Phase-3 ``attack_path/`` artifacts for the local viewer API.

Reuses ``attack_graph.json`` + ``meta.json`` (+ optional ``analysis.txt``).
Never invents a second schema. Missing artifacts degrade gracefully.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ATTACK_PATH_DIRNAME = "attack_path"


def read_attack_path(run_dir: Path) -> dict[str, Any]:
    """Return the attack-path payload for ``GET /api/attack-path``.

    When artifacts are absent, ``available`` is false and ``reason`` explains why
    so the SPA can degrade without implying a failed scan.
    """
    base = run_dir / ATTACK_PATH_DIRNAME
    graph_path = base / "attack_graph.json"
    meta_path = base / "meta.json"
    analysis_path = base / "analysis.txt"

    if not base.is_dir():
        return {
            "available": False,
            "reason": (
                "No attack_path/ artifacts for this run. Generate them with "
                "`strix attack-path <run>` or `python -m strix_dsa_backend <run>` "
                "(modeled analysis — not confirmed multi-hop exploits)."
            ),
            "graph": None,
            "meta": None,
            "analysis_text": None,
        }

    if not graph_path.is_file():
        return {
            "available": False,
            "reason": (
                "attack_path/ exists but attack_graph.json is missing. "
                "Re-run the DSA backend against this run directory."
            ),
            "graph": None,
            "meta": None,
            "analysis_text": None,
        }

    try:
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "available": False,
            "reason": f"attack_graph.json is unreadable ({exc}).",
            "graph": None,
            "meta": None,
            "analysis_text": None,
        }

    meta: dict[str, Any] | None
    if meta_path.is_file():
        try:
            loaded_meta = json.loads(meta_path.read_text(encoding="utf-8"))
            meta = loaded_meta if isinstance(loaded_meta, dict) else None
        except (OSError, json.JSONDecodeError):
            meta = None
    else:
        meta = None

    analysis_text: str | None = None
    if analysis_path.is_file():
        try:
            analysis_text = analysis_path.read_text(encoding="utf-8")
        except OSError:
            analysis_text = None

    if not isinstance(graph, dict):
        return {
            "available": False,
            "reason": "attack_graph.json must be a JSON object.",
            "graph": None,
            "meta": None,
            "analysis_text": None,
        }

    return {
        "available": True,
        "reason": None,
        "graph": graph,
        "meta": meta,
        "analysis_text": analysis_text,
        # Convenience flags for the SPA (derived, not a new schema).
        "disclaimer": graph.get("disclaimer")
        or (meta or {}).get("disclaimer")
        or (
            "MODELED attack-path view — not confirmed multi-hop exploit chains."
        ),
        "simulated_lateral_default": bool(
            (meta or {}).get("product_defaults", {}).get("allow_simulated_lateral", False)
            if meta
            else graph.get("sources", {}).get("simulated_lateral", False)
        ),
    }
