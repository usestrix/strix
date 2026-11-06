"""Lightweight path helpers on a bridge graph dict (no C++ required).

Used to populate ``meta.json`` modeled_paths for UI highlighting without
forking the attack_graph schema.
"""

from __future__ import annotations

from collections import deque
from typing import Any


def _adj(graph: dict[str, Any], *, include_lateral: bool = False) -> dict[int, list[dict[str, Any]]]:
    out: dict[int, list[dict[str, Any]]] = {}
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        labels = edge.get("labels") or []
        if (not include_lateral) and "MODELED_LATERAL" in labels:
            continue
        # Match C++ traversable rule: probability must be > 0.
        try:
            probability = float(edge.get("probability", 0.0))
        except (TypeError, ValueError):
            probability = 0.0
        if probability <= 0.0:
            continue
        status = str(edge.get("status") or "Active")
        if status == "Disabled":
            continue
        frm = int(edge["from"])
        out.setdefault(frm, []).append(edge)
    return out


def bfs_node_path(
    graph: dict[str, Any],
    start: int,
    target: int,
    *,
    include_lateral: bool = False,
) -> list[int]:
    """Return one fewest-hop node id path, or [] if unreachable."""
    if start == target:
        return [start]
    adj = _adj(graph, include_lateral=include_lateral)
    parent: dict[int, int | None] = {start: None}
    queue: deque[int] = deque([start])
    while queue:
        current = queue.popleft()
        for edge in adj.get(current, []):
            nxt = int(edge["to"])
            if nxt in parent:
                continue
            parent[nxt] = current
            if nxt == target:
                path = [target]
                while path[-1] != start:
                    prev = parent[path[-1]]
                    assert prev is not None
                    path.append(prev)
                path.reverse()
                return path
            queue.append(nxt)
    return []


def path_edges(graph: dict[str, Any], node_ids: list[int]) -> list[dict[str, Any]]:
    """Map consecutive node ids to edge records (first match)."""
    if len(node_ids) < 2:
        return []
    by_pair: dict[tuple[int, int], dict[str, Any]] = {}
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        key = (int(edge["from"]), int(edge["to"]))
        by_pair.setdefault(key, edge)
    edges: list[dict[str, Any]] = []
    for i in range(len(node_ids) - 1):
        edge = by_pair.get((node_ids[i], node_ids[i + 1]))
        if edge:
            edges.append(edge)
    return edges


def build_modeled_paths(
    graph: dict[str, Any],
    *,
    start: int | None,
    target: int | None,
    include_lateral: bool = False,
) -> dict[str, Any]:
    """Structured path summary for meta.json (UI highlight aid)."""
    from .constants import DISCLAIMER_BANNER

    result: dict[str, Any] = {
        "note": DISCLAIMER_BANNER,
        "start": start,
        "target": target,
        "include_simulated_lateral": include_lateral,
        "bfs_node_ids": [],
        "bfs_edges": [],
    }
    if start is None or target is None:
        return result
    nodes = bfs_node_path(graph, int(start), int(target), include_lateral=include_lateral)
    result["bfs_node_ids"] = nodes
    edges = path_edges(graph, nodes)
    result["bfs_edges"] = [
        {
            "from": e.get("from"),
            "to": e.get("to"),
            "provenance": e.get("provenance"),
            "probability": e.get("probability"),
            "labels": e.get("labels") or [],
            "title": e.get("title"),
        }
        for e in edges
    ]
    return result
