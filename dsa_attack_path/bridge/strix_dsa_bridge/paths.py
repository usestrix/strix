"""Lightweight path helpers on a bridge graph dict (no C++ required).

Used to populate ``meta.json`` modeled_paths for UI highlighting without
forking the attack_graph schema.

BFS = fewest hops. Dijkstra = max path-product via edge weight ``-log(p)``,
matching ``dsa_attack_path`` C++ ``run_dijkstra`` (tie-break: fewer hops).
"""

from __future__ import annotations

import heapq
import math
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


def dijkstra_node_path(
    graph: dict[str, Any],
    start: int,
    target: int,
    *,
    include_lateral: bool = False,
) -> list[int]:
    """Return max path-product node ids (Dijkstra on ``-log(p)``), or [].

    Mirrors C++ ``run_dijkstra``: settle by distance, prefer fewer hops on ties.
    """
    if start == target:
        return [start]
    adj = _adj(graph, include_lateral=include_lateral)
    dist: dict[int, tuple[float, int]] = {start: (0.0, 0)}
    parent: dict[int, int | None] = {start: None}
    # (distance, hops, node)
    queue: list[tuple[float, int, int]] = [(0.0, 0, start)]
    settled: set[int] = set()
    while queue:
        current_dist, current_hops, current = heapq.heappop(queue)
        if current in settled:
            continue
        known = dist.get(current)
        if known is None or current_dist > known[0] + 1e-12:
            continue
        settled.add(current)
        if current == target:
            break
        for edge in adj.get(current, []):
            nxt = int(edge["to"])
            if nxt in settled:
                continue
            try:
                probability = float(edge.get("probability", 0.0))
            except (TypeError, ValueError):
                continue
            if probability <= 0.0:
                continue
            weight = 0.0 if probability >= 1.0 else -math.log(probability)
            next_dist = dist[current][0] + weight
            next_hops = dist[current][1] + 1
            prev = dist.get(nxt)
            better_distance = prev is None or next_dist + 1e-12 < prev[0]
            same_distance_fewer_hops = (
                prev is not None
                and abs(next_dist - prev[0]) <= 1e-12
                and next_hops < prev[1]
            )
            if better_distance or same_distance_fewer_hops:
                dist[nxt] = (next_dist, next_hops)
                parent[nxt] = current
                heapq.heappush(queue, (next_dist, next_hops, nxt))
    if target not in settled:
        return []
    path = [target]
    while path[-1] != start:
        prev = parent.get(path[-1])
        if prev is None:
            return []
        path.append(prev)
    path.reverse()
    return path


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


def path_product(edges: list[dict[str, Any]]) -> float | None:
    """Modeled traversal product along edges (None if empty)."""
    if not edges:
        return None
    product = 1.0
    for edge in edges:
        try:
            product *= float(edge.get("probability", 0.0))
        except (TypeError, ValueError):
            return None
    return product


def _edge_summaries(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
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


def build_modeled_paths(
    graph: dict[str, Any],
    *,
    start: int | None,
    target: int | None,
    include_lateral: bool = False,
) -> dict[str, Any]:
    """Structured path summary for meta.json (UI highlight aid).

    Always includes BFS + Dijkstra fields (empty lists when unreachable).
    ``analysis.txt`` from the C++ CLI remains the richer transcript fallback.
    """
    from .constants import DISCLAIMER_BANNER

    result: dict[str, Any] = {
        "note": DISCLAIMER_BANNER,
        "start": start,
        "target": target,
        "include_simulated_lateral": include_lateral,
        "bfs_node_ids": [],
        "bfs_edges": [],
        "dijkstra_node_ids": [],
        "dijkstra_edges": [],
        "dijkstra_path_probability": None,
        "weighting": "dijkstra uses -log(p) for max path-product; BFS is fewest hops",
    }
    if start is None or target is None:
        return result

    bfs_nodes = bfs_node_path(graph, int(start), int(target), include_lateral=include_lateral)
    result["bfs_node_ids"] = bfs_nodes
    result["bfs_edges"] = _edge_summaries(path_edges(graph, bfs_nodes))

    dijkstra_nodes = dijkstra_node_path(
        graph, int(start), int(target), include_lateral=include_lateral
    )
    dijkstra_edge_recs = path_edges(graph, dijkstra_nodes)
    result["dijkstra_node_ids"] = dijkstra_nodes
    result["dijkstra_edges"] = _edge_summaries(dijkstra_edge_recs)
    result["dijkstra_path_probability"] = path_product(dijkstra_edge_recs)
    return result
