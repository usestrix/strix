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


DEFAULT_MAX_DEPTH = 12
DEFAULT_MAX_PATHS = 10000
DEFAULT_BOTTLENECK_TOP = 10


def _nodes_by_id(graph: dict[str, Any]) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for node in graph.get("nodes") or []:
        if isinstance(node, dict) and "id" in node:
            out[int(node["id"])] = node
    return out


def _reachable_from_start(
    adj: dict[int, list[dict[str, Any]]], start: int
) -> set[int]:
    seen = {start}
    queue: deque[int] = deque([start])
    while queue:
        current = queue.popleft()
        for edge in adj.get(current, []):
            nxt = int(edge["to"])
            if nxt in seen:
                continue
            seen.add(nxt)
            queue.append(nxt)
    return seen


def _enumerate_simple_paths(
    adj: dict[int, list[dict[str, Any]]],
    start: int,
    target: int,
    *,
    max_depth: int,
    max_paths: int,
) -> tuple[list[list[int]], bool]:
    """DFS simple-path enum matching C++ caps. Returns (paths, truncated)."""
    if max_depth <= 0 or max_paths <= 0:
        return [], False
    paths: list[list[int]] = []
    truncated = False

    def visit(current: int, depth: int, path: list[int], visited: set[int]) -> None:
        nonlocal truncated
        if truncated:
            return
        if current == target:
            if len(paths) >= max_paths:
                truncated = True
                return
            paths.append(list(path))
            return
        if depth >= max_depth:
            return
        for edge in adj.get(current, []):
            if truncated:
                return
            nxt = int(edge["to"])
            if nxt in visited:
                continue
            visited.add(nxt)
            path.append(nxt)
            visit(nxt, depth + 1, path, visited)
            path.pop()
            visited.remove(nxt)

    visit(start, 0, [start], {start})
    return paths, truncated


def _reverse_reaches_jewels(
    adj: dict[int, list[dict[str, Any]]], jewel_ids: list[int]
) -> dict[int, set[int]]:
    """Map node_id -> set of crown-jewel ids reachable forward from that node."""
    reverse: dict[int, list[int]] = {}
    for frm, edges in adj.items():
        for edge in edges:
            reverse.setdefault(int(edge["to"]), []).append(int(frm))

    # For each jewel, walk reverse edges; every visited node can reach that jewel.
    can_reach: dict[int, set[int]] = {}
    for jewel in jewel_ids:
        queue: deque[int] = deque([jewel])
        seen = {jewel}
        while queue:
            current = queue.popleft()
            can_reach.setdefault(current, set()).add(jewel)
            for prev in reverse.get(current, []):
                if prev in seen:
                    continue
                seen.add(prev)
                queue.append(prev)
    return can_reach


def build_bottleneck_analysis(
    graph: dict[str, Any],
    *,
    start: int | None,
    target: int | None,
    include_lateral: bool = False,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_paths: int = DEFAULT_MAX_PATHS,
    top_n: int = DEFAULT_BOTTLENECK_TOP,
) -> dict[str, Any]:
    """Rank edges by crown-jewel reach + DFS path frequency (C++ bottleneck order).

    Mirrors ``Graph::analyze`` bottleneck ranking. ``analysis.txt`` remains the
    engine transcript fallback when the C++ CLI is invoked.
    """
    from .constants import DISCLAIMER_BANNER

    result: dict[str, Any] = {
        "note": DISCLAIMER_BANNER,
        "start": start,
        "target": target,
        "include_simulated_lateral": include_lateral,
        "max_depth": max_depth,
        "max_paths": max_paths,
        "truncated": False,
        "frequency_complete": True,
        "total_paths": 0,
        "ranking": "crown_jewels_count, total_impact, path_count, probability",
        "edges": [],
        "crown_jewels": [],
    }
    if start is None or target is None:
        return result

    start_i = int(start)
    target_i = int(target)
    adj = _adj(graph, include_lateral=include_lateral)
    nodes = _nodes_by_id(graph)
    jewel_ids = [
        nid
        for nid, node in nodes.items()
        if node.get("is_crown_jewel") or str(node.get("zone") or "") == "CrownJewel"
    ]

    reachable = _reachable_from_start(adj, start_i)
    can_reach = _reverse_reaches_jewels(adj, jewel_ids)

    crown_jewels: list[dict[str, Any]] = []
    for jid in jewel_ids:
        node = nodes.get(jid, {})
        hops = -1
        if jid in reachable:
            # cheapest hop count via BFS on same adj
            parent_path = bfs_node_path(
                graph, start_i, jid, include_lateral=include_lateral
            )
            hops = max(0, len(parent_path) - 1) if parent_path else -1
        crown_jewels.append(
            {
                "id": jid,
                "name": node.get("name"),
                "impact": int(node.get("impact") or 0),
                "reachable": jid in reachable,
                "shortest_hops": hops if jid in reachable else -1,
            }
        )
    result["crown_jewels"] = crown_jewels

    paths, truncated = _enumerate_simple_paths(
        adj, start_i, target_i, max_depth=max_depth, max_paths=max_paths
    )
    result["total_paths"] = len(paths)
    result["truncated"] = truncated
    result["frequency_complete"] = not truncated

    freq: dict[tuple[int, int], int] = {}
    for path in paths:
        for i in range(len(path) - 1):
            key = (path[i], path[i + 1])
            freq[key] = freq.get(key, 0) + 1

    # Edge lookup for provenance/labels
    edge_by_pair: dict[tuple[int, int], dict[str, Any]] = {}
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        edge_by_pair.setdefault((int(edge["from"]), int(edge["to"])), edge)

    items: list[dict[str, Any]] = []
    for (frm, to), count in freq.items():
        edge = edge_by_pair.get((frm, to), {})
        jewels_from_to = can_reach.get(to, set())
        # Only count jewels when the edge's from-node is reachable from start (C++ filter).
        if frm not in reachable:
            jewels_from_to = set()
        try:
            probability = float(edge.get("probability", 0.0))
        except (TypeError, ValueError):
            probability = 0.0
        impact = sum(int(nodes.get(j, {}).get("impact") or 0) for j in jewels_from_to)
        share = (100.0 * count / len(paths)) if paths else 0.0
        items.append(
            {
                "from": frm,
                "to": to,
                "path_count": count,
                "path_share_percent": share,
                "crown_jewels_count": len(jewels_from_to),
                "total_impact": impact,
                "probability": probability,
                "provenance": edge.get("provenance"),
                "labels": edge.get("labels") or [],
                "title": edge.get("title"),
                "frequency_complete": not truncated,
            }
        )

    items.sort(
        key=lambda item: (
            -int(item["crown_jewels_count"]),
            -int(item["total_impact"]),
            -int(item["path_count"]),
            -float(item["probability"] or 0.0),
            int(item["from"]),
            int(item["to"]),
        )
    )
    result["edges"] = items[: max(0, top_n)]
    return result


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
