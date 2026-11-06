"""Unit tests for modeled BFS / Dijkstra path helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from strix_dsa_bridge.mapper import BridgeOptions, build_attack_graph  # noqa: E402
from strix_dsa_bridge.paths import (  # noqa: E402
    bfs_node_path,
    build_modeled_paths,
    dijkstra_node_path,
)
from strix_dsa_bridge.emit import load_findings_file  # noqa: E402


FIXTURE = ROOT / "fixtures" / "sample_vulnerabilities.json"


class PathsTest(unittest.TestCase):
    def test_bfs_on_fixture_graph(self) -> None:
        findings = load_findings_file(FIXTURE)
        graph = build_attack_graph(findings, options=BridgeOptions(allow_simulated_lateral=False))
        start = graph["analysis_defaults"]["start"]
        target = graph["analysis_defaults"]["target"]
        path = bfs_node_path(graph, start, target)
        self.assertGreaterEqual(len(path), 2)
        self.assertEqual(path[0], start)
        self.assertEqual(path[-1], target)

        modeled = build_modeled_paths(graph, start=start, target=target)
        self.assertEqual(modeled["bfs_node_ids"], path)
        self.assertTrue(modeled["bfs_edges"])
        self.assertIn("not confirmed multi-hop", modeled["note"])
        self.assertIn("dijkstra_node_ids", modeled)
        self.assertEqual(modeled["dijkstra_node_ids"][0], start)
        self.assertEqual(modeled["dijkstra_node_ids"][-1], target)
        self.assertTrue(modeled["dijkstra_edges"])
        self.assertIsNotNone(modeled["dijkstra_path_probability"])

    def test_dijkstra_prefers_higher_product(self) -> None:
        # Mirrors C++ test_dijkstra_product: 1→2→4 (0.9*0.9=0.81) beats 1→3→4 (0.25).
        graph = {
            "edges": [
                {"from": 1, "to": 2, "probability": 0.9, "status": "Active", "labels": []},
                {"from": 2, "to": 4, "probability": 0.9, "status": "Active", "labels": []},
                {"from": 1, "to": 3, "probability": 0.5, "status": "Active", "labels": []},
                {"from": 3, "to": 4, "probability": 0.5, "status": "Active", "labels": []},
            ]
        }
        path = dijkstra_node_path(graph, 1, 4)
        self.assertEqual(path, [1, 2, 4])
        # Same hop count — BFS may pick either corridor depending on edge order;
        # Dijkstra must lock the higher product.
        modeled = build_modeled_paths(graph, start=1, target=4)
        self.assertEqual(modeled["dijkstra_node_ids"], [1, 2, 4])
        self.assertAlmostEqual(modeled["dijkstra_path_probability"], 0.81, places=9)

    def test_dijkstra_skips_zero_probability(self) -> None:
        graph = {
            "edges": [
                {"from": 1, "to": 3, "probability": 0.0, "status": "Active", "labels": []},
                {"from": 1, "to": 2, "probability": 0.5, "status": "Active", "labels": []},
                {"from": 2, "to": 3, "probability": 0.5, "status": "Active", "labels": []},
            ]
        }
        self.assertEqual(dijkstra_node_path(graph, 1, 3), [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
