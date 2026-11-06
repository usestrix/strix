"""Unit tests for modeled BFS path helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from strix_dsa_bridge.mapper import BridgeOptions, build_attack_graph  # noqa: E402
from strix_dsa_bridge.paths import bfs_node_path, build_modeled_paths  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
