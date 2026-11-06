"""Unit tests for Strix → DSA bridge mapping heuristics."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from strix_dsa_bridge.constants import (  # noqa: E402
    PROVENANCE_FINDING,
    PROVENANCE_SIMULATED,
)
from strix_dsa_bridge.emit import (  # noqa: E402
    emit_graph_json,
    emit_topology_txt,
    load_findings_file,
)
from strix_dsa_bridge.mapper import (  # noqa: E402
    BridgeOptions,
    build_attack_graph,
    normalize_endpoint,
    parse_target,
)


FIXTURE = ROOT / "fixtures" / "sample_vulnerabilities.json"
RUN_FIXTURE = ROOT / "fixtures" / "sample_run.json"


class ParseHelpersTest(unittest.TestCase):
    def test_parse_https_target(self) -> None:
        parsed = parse_target("https://App.Example.com/path")
        self.assertEqual(parsed["host"], "app.example.com")
        self.assertEqual(parsed["zone"], "DMZ")

    def test_parse_localhost_lab_zone(self) -> None:
        parsed = parse_target("http://localhost:8080")
        self.assertEqual(parsed["zone"], "Lab")

    def test_normalize_endpoint(self) -> None:
        self.assertEqual(normalize_endpoint("api/login"), "/api/login")
        self.assertIsNone(normalize_endpoint(""))
        self.assertIsNone(normalize_endpoint(None))


class MapperTest(unittest.TestCase):
    def setUp(self) -> None:
        self.findings = load_findings_file(FIXTURE)
        self.run_record = json.loads(RUN_FIXTURE.read_text(encoding="utf-8"))

    def test_fixture_schema_fields_present(self) -> None:
        required = {"id", "title", "severity", "target"}
        for finding in self.findings:
            self.assertTrue(required.issubset(finding.keys()))

    def test_build_separates_provenance(self) -> None:
        graph = build_attack_graph(self.findings, run_record=self.run_record)
        self.assertIn("MODELED ATTACK GRAPH", graph["disclaimer"])
        self.assertGreater(graph["counts"]["from_finding_nodes"], 0)
        self.assertGreater(graph["counts"]["simulated_nodes"], 0)
        self.assertGreater(graph["counts"]["from_finding_edges"], 0)
        self.assertGreater(graph["counts"]["simulated_edges"], 0)

        for node in graph["nodes"]:
            self.assertIn(node["provenance"], {PROVENANCE_FINDING, PROVENANCE_SIMULATED})
            if node["provenance"] == PROVENANCE_SIMULATED:
                self.assertIn("SIMULATED", node["labels"])
            else:
                self.assertTrue(
                    "FROM_FINDING" in node["labels"] or "FROM_RUN_TARGET" in node["labels"]
                )

        for edge in graph["edges"]:
            self.assertIn(edge["provenance"], {PROVENANCE_FINDING, PROVENANCE_SIMULATED})
            if edge["provenance"] == PROVENANCE_SIMULATED:
                self.assertTrue(any(label.startswith("SIMULATED") or label == "SIMULATED"
                                    for label in edge["labels"]) or "MODELED_ENTRY" in edge["labels"]
                                or "MODELED_LATERAL" in edge["labels"] or "SIMULATED" in edge["labels"])

    def test_host_and_endpoint_dedup(self) -> None:
        graph = build_attack_graph(self.findings)
        hosts = [n for n in graph["nodes"] if n["type"] == "Host" and "app.example.com" in n["name"]]
        self.assertEqual(len(hosts), 1)
        endpoints = [n for n in graph["nodes"] if n["type"] == "Endpoint"]
        # /api/login and /search on app, /internal/status on admin
        self.assertEqual(len(endpoints), 3)

    def test_severity_drives_probability(self) -> None:
        graph = build_attack_graph(self.findings)
        login_edges = [
            e for e in graph["edges"]
            if e["provenance"] == PROVENANCE_FINDING and e.get("title", "").startswith("SQL")
        ]
        self.assertTrue(login_edges)
        self.assertAlmostEqual(login_edges[0]["probability"], 0.85)

    def test_missing_endpoint_warns(self) -> None:
        graph = build_attack_graph(self.findings)
        self.assertTrue(any("no endpoint" in w for w in graph["warnings"]))

    def test_run_target_without_finding_added(self) -> None:
        graph = build_attack_graph(self.findings, run_record=self.run_record)
        unused = [n for n in graph["nodes"] if "unused-target.example.com" in n["name"]]
        self.assertEqual(len(unused), 1)
        self.assertIn("FROM_RUN_TARGET", unused[0]["labels"])

    def test_simulated_lateral_flag(self) -> None:
        off = build_attack_graph(self.findings, options=BridgeOptions(allow_simulated_lateral=False))
        on = build_attack_graph(self.findings, options=BridgeOptions(allow_simulated_lateral=True))
        self.assertGreater(on["counts"]["simulated_edges"], off["counts"]["simulated_edges"])
        self.assertTrue(any("Simulated lateral" in w for w in on["warnings"]))

    def test_no_simulated_entry(self) -> None:
        graph = build_attack_graph(
            self.findings, options=BridgeOptions(allow_simulated_entry=False)
        )
        self.assertEqual(graph["counts"]["simulated_nodes"], 0)
        attackers = [n for n in graph["nodes"] if n["type"] == "Attacker"]
        self.assertEqual(attackers, [])

    def test_crown_jewel_marked(self) -> None:
        graph = build_attack_graph(self.findings)
        crowns = [n for n in graph["nodes"] if n["is_crown_jewel"]]
        self.assertEqual(len(crowns), 1)
        self.assertIn("MODELED_CROWN_JEWEL", crowns[0]["labels"])

    def test_emit_topology_roundtrip_fields(self) -> None:
        graph = build_attack_graph(self.findings, run_record=self.run_record)
        out = Path(self._testMethodName + "_out")
        try:
            txt = emit_topology_txt(graph, out / "topology.txt")
            js = emit_graph_json(graph, out / "attack_graph.json")
            text = txt.read_text(encoding="utf-8")
            self.assertIn("MODELED ATTACK GRAPH", text)
            self.assertIn("[NODES]", text)
            self.assertIn("[EDGES]", text)
            loaded = json.loads(js.read_text(encoding="utf-8"))
            self.assertEqual(loaded["counts"]["nodes"], graph["counts"]["nodes"])
        finally:
            if out.exists():
                for child in out.iterdir():
                    child.unlink()
                out.rmdir()


class CliDemoTest(unittest.TestCase):
    def test_cli_convert_fixture(self) -> None:
        out = ROOT / "tests" / "_cli_out"
        if out.exists():
            for child in out.rglob("*"):
                if child.is_file():
                    child.unlink()
        cmd = [
            sys.executable,
            "-m",
            "strix_dsa_bridge",
            "convert",
            str(FIXTURE),
            "--run-json",
            str(RUN_FIXTURE),
            "-o",
            str(out),
            "--allow-simulated-lateral",
        ]
        completed = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue((out / "attack_graph.json").exists())
        self.assertTrue((out / "topology.txt").exists())
        summary = json.loads(completed.stdout)
        self.assertIn("counts", summary)


if __name__ == "__main__":
    unittest.main()
