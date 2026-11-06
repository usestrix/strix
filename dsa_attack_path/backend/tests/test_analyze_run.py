"""Integration tests for Phase 3 run-dir attack-path analysis."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
DSA_ROOT = BACKEND_ROOT.parent
sys.path.insert(0, str(BACKEND_ROOT))
sys.path.insert(0, str(DSA_ROOT / "bridge"))

from strix_dsa_backend.analyze_run import AnalyzeOptions, analyze_run_dir  # noqa: E402
from strix_dsa_backend.paths_util import attack_path_dir, resolve_run_dir  # noqa: E402


def _make_fixture_run(dest: Path) -> Path:
    bridge_fx = DSA_ROOT / "bridge" / "fixtures"
    dest.mkdir(parents=True)
    shutil.copy(bridge_fx / "sample_vulnerabilities.json", dest / "vulnerabilities.json")
    shutil.copy(bridge_fx / "sample_run.json", dest / "run.json")
    return dest


class AnalyzeRunTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.run_dir = _make_fixture_run(Path(self._tmpdir.name) / "fixture-run")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_writes_attack_path_artifacts_lateral_off_by_default(self) -> None:
        engine = DSA_ROOT / "build" / "strix_dsa_cli.exe"
        options = AnalyzeOptions(
            run_engine=engine.exists(),
            engine_path=engine if engine.exists() else None,
        )
        self.assertFalse(options.allow_simulated_lateral)

        meta = analyze_run_dir(self.run_dir, options)
        out = attack_path_dir(self.run_dir)
        self.assertTrue((out / "attack_graph.json").exists())
        self.assertTrue((out / "topology.txt").exists())
        self.assertTrue((out / "meta.json").exists())
        self.assertTrue((out / "analysis.txt").exists())

        graph = json.loads((out / "attack_graph.json").read_text(encoding="utf-8"))
        self.assertFalse(graph["sources"]["simulated_lateral"])
        self.assertEqual(meta["product_defaults"]["allow_simulated_lateral"], False)
        self.assertIn("MODELED", graph["disclaimer"])
        self.assertIn("modeled_paths", meta)
        self.assertIn("bfs_node_ids", meta["modeled_paths"])
        self.assertGreaterEqual(len(meta["modeled_paths"]["bfs_node_ids"]), 1)

        # No MODELED_LATERAL edges when default options are used.
        lateral = [
            e for e in graph["edges"] if "MODELED_LATERAL" in e.get("labels", [])
        ]
        self.assertEqual(lateral, [])

    def test_opt_in_simulated_lateral(self) -> None:
        meta = analyze_run_dir(
            self.run_dir,
            AnalyzeOptions(allow_simulated_lateral=True, run_engine=False),
        )
        graph = json.loads(Path(meta["artifacts"]["attack_graph_json"]).read_text(encoding="utf-8"))
        self.assertTrue(graph["sources"]["simulated_lateral"])
        self.assertTrue(
            any("MODELED_LATERAL" in e.get("labels", []) for e in graph["edges"])
        )

    def test_resolve_run_name_under_strix_runs(self) -> None:
        cwd = Path(self._tmpdir.name)
        runs = cwd / "strix_runs" / "demo"
        _make_fixture_run(runs)
        resolved = resolve_run_dir("demo", cwd=cwd)
        self.assertEqual(resolved, runs.resolve())

    def test_cli_module(self) -> None:
        cmd = [
            sys.executable,
            "-m",
            "strix_dsa_backend",
            str(self.run_dir),
            "--skip-engine",
            "--json",
        ]
        completed = subprocess.run(
            cmd, cwd=BACKEND_ROOT, capture_output=True, text=True, check=False
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertFalse(payload["product_defaults"]["allow_simulated_lateral"])
        self.assertTrue(Path(payload["artifacts"]["attack_graph_json"]).exists())

    def test_engine_end_to_end_when_built(self) -> None:
        engine = DSA_ROOT / "build" / "strix_dsa_cli.exe"
        if not engine.exists():
            self.skipTest("C++ engine not built")
        meta = analyze_run_dir(
            self.run_dir,
            AnalyzeOptions(run_engine=True, engine_path=engine),
        )
        self.assertTrue(meta["engine"]["invoked"])
        self.assertEqual(meta["engine"]["returncode"], 0)
        text = Path(meta["artifacts"]["analysis_txt"]).read_text(encoding="utf-8")
        self.assertIn("MODELED attack-path analysis", text)
        self.assertIn("not confirmed multi-hop", text)


class AttackPathShimTest(unittest.TestCase):
    def test_shim_imports(self) -> None:
        # Load the shim file directly so we do not require Strix runtime deps
        # pulled in by strix.interface.__init__ (rich, etc.).
        import importlib.util

        shim_path = DSA_ROOT.parent / "strix" / "interface" / "attack_path_cli.py"
        spec = importlib.util.spec_from_file_location("attack_path_cli_under_test", shim_path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = _make_fixture_run(Path(tmp) / "shim-run")
            rc = module.run_attack_path([str(run_dir), "--skip-engine", "--json"])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
