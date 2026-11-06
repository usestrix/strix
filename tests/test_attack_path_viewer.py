"""Phase 4: attack_path artifact reader (stdlib-importable unit tests).

Full HTTP viewer tests live in test_viewer.py once the checkout deps are synced
via ``uv sync``. These cases validate the Phase-4 contract without pulling the
TUI/MCP import graph.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path


def _load_attack_path_module():
    path = (
        Path(__file__).resolve().parents[1]
        / "strix"
        / "interface"
        / "viewer"
        / "attack_path.py"
    )
    spec = importlib.util.spec_from_file_location("strix_viewer_attack_path", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _make_run(base: Path, name: str) -> Path:
    run_dir = base / "strix_runs" / name
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps({"run_name": name, "status": "completed", "end_time": "2026-01-01T00:00:00Z"}),
        encoding="utf-8",
    )
    (run_dir / "vulnerabilities.json").write_text("[]", encoding="utf-8")
    return run_dir


def test_read_attack_path_missing(tmp_path: Path) -> None:
    mod = _load_attack_path_module()
    run_dir = _make_run(tmp_path, "empty")
    payload = mod.read_attack_path(run_dir)
    assert payload["available"] is False
    assert "attack_path" in (payload["reason"] or "").lower()
    assert payload["graph"] is None


def test_read_attack_path_available_from_fixture(tmp_path: Path) -> None:
    mod = _load_attack_path_module()
    run_dir = _make_run(tmp_path, "with-path")
    src = (
        Path(__file__).resolve().parents[1]
        / "dsa_attack_path"
        / "backend"
        / "fixtures"
        / "sample_run_dir"
        / "attack_path"
    )
    if src.is_dir():
        shutil.copytree(src, run_dir / "attack_path")
    else:
        ap = run_dir / "attack_path"
        ap.mkdir()
        (ap / "attack_graph.json").write_text(
            json.dumps(
                {
                    "disclaimer": "MODELED ATTACK GRAPH",
                    "sources": {"simulated_lateral": False},
                    "nodes": [],
                    "edges": [],
                }
            ),
            encoding="utf-8",
        )
        (ap / "meta.json").write_text(
            json.dumps({"product_defaults": {"allow_simulated_lateral": False}}),
            encoding="utf-8",
        )
        (ap / "analysis.txt").write_text("MODELED ATTACK-PATH ANALYSIS\n", encoding="utf-8")

    payload = mod.read_attack_path(run_dir)
    assert payload["available"] is True
    assert payload["graph"] is not None
    assert "MODELED" in (payload["disclaimer"] or "")
    assert payload["simulated_lateral_default"] is False


def test_read_attack_path_corrupt_graph(tmp_path: Path) -> None:
    mod = _load_attack_path_module()
    run_dir = _make_run(tmp_path, "bad")
    ap = run_dir / "attack_path"
    ap.mkdir()
    (ap / "attack_graph.json").write_text("{not-json", encoding="utf-8")
    payload = mod.read_attack_path(run_dir)
    assert payload["available"] is False
    assert "unreadable" in (payload["reason"] or "").lower()
