"""Unit tests for authorized-target URL gate (no live Strix spawn)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load():
    path = (
        Path(__file__).resolve().parents[1]
        / "strix"
        / "interface"
        / "viewer"
        / "authorized_scan.py"
    )
    spec = importlib.util.spec_from_file_location("authorized_scan_under_test", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_refuse_without_authorization(tmp_path: Path) -> None:
    mod = _load()
    out = mod.queue_authorized_scan(
        target_url="https://example.com",
        authorized=False,
        runs_base=tmp_path / "strix_runs",
        start_process=False,
    )
    assert out["ok"] is False
    assert out["error"] == "authorization_required"


def test_invalid_url_rejected(tmp_path: Path) -> None:
    mod = _load()
    out = mod.queue_authorized_scan(
        target_url="not a url",
        authorized=True,
        runs_base=tmp_path / "strix_runs",
        start_process=False,
    )
    assert out["ok"] is False
    assert out["error"] == "invalid_url"


def test_strip_url_fragment() -> None:
    mod = _load()
    assert (
        mod.normalize_target_url("https://qldt.example.edu.vn/#/home")
        == "https://qldt.example.edu.vn/"
    )


def test_authorized_queue_dry(tmp_path: Path) -> None:
    mod = _load()
    runs = tmp_path / "strix_runs"
    out = mod.queue_authorized_scan(
        target_url="https://lab.example.com/app#frag",
        authorized=True,
        runs_base=runs,
        start_process=False,
    )
    assert out["ok"] is True
    assert out["scan_started"] is False
    assert out["target_url"] == "https://lab.example.com/app"
    assert "#" not in out["target_url"]
    ack = Path(out["authorization_file"])
    assert ack.is_file()
    data = json.loads(ack.read_text(encoding="utf-8"))
    assert data["authorized"] is True


def test_demo_fixture_requires_auth(tmp_path: Path) -> None:
    mod = _load()
    out = mod.stage_authorized_demo_fixture(
        target_url="https://lab.example.com",
        authorized=False,
        runs_base=tmp_path / "strix_runs",
    )
    assert out["ok"] is False
    assert out["error"] == "authorization_required"


def test_demo_fixture_relabels_and_switches(tmp_path: Path) -> None:
    mod = _load()
    repo = Path(__file__).resolve().parents[1]
    out = mod.stage_authorized_demo_fixture(
        target_url="https://lab.example.com/#/x",
        authorized=True,
        runs_base=tmp_path / "strix_runs",
        repo_root=repo,
    )
    assert out["ok"] is True
    assert out["switch_to_run"] == out["run_name"]
    assert out["target_url"] == "https://lab.example.com/"
    run_dir = Path(out["run_dir"])
    run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert run.get("synthetic_demo") is True
    assert run["targets"] == ["https://lab.example.com/"]
    assert "app.example.com" not in json.dumps(run.get("targets_info"))
    vulns = json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert isinstance(vulns, list) and vulns
    assert all(v.get("target") == "https://lab.example.com/" for v in vulns if isinstance(v, dict))
    assert (run_dir / "SYNTHETIC_DEMO.txt").is_file()
