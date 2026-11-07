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
    assert "written permission" in out["message"].lower() or "own" in out["message"].lower()


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


def test_authorized_queue_dry(tmp_path: Path) -> None:
    mod = _load()
    runs = tmp_path / "strix_runs"
    out = mod.queue_authorized_scan(
        target_url="https://lab.example.com/app",
        authorized=True,
        runs_base=runs,
        start_process=False,
    )
    assert out["ok"] is True
    assert out["scan_started"] is False
    assert out["simulated_lateral_default"] is False
    assert "MODELED" in out["modeled_note"]
    ack = Path(out["authorization_file"])
    assert ack.is_file()
    data = json.loads(ack.read_text(encoding="utf-8"))
    assert data["authorized"] is True
    assert data["target_url"].startswith("https://lab.example.com")


def test_demo_fixture_requires_auth(tmp_path: Path) -> None:
    mod = _load()
    out = mod.stage_authorized_demo_fixture(
        target_url="https://lab.example.com",
        authorized=False,
        runs_base=tmp_path / "strix_runs",
    )
    assert out["ok"] is False
    assert out["error"] == "authorization_required"
