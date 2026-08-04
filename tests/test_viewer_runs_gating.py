"""Tests for the /api/runs gating and the ?run= resolver (pure functions)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from strix.interface.viewer.server import build_runs_payload, resolve_run_dir


if TYPE_CHECKING:
    from pathlib import Path


def _make_run(base: Path, name: str, *, severity: str = "high") -> Path:
    run_dir = base / "strix_runs" / name
    run_dir.mkdir(parents=True)
    record = {
        "run_name": name,
        "targets_info": [{"original": f"https://{name}.example.com"}],
        "scan_mode": "deep",
        "status": "completed",
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-01-01T00:10:00Z",
    }
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps([{"title": "v", "severity": severity}]), encoding="utf-8"
    )
    return run_dir


def test_runs_payload_locked_when_unverified(tmp_path: Path) -> None:
    base = tmp_path / "strix_runs"
    _make_run(tmp_path, "alpha")
    _make_run(tmp_path, "beta")

    payload = build_runs_payload(base, verified=False)
    assert payload["locked"] is True
    assert payload["count"] == 2
    assert payload["runs"] == []


def test_runs_payload_lists_when_verified(tmp_path: Path) -> None:
    base = tmp_path / "strix_runs"
    _make_run(tmp_path, "alpha", severity="critical")
    _make_run(tmp_path, "beta", severity="info")

    payload = build_runs_payload(base, verified=True)
    assert payload["locked"] is False
    assert payload["count"] == 2
    assert len(payload["runs"]) == 2
    entry = next(r for r in payload["runs"] if r["name"] == "alpha")
    assert entry["target"] == "https://alpha.example.com"
    assert entry["severity_counts"]["critical"] == 1
    # "info" folds into low, matching the SPA's bucketing.
    beta = next(r for r in payload["runs"] if r["name"] == "beta")
    assert beta["severity_counts"]["low"] == 1


def test_runs_payload_empty_base(tmp_path: Path) -> None:
    payload = build_runs_payload(tmp_path / "strix_runs", verified=True)
    assert payload == {"locked": False, "count": 0, "runs": []}


def test_resolve_run_dir_defaults_when_absent(tmp_path: Path) -> None:
    base = tmp_path / "strix_runs"
    default = _make_run(tmp_path, "alpha")
    assert resolve_run_dir(base, None, default) == default
    assert resolve_run_dir(base, "", default) == default


def test_resolve_run_dir_valid_named_run(tmp_path: Path) -> None:
    base = tmp_path / "strix_runs"
    default = _make_run(tmp_path, "alpha")
    other = _make_run(tmp_path, "beta")
    assert resolve_run_dir(base, "beta", default) == other


def test_resolve_run_dir_rejects_unknown_and_traversal(tmp_path: Path) -> None:
    base = tmp_path / "strix_runs"
    default = _make_run(tmp_path, "alpha")
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "run.json").write_text("{}", encoding="utf-8")

    assert resolve_run_dir(base, "nope", default) is None
    assert resolve_run_dir(base, "../secret", default) is None
    assert resolve_run_dir(base, "../../etc", default) is None
