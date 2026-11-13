"""The engine skips cloning when a repository artifact was delivered already.

The backend downloads the repo and packs it as an artifact (``audit.request`` carries
``artifact_id``); the orchestrator unpacks it and pre-sets ``cloned_repo_path`` on the
target details. ``prepare_run`` must then keep that path instead of cloning again.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from strix.interface import scan_setup


FAKE_CLONE_PATH = "/nonexistent-cloned-by-helper"


def _args_with_repo(tmp_path: Path, preloaded: str | None) -> argparse.Namespace:
    args = argparse.Namespace(
        target=["https://github.com/inditex/demo"],
        target_list=None,
        run_name="r1",
        resume=None,
        scope_mode=None,
        diff_base=None,
        non_interactive=True,
    )
    args.targets_info = [
        {
            "type": "repository",
            "details": {
                "target_repo": "https://github.com/inditex/demo",
                **({"cloned_repo_path": preloaded} if preloaded else {}),
            },
            "original": "https://github.com/inditex/demo",
        }
    ]
    return args


def _patch_helpers(
    monkeypatch: pytest.MonkeyPatch, calls: list[str], cloned: str = FAKE_CLONE_PATH
) -> None:
    monkeypatch.setattr(
        scan_setup, "clone_repository", lambda *a, **k: calls.append("clone") or cloned
    )
    monkeypatch.setattr(scan_setup, "collect_local_sources", lambda targets: [])
    monkeypatch.setattr(scan_setup, "stage_api_specs", lambda targets, run: [])

    class _Diff:
        metadata = None
        instruction_block = None

    monkeypatch.setattr(scan_setup, "resolve_diff_scope_context", lambda *a, **k: _Diff())
    monkeypatch.setattr(scan_setup, "_persist_run_record", lambda args: None)
    monkeypatch.setattr(scan_setup, "attach_workspace_mount", lambda args: None)


def test_preloaded_repo_is_not_cloned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    delivered = tmp_path / "demo"
    delivered.mkdir()
    calls: list[str] = []
    _patch_helpers(monkeypatch, calls)

    args = _args_with_repo(tmp_path, str(delivered))
    scan_setup.prepare_run(args)

    assert calls == []
    assert args.targets_info[0]["details"]["cloned_repo_path"] == str(delivered)


def test_missing_preload_falls_back_to_clone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    _patch_helpers(monkeypatch, calls)

    args = _args_with_repo(tmp_path, str(tmp_path / "does-not-exist"))
    scan_setup.prepare_run(args)

    assert calls == ["clone"]
    assert args.targets_info[0]["details"]["cloned_repo_path"] == FAKE_CLONE_PATH


def test_no_preload_field_clones_as_before(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    _patch_helpers(monkeypatch, calls)

    args = _args_with_repo(tmp_path, None)
    scan_setup.prepare_run(args)

    assert calls == ["clone"]
