"""--resume re-validates persisted mounts against the mount guard.

run.json lives on disk under the scanned tree and is treated as untrusted on
resume: workspace_mount, repository cloned_repo_path and workspace_files
sources must all pass the same checks a fresh invocation would apply.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from strix.interface.cli_args import _load_resume_state


def _parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser()


def _resume_args(**overrides: object) -> argparse.Namespace:
    defaults: dict[str, object] = {
        "resume": "old-run",
        "targets_info": [],
        "instruction": None,
        "user_instruction": None,
        "local_sources": [],
        "workspace_mount": None,
        "workspace_files": None,
        "diff_scope": None,
        "scan_mode": "quick",
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _write_run(tmp_path: Path, record: dict[str, object]) -> None:
    run_dir = tmp_path / "strix_runs" / "old-run"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")


def _patch_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))
    return home


def test_resume_rejects_forbidden_workspace_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _patch_home(tmp_path, monkeypatch)
    monkeypatch.chdir(tmp_path)
    _write_run(
        tmp_path,
        {"targets_info": [], "workspace_mount": str(home), "workspace_files": []},
    )

    with pytest.raises(SystemExit):
        _load_resume_state(_resume_args(), _parser())


def test_resume_rejects_system_workspace_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run(
        tmp_path,
        {"targets_info": [], "workspace_mount": "/etc", "workspace_files": []},
    )

    with pytest.raises(SystemExit):
        _load_resume_state(_resume_args(), _parser())


def test_resume_rejects_forbidden_cloned_repo_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run(
        tmp_path,
        {
            "targets_info": [{"type": "repository", "details": {"cloned_repo_path": "/etc"}}],
            "workspace_mount": None,
            "workspace_files": [],
        },
    )

    with pytest.raises(SystemExit):
        _load_resume_state(_resume_args(), _parser())


def test_resume_rejects_credential_workspace_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _patch_home(tmp_path, monkeypatch)
    ssh = home / ".ssh"
    ssh.mkdir()
    key = ssh / "id_rsa"
    key.write_text("key", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _write_run(
        tmp_path,
        {
            "targets_info": [],
            "workspace_mount": None,
            "workspace_files": [{"source_path": str(key), "workspace_path": "id_rsa"}],
        },
    )

    with pytest.raises(SystemExit):
        _load_resume_state(_resume_args(), _parser())


def test_resume_accepts_a_clean_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run(
        tmp_path,
        {
            "targets_info": [],
            "user_instruction": "scan the target",
            "workspace_mount": None,
            "workspace_files": [],
        },
    )

    args = _resume_args()
    _load_resume_state(args, _parser())

    assert args.user_instruction == "scan the target"
