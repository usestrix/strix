"""Tests for DOPS-1157 hard containment: read-only evidence targets plus a
writable, out-of-scope workspace mount.

The contract under test: ``--read-only-local-targets`` makes every local-code
target bind mount read-only; ``--workspace-mount`` stays writable, is not an
assessment target, and may coexist with real targets. Each test here would fail
if the target became writable, the workspace became read-only or in-scope, or
the root task lied about either.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from strix.core.inputs import build_root_task, build_scope_context
from strix.interface.scan_setup import attach_workspace_mount, build_targets_info
from strix.interface.utils import (
    check_mountable_dir,
    collect_local_sources,
)
from strix.runtime.session_manager import build_bind_mounts


if TYPE_CHECKING:
    from pathlib import Path

cli_main: Any = importlib.import_module("strix.interface.main")


def _stub_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(max_local_copy_mb=1024)),
    )


def _local_target(target_path: str, *, read_only: bool = False) -> dict[str, Any]:
    details: dict[str, Any] = {"target_path": target_path, "workspace_subdir": "repo"}
    if read_only:
        details["read_only"] = True
    return {"type": "local_code", "details": details, "original": target_path}


# --- Parser: the flags exist and propagate ----------------------------------


def test_parse_arguments_accepts_read_only_local_targets_and_workspace_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "strix",
            "--target",
            str(project),
            "--read-only-local-targets",
            "--workspace-mount",
            str(workspace),
            "-n",
        ],
    )

    args = cli_main.parse_arguments()

    assert args.read_only_local_targets is True
    assert args.workspace_mount == str(workspace)


def test_parse_arguments_keeps_targets_writable_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _stub_settings(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["strix", "--target", str(project), "-n"])

    args = cli_main.parse_arguments()

    assert args.read_only_local_targets is False
    target_details = args.targets_info[0]["details"]
    assert not target_details.get("read_only")


def test_parse_arguments_stamps_local_code_targets_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--target", str(project), "--read-only-local-targets", "-n"],
    )

    args = cli_main.parse_arguments()

    assert args.targets_info[0]["type"] == "local_code"
    assert args.targets_info[0]["details"]["read_only"] is True


def test_parse_arguments_rejects_a_forbidden_workspace_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_settings(monkeypatch)
    forbidden = tmp_path / "home"
    forbidden.mkdir()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "strix",
            "--target",
            str(tmp_path / "whatever"),
            "--workspace-mount",
            str(forbidden),
            "-n",
        ],
    )
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda _cls: forbidden))

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "--workspace-mount" in capsys.readouterr().err


def test_parse_arguments_rejects_a_missing_workspace_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "strix",
            "--target",
            str(tmp_path / "whatever"),
            "--workspace-mount",
            str(tmp_path / "nope"),
            "-n",
        ],
    )

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "--workspace-mount" in capsys.readouterr().err


# --- Propagation: read_only reaches the sandbox mounts -----------------------


def test_read_only_target_propagates_to_a_read_only_bind_mount(
    tmp_path: Path,
) -> None:
    sources = collect_local_sources([_local_target(str(tmp_path), read_only=True)])

    assert sources[0]["read_only"] is True
    mounts = build_bind_mounts(sources)
    # Only the tree mount exists here (no .git), and it must be read-only.
    assert len(mounts) == 1
    assert mounts[0]["target"] == "/workspace/repo"
    assert mounts[0]["read_only"] is True


def test_writable_target_stays_writable_without_the_flag(tmp_path: Path) -> None:
    sources = collect_local_sources([_local_target(str(tmp_path), read_only=False)])

    assert "read_only" not in sources[0]
    mounts = build_bind_mounts(sources)
    assert mounts[0]["read_only"] is False


def test_workspace_mount_stays_writable_beside_read_only_targets(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    args = argparse.Namespace(
        target=[str(evidence)],
        target_list=None,
        targets_info=[],
        local_sources=[],
        workspace_mount=str(workspace),
        read_only_local_targets=True,
    )
    build_targets_info(args)
    # Match prepare_run's ordering: collect_local_sources first, then the
    # workspace mount is appended to those sources.
    args.local_sources = collect_local_sources(args.targets_info)

    attach_workspace_mount(args)

    evidence_subdir = args.targets_info[0]["details"]["workspace_subdir"]
    assert evidence_subdir == "evidence"
    mounts = build_bind_mounts(args.local_sources)
    by_target = {m["target"]: m["read_only"] for m in mounts}

    # Evidence target is read-only; the workspace remediation area is writable.
    assert by_target[f"/workspace/{evidence_subdir}"] is True
    workspace_mounts = [
        m for m in mounts if m["target"].startswith(f"/workspace/{args.workspace_subdir}")
    ]
    assert workspace_mounts, "workspace mount missing from bind mounts"
    assert all(m["read_only"] is False for m in workspace_mounts)


def test_workspace_mount_gets_a_unique_container_path_when_basenames_collide(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "source" / "repo"
    workspace = tmp_path / "remediation" / "repo"
    evidence.mkdir(parents=True)
    workspace.mkdir(parents=True)
    args = argparse.Namespace(
        workspace_mount=str(workspace),
        local_sources=[
            {
                "source_path": str(evidence),
                "workspace_subdir": "repo",
                "read_only": True,
            }
        ],
    )

    attach_workspace_mount(args)

    assert args.workspace_subdir == "repo-2"
    assert [source["workspace_subdir"] for source in args.local_sources] == ["repo", "repo-2"]


@pytest.mark.parametrize("relation", ["same", "workspace_child", "evidence_child"])
def test_workspace_mount_rejects_overlap_with_read_only_evidence(
    tmp_path: Path, relation: str
) -> None:
    if relation == "same":
        evidence = workspace = tmp_path / "shared"
    elif relation == "workspace_child":
        evidence = tmp_path / "evidence"
        workspace = evidence / "workspace"
    else:
        workspace = tmp_path / "workspace"
        evidence = workspace / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    workspace.mkdir(parents=True, exist_ok=True)
    args = argparse.Namespace(
        workspace_mount=str(workspace),
        local_sources=[
            {
                "source_path": str(evidence),
                "workspace_subdir": "evidence",
                "read_only": True,
            }
        ],
    )

    with pytest.raises(ValueError, match="overlaps read-only target"):
        attach_workspace_mount(args)


# --- Root task framing -------------------------------------------------------


def test_root_task_renders_a_read_only_target_as_immutable_evidence() -> None:
    task = build_root_task(
        {
            "targets": [_local_target("/evidence", read_only=True)],
        }
    )

    assert "Local Codebases:" in task
    assert "mounted read-only" in task
    assert "immutable evidence" in task

    assert "remediate in the writable working directory" not in task


def test_root_task_renders_a_writable_target_without_the_read_only_claim() -> None:
    task = build_root_task(
        {
            "targets": [_local_target("/codebase", read_only=False)],
        }
    )

    assert "Local Codebases:" in task
    assert "mounted live and writable" in task
    assert "mounted read-only" not in task


def test_root_task_renders_the_workspace_as_a_writable_remediation_area() -> None:
    task = build_root_task(
        {
            "targets": [_local_target("/evidence", read_only=True)],
            "workspace_mount": "/remediation",
            "workspace_subdir": "remediation",
        }
    )

    assert "/workspace/remediation" in task
    assert "writable" in task
    # Targets exist, so the task must not claim there is no target.
    assert "No scan target was set" not in task
    assert "remediation" in task
    assert "remediate in the writable working directory" in task


def test_root_task_claims_no_target_only_when_none_exist() -> None:
    task = build_root_task(
        {
            "targets": [],
            "workspace_mount": "/workspace-only",
            "workspace_subdir": "workspace-only",
            "user_instructions": "Do the thing",
        }
    )

    assert "No scan target was set" in task
    assert "/workspace/workspace-only" in task


def test_workspace_mount_grants_no_authorized_scope() -> None:
    scope = build_scope_context(
        {
            "targets": [_local_target("/evidence", read_only=True)],
            "workspace_mount": "/remediation",
            "workspace_subdir": "remediation",
        }
    )

    authorized = scope["authorized_targets"]
    assert [t["value"] for t in authorized] == ["/evidence"]
    assert all(
        t["type"] != "local_code" or t["workspace_path"] != "/workspace/remediation"
        for t in authorized
    )


def test_check_mountable_dir_accepts_a_workspace_project_dir(tmp_path: Path) -> None:
    project = tmp_path / "workspace-project"
    project.mkdir()
    check_mountable_dir(project)
