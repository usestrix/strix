"""Tests for --workspace-mount: a sandbox mount that is not a target."""

from __future__ import annotations

import argparse
import importlib
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from strix.interface.scan_setup import attach_workspace_mount
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


def test_workspace_mount_is_parsed_and_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--target", "https://test.com/", "--workspace-mount", str(source), "-n"],
    )

    args = cli_main.parse_arguments()

    assert args.workspace_mount == str(source.resolve())


def test_workspace_mount_is_not_a_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole point: it is mounted, but nothing about it is in scope."""
    source = tmp_path / "src"
    source.mkdir()
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--target", "https://test.com/", "--workspace-mount", str(source), "-n"],
    )

    args = cli_main.parse_arguments()

    assert [target["original"] for target in args.targets_info] == ["https://test.com/"]
    assert str(source.resolve()) not in str(args.targets_info)


def test_workspace_mount_rejects_a_missing_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "strix",
            "--target",
            "https://test.com/",
            "--workspace-mount",
            str(tmp_path / "nope"),
            "-n",
        ],
    )

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()


def test_workspace_mount_conflicts_with_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--resume", "some-run", "--workspace-mount", str(source), "-n"],
    )

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()


def test_attach_workspace_mount_produces_a_read_path_under_workspace(tmp_path: Path) -> None:
    """attach -> local_sources -> bind mount at /workspace/<name>."""
    source = tmp_path / "DVLS"
    source.mkdir()
    args = argparse.Namespace(workspace_mount=str(source), local_sources=[])

    attach_workspace_mount(args)

    assert args.workspace_subdir == "DVLS"
    assert args.local_sources[0]["source_path"] == str(source)
    assert args.local_sources[0]["protect_metadata"] is True

    mounts = build_bind_mounts(args.local_sources)
    targets = [mount["target"] for mount in mounts]
    assert "/workspace/DVLS" in targets


def test_attach_workspace_mount_is_a_noop_without_the_flag() -> None:
    args = argparse.Namespace(local_sources=[])

    attach_workspace_mount(args)

    assert args.local_sources == []
