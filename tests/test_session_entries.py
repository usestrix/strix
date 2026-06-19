"""Tests for build_session_entries: splitting copied vs bind-mounted sources."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agents.sandbox.entries import LocalDir

from strix.runtime.session_manager import build_session_entries


if TYPE_CHECKING:
    from pathlib import Path


def _source(subdir: str, path: str, *, mount: bool = False) -> dict[str, Any]:
    return {"source_path": path, "workspace_subdir": subdir, "mount": mount}


def test_copied_source_becomes_localdir_entry(tmp_path: Path) -> None:
    entries, bind_mounts = build_session_entries([_source("repo", str(tmp_path))])

    assert bind_mounts == []
    assert isinstance(entries["repo"], LocalDir)
    assert entries["repo"].src == tmp_path.resolve()


def test_mounted_source_becomes_bind_mount(tmp_path: Path) -> None:
    entries, bind_mounts = build_session_entries([_source("repo", str(tmp_path), mount=True)])

    assert entries == {}
    assert bind_mounts == [
        {
            "source": str(tmp_path.resolve()),
            "target": "/workspace/repo",
            "read_only": True,
        }
    ]


def test_mixed_sources_split_correctly(tmp_path: Path) -> None:
    copied = tmp_path / "copied"
    mounted = tmp_path / "mounted"
    copied.mkdir()
    mounted.mkdir()

    entries, bind_mounts = build_session_entries(
        [
            _source("copied", str(copied)),
            _source("mounted", str(mounted), mount=True),
        ]
    )

    assert list(entries) == ["copied"]
    assert isinstance(entries["copied"], LocalDir)
    assert [m["target"] for m in bind_mounts] == ["/workspace/mounted"]


def test_incomplete_sources_are_skipped() -> None:
    entries, bind_mounts = build_session_entries(
        [
            {"source_path": "", "workspace_subdir": "x"},
            {"source_path": "/p", "workspace_subdir": ""},
        ]
    )
    assert entries == {}
    assert bind_mounts == []
