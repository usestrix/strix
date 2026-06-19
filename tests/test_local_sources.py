"""Tests for local-source sizing and ``--mount`` target helpers in interface.utils."""

from __future__ import annotations

import logging
import os
import sys
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from pathlib import Path

from strix.interface.utils import (
    build_mount_targets_info,
    collect_local_sources,
    dedupe_local_targets,
    directory_size_bytes,
    find_oversized_local_targets,
)


def _write_file(path: Path, size: int) -> None:
    path.write_bytes(b"x" * size)


def _local_target(target_path: str, *, mount: bool = False) -> dict[str, Any]:
    details: dict[str, Any] = {"target_path": target_path, "workspace_subdir": "repo"}
    if mount:
        details["mount"] = True
    return {"type": "local_code", "details": details, "original": target_path}


def test_directory_size_empty_dir_is_zero(tmp_path: Path) -> None:
    assert directory_size_bytes(tmp_path) == 0


def test_directory_size_sums_flat_and_nested_files(tmp_path: Path) -> None:
    _write_file(tmp_path / "a.txt", 100)
    nested = tmp_path / "sub" / "deep"
    nested.mkdir(parents=True)
    _write_file(nested / "b.txt", 250)
    assert directory_size_bytes(tmp_path) == 350


def test_directory_size_skips_symlinks(tmp_path: Path) -> None:
    _write_file(tmp_path / "real.txt", 100)
    (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")
    # The symlink target is counted once via the real file, not doubled.
    assert directory_size_bytes(tmp_path) == 100


@pytest.mark.skipif(sys.platform == "win32", reason="relies on POSIX permissions")
def test_directory_size_logs_and_skips_unreadable_subdir(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root bypasses directory permissions")
    _write_file(tmp_path / "top.txt", 100)
    locked = tmp_path / "locked"
    locked.mkdir()
    _write_file(locked / "secret.bin", 9999)
    locked.chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING):
            size = directory_size_bytes(tmp_path)
    finally:
        locked.chmod(0o755)
    # The unreadable subtree is excluded (not silently treated as readable) and
    # the omission is logged rather than vanishing without a trace.
    assert size == 100
    assert any("Could not read" in record.message for record in caplog.records)


def test_find_oversized_returns_nothing_under_limit(tmp_path: Path) -> None:
    _write_file(tmp_path / "a.txt", 100)
    targets = [_local_target(str(tmp_path))]
    assert find_oversized_local_targets(targets, max_bytes=1000) == []


def test_find_oversized_returns_target_over_limit(tmp_path: Path) -> None:
    _write_file(tmp_path / "big.bin", 500)
    targets = [_local_target(str(tmp_path))]
    result = find_oversized_local_targets(targets, max_bytes=100)
    assert result == [(str(tmp_path), 500)]


def test_find_oversized_ignores_mounted_targets(tmp_path: Path) -> None:
    _write_file(tmp_path / "big.bin", 500)
    targets = [_local_target(str(tmp_path), mount=True)]
    assert find_oversized_local_targets(targets, max_bytes=100) == []


def test_find_oversized_ignores_non_local_targets() -> None:
    targets = [{"type": "web_application", "details": {"target_url": "https://x"}}]
    assert find_oversized_local_targets(targets, max_bytes=1) == []


@pytest.mark.parametrize("disabled", [0, -1])
def test_find_oversized_disabled_for_non_positive_limit(tmp_path: Path, disabled: int) -> None:
    _write_file(tmp_path / "big.bin", 500)
    targets = [_local_target(str(tmp_path))]
    assert find_oversized_local_targets(targets, max_bytes=disabled) == []


def test_collect_local_sources_propagates_mount_flag() -> None:
    copied = _local_target("/copied")
    copied["details"]["workspace_subdir"] = "copied"
    mounted = _local_target("/mounted", mount=True)
    mounted["details"]["workspace_subdir"] = "mounted"

    sources = collect_local_sources([copied, mounted])

    by_path = {s["source_path"]: s for s in sources}
    assert by_path["/copied"]["mount"] is False
    assert by_path["/mounted"]["mount"] is True


def test_collect_local_sources_repository_is_never_mounted() -> None:
    repo = {
        "type": "repository",
        "details": {"cloned_repo_path": "/clone", "workspace_subdir": "clone"},
    }
    sources = collect_local_sources([repo])
    assert sources == [{"source_path": "/clone", "workspace_subdir": "clone", "mount": False}]


def test_build_mount_targets_info_for_valid_dir(tmp_path: Path) -> None:
    result = build_mount_targets_info([str(tmp_path)])
    assert len(result) == 1
    entry = result[0]
    assert entry["type"] == "local_code"
    assert entry["details"]["mount"] is True
    assert entry["details"]["target_path"] == str(tmp_path.resolve())


def test_build_mount_targets_info_rejects_missing_path(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    with pytest.raises(ValueError, match="not an existing directory"):
        build_mount_targets_info([str(missing)])


def test_build_mount_targets_info_rejects_file(tmp_path: Path) -> None:
    file_path = tmp_path / "a-file.txt"
    _write_file(file_path, 10)
    with pytest.raises(ValueError, match="not an existing directory"):
        build_mount_targets_info([str(file_path)])


@pytest.mark.parametrize("empty", ["", "   "])
def test_build_mount_targets_info_rejects_empty_path(empty: str) -> None:
    # An empty path would otherwise resolve to the current working directory
    # and silently bind-mount it into the sandbox.
    with pytest.raises(ValueError, match="must not be empty"):
        build_mount_targets_info([empty])


def test_dedupe_keeps_distinct_targets_in_order() -> None:
    targets = [
        _local_target("/a"),
        {"type": "web_application", "details": {"target_url": "https://x"}},
        _local_target("/b", mount=True),
    ]
    assert dedupe_local_targets(targets) == targets


def test_dedupe_mount_supersedes_copied_same_path() -> None:
    copied = _local_target("/repo")
    mounted = _local_target("/repo", mount=True)

    # Copied first, then mounted: the single surviving entry is the mount.
    result = dedupe_local_targets([copied, mounted])
    assert len(result) == 1
    assert result[0]["details"]["mount"] is True

    # Order-independent: mounted first, copied second also yields the mount.
    result_rev = dedupe_local_targets([mounted, copied])
    assert len(result_rev) == 1
    assert result_rev[0]["details"]["mount"] is True


def test_dedupe_collapses_duplicate_mounts() -> None:
    result = dedupe_local_targets(
        [_local_target("/repo", mount=True), _local_target("/repo", mount=True)]
    )
    assert len(result) == 1
