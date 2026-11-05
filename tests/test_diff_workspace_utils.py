"""Tests for diff classification and workspace-subdir assignment in interface.utils."""

from __future__ import annotations

from typing import Any

from strix.interface.utils import (
    DiffEntry,
    _classify_diff_entries,
    assign_workspace_subdirs,
)


def _local_target(path: str) -> dict[str, Any]:
    return {"type": "local_code", "details": {"target_path": path}}


def test_assign_workspace_subdirs_avoids_suffix_collision() -> None:
    # Base names derive to ["api-2", "api", "api"]; the third target's naive
    # suffix "api-2" would collide with the first, silently dropping a repo.
    targets = [
        _local_target("/srv/api-2"),
        _local_target("/srv/api"),
        _local_target("/other/api"),
    ]

    assign_workspace_subdirs(targets)

    subdirs = [t["details"]["workspace_subdir"] for t in targets]
    assert len(set(subdirs)) == 3
    assert subdirs[0] == "api-2"
    assert subdirs[1] == "api"
    assert subdirs[2] not in {"api-2", "api"}


def test_assign_workspace_subdirs_suffix_does_not_poison_later_base() -> None:
    # Base names ["api", "api", "api-2"]: the second "api" target allocates the
    # subdir "api-2"; the later real "api-2" target must still get a unique,
    # non-colliding subdir without the earlier allocation poisoning its counter.
    targets = [
        _local_target("/srv/api"),
        _local_target("/other/api"),
        _local_target("/srv/api-2"),
    ]

    assign_workspace_subdirs(targets)

    subdirs = [t["details"]["workspace_subdir"] for t in targets]
    assert len(set(subdirs)) == 3
    assert subdirs[0] == "api"
    assert subdirs[1] == "api-2"
    assert subdirs[2].startswith("api-2")


def test_classify_diff_entries_copy_is_added_not_modified() -> None:
    result = _classify_diff_entries(
        [DiffEntry(status="C", path="new.py", old_path="orig.py", similarity=100)]
    )

    assert "new.py" in result["added_files"]
    assert "new.py" not in result["modified_files"]
    assert "new.py" in result["analyzable_files"]
