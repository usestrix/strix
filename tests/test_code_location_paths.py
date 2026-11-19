"""code_locations accept the sandbox-absolute path agents naturally report.

Agents see the target at /workspace/<subdir>/... and report code_locations with that
absolute path. Rejecting it as "must be relative" silently drops the report — the
cause of findings-detected-but-never-filed (findings=N filed_reports=0; see
usestrix/strix#1439). The normalizer now strips the workspace root and the per-target
mount subdir so the path is repo-root-relative and files, while paths genuinely outside
the workspace are still rejected.
"""

from __future__ import annotations

from strix.tools.reporting.tool import (
    _normalize_code_locations,
    _to_workspace_relative,
    _validate_code_locations,
)


def test_workspace_absolute_becomes_repo_relative() -> None:
    # The leading mount subdir (b8bLSpkh) is Strix's per-target mount point, not
    # part of the repo; SARIF/report consumers want a repo-root-relative path.
    assert (
        _to_workspace_relative("/workspace/b8bLSpkh/src/picklescan/scanner.py")
        == "src/picklescan/scanner.py"
    )


def test_relative_path_unchanged() -> None:
    assert _to_workspace_relative("src/picklescan/scanner.py") == "src/picklescan/scanner.py"


def test_outside_workspace_left_absolute() -> None:
    assert _to_workspace_relative("/etc/passwd") == "/etc/passwd"


def test_bare_mount_subdir_has_nothing_to_strip() -> None:
    # /workspace/<subdir> with no file beneath it: only the subdir component is
    # left after stripping the root, and there is nothing repo-relative to keep.
    assert _to_workspace_relative("/workspace/b8bLSpkh") == "b8bLSpkh"


def test_absolute_workspace_location_normalizes_and_validates() -> None:
    loc = [
        {
            "file": "/workspace/b8bLSpkh/src/picklescan/scanner.py",
            "start_line": 10,
            "end_line": 12,
            "snippet": "x",
        }
    ]
    normalized = _normalize_code_locations(loc)
    assert normalized is not None
    assert normalized[0]["file"] == "src/picklescan/scanner.py"
    assert _validate_code_locations(normalized) == []  # files cleanly now


def test_outside_workspace_absolute_still_rejected() -> None:
    loc = [{"file": "/etc/passwd", "start_line": 1, "end_line": 1}]
    normalized = _normalize_code_locations(loc)
    assert normalized is not None
    errs = _validate_code_locations(normalized)
    assert errs and "must be relative" in errs[0]
