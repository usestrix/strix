"""Helpers that read the resolved scan targets.

Kept free of heavy imports on purpose: the interface layer needs them before the
agents SDK may be imported.
"""

from __future__ import annotations

from typing import Any


def is_whitebox_scan(targets_info: list[dict[str, Any]] | None) -> bool:
    """True when any target puts source code in front of the agent (a source-aware scan).

    That is a local directory, and also a repository that was cloned for the scan: both
    end up in the sandbox workspace, as ``collect_local_sources`` in
    ``strix.interface.utils`` collects them. A repository that was not cloned has no
    source to read, so it does not count.
    """
    for target in targets_info or []:
        target_type = target.get("type")
        if target_type == "local_code":
            return True
        if target_type == "repository" and (target.get("details") or {}).get("cloned_repo_path"):
            return True
    return False
