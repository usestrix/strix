"""One local git branch per approved patch, in the repository the user scanned.

The branch is built with a private index, so the user's working tree, index,
and current branch stay as they are. Nothing is pushed.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess  # nosec B404 - runs the user's own git with fixed arguments
import tempfile
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

_IDENTITY = {
    "GIT_AUTHOR_NAME": "Strix",
    "GIT_AUTHOR_EMAIL": "fixes@strix.ai",
    "GIT_COMMITTER_NAME": "Strix",
    "GIT_COMMITTER_EMAIL": "fixes@strix.ai",
}


def _host_repository(fix: dict[str, Any], local_sources: list[dict[str, Any]]) -> Path | None:
    """The scanned directory on this machine that the patch was made for."""
    for source in local_sources:
        subdir = source.get("workspace_subdir")
        workspace_path = f"/workspace/{subdir}" if subdir else "/workspace"
        if workspace_path == fix.get("repository") and source.get("source_path"):
            return Path(str(source["source_path"]))
    return None


def create_fix_branch(repository: Path, report: dict[str, Any], patch: str) -> str | None:
    """Commit ``patch`` on the scanned commit as a new branch. None when git refuses.

    Git refuses when the directory is not a repository, or when the scan read
    files that differ from the scanned commit, so the patch does not fit it.
    """
    fix = report.get("fix") or {}
    base = str(fix.get("base_commit") or "")
    git = shutil.which("git")
    if git is None or not re.fullmatch(r"[0-9a-f]{40,64}", base):
        return None
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", str(report.get("id") or "finding")).strip("-.")
    branch = f"strix/fix-{slug}-{str(fix.get('digest') or '')[:8]}"
    message = f"fix: {report.get('title') or report.get('id')}\n\nReviewed patch from Strix."

    with tempfile.TemporaryDirectory() as scratch:
        env = {**os.environ, **_IDENTITY, "GIT_INDEX_FILE": str(Path(scratch) / "index")}

        def run(*args: str, stdin: str | None = None) -> str:
            done = subprocess.run(  # noqa: S603  # nosec B603 - fixed git arguments
                [git, "-C", str(repository), *args],
                input=stdin,
                capture_output=True,
                text=True,
                env=env,
                check=True,
                timeout=120,
            )
            return done.stdout.strip()

        try:
            # The name carries the digest of the patched tree, so a branch that
            # already has it holds this patch.
            if run("for-each-ref", f"refs/heads/{branch}"):
                return branch
            run("read-tree", base)
            run("apply", "--cached", "--binary", "-", stdin=patch)
            commit = run("commit-tree", run("write-tree"), "-p", base, "-m", message)
            # The empty old value makes git fail when the branch already exists.
            run("update-ref", f"refs/heads/{branch}", commit, "")
        except (OSError, subprocess.SubprocessError) as error:
            detail = getattr(error, "stderr", "") or str(error)
            logger.info("no branch for %s in %s: %s", report.get("id"), repository, detail)
            return None
    return branch


def create_fix_branches(
    reports: list[dict[str, Any]],
    *,
    run_dir: Path,
    local_sources: list[dict[str, Any]],
) -> dict[str, str]:
    """Create the branch of every approved patch that has none. Finding ID to branch."""
    branches: dict[str, str] = {}
    for report in reports:
        fix = report.get("fix")
        if not isinstance(fix, dict) or fix.get("branch") or not fix.get("patch_file"):
            continue
        repository = _host_repository(fix, local_sources)
        patch_path = run_dir / str(fix["patch_file"])
        if repository is None or not patch_path.is_file():
            continue
        branch = create_fix_branch(repository, report, patch_path.read_bytes().decode("utf-8"))
        if branch:
            fix["branch"] = branch
            branches[str(report.get("id"))] = branch
    return branches
