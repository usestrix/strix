"""Materialize writable, symlink-safe copies of user-owned source trees."""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def validate_workspace_subdir(value: Any) -> str:
    """Return a workspace-relative subdirectory that cannot traverse upward."""
    subdir = str(value or "workspace")
    relative = Path(subdir)
    if relative.is_absolute() or relative == Path() or ".." in relative.parts:
        raise ValueError(f"invalid workspace_subdir {subdir!r}: must stay under /workspace")
    return subdir


def _copy_tree(
    source: Path,
    destination: Path,
    *,
    root: Path,
    excluded: tuple[Path, ...],
    seen: frozenset[Path],
) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with os.scandir(source) as entries:
        for entry in entries:
            src = Path(entry.path)
            dst = destination / entry.name
            resolved = src.resolve(strict=False)
            if any(_is_within(resolved, blocked) for blocked in excluded):
                continue
            if entry.name == "strix_runs" and entry.is_dir(follow_symlinks=False):
                continue
            if entry.is_symlink():
                target = src.resolve(strict=False)
                if not target.exists() or not _is_within(target, root) or target in seen:
                    logger.warning("isolated workspace: dropping unsafe symlink %s", src)
                    continue
                if target.is_dir():
                    _copy_tree(
                        target,
                        dst,
                        root=root,
                        excluded=excluded,
                        seen=seen | {target},
                    )
                elif target.is_file():
                    shutil.copy2(target, dst)
                continue
            if entry.is_dir(follow_symlinks=False):
                _copy_tree(src, dst, root=root, excluded=excluded, seen=seen)
            elif entry.is_file(follow_symlinks=False):
                # Never hard-link: the destination is intentionally writable.
                shutil.copy2(src, dst)


def materialize_isolated_sources(
    local_sources: list[dict[str, Any]],
    *,
    run_dir: Path,
) -> list[dict[str, Any]]:
    """Replace user-owned live mounts with durable per-run writable copies."""
    workspace_root = (run_dir / ".state" / "workspaces").resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)
    result: list[dict[str, Any]] = []
    for source in local_sources:
        item = dict(source)
        if not item.get("protect_metadata"):
            result.append(item)
            continue
        # Staging runs once in `prepare_run` and again in `run_strix_scan`, and `--resume`
        # rehydrates already-staged entries, so the origin is read back from
        # `original_source_path` once set. Taking it from `source_path` every time would
        # make the copy its own origin on the second pass: a re-copy would then read the
        # destination it had just cleared and leave an empty workspace behind.
        origin = (
            Path(str(item.get("original_source_path") or item.get("source_path") or ""))
            .expanduser()
            .resolve()
        )
        subdir = validate_workspace_subdir(item.get("workspace_subdir"))
        destination = (workspace_root / subdir).resolve()
        if destination == workspace_root or not _is_within(destination, workspace_root):
            raise ValueError(
                f"invalid workspace_subdir {subdir!r}: destination escapes isolated workspace"
            )
        complete_marker = workspace_root / f".{subdir}.complete"
        if complete_marker.is_symlink() or not _is_within(
            complete_marker.resolve(), workspace_root
        ):
            raise ValueError(
                f"invalid workspace_subdir {subdir!r}: marker escapes isolated workspace"
            )
        if destination.exists() and not complete_marker.is_file():
            shutil.rmtree(destination, ignore_errors=True)
        if not destination.exists():
            try:
                _copy_tree(
                    origin,
                    destination,
                    root=origin,
                    excluded=(run_dir.resolve(), destination),
                    seen=frozenset({origin}),
                )
            except Exception:
                shutil.rmtree(destination, ignore_errors=True)
                complete_marker.unlink(missing_ok=True)
                raise
            complete_marker.write_text(str(origin), encoding="utf-8")
            logger.info("materialized isolated workspace %s -> %s", origin, destination)
        item["original_source_path"] = str(origin)
        item["source_path"] = str(destination)
        item["workspace_mode"] = "isolated_copy"
        # `protect_metadata` is deliberately preserved: the copy's `.git`, `.agents`, and
        # `.codex` still stay read-only. They are agent-instruction and repository state
        # that persist across `--resume`, so a run that ingested injected target content
        # must not be able to rewrite them.
        result.append(item)
    return result
