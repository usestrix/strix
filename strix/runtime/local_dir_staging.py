"""Symlink-safe staging for ``LocalDir`` manifest uploads.

The sandbox SDK's ``LocalDir`` walker refuses to copy symlinks at all — it
raises ``LocalDirReadError(reason="symlink_not_supported")`` on the first one
as a path-escape / TOCTOU safeguard. Real source trees (especially JS/TS
monorepos with workspace or shared-config links) routinely commit symlinks, so
handing such a tree straight to ``LocalDir`` aborts the upload before the agent
even starts.

:func:`stage_symlink_safe_dir` returns a path that is always safe to hand to
``LocalDir``:

* a tree with no symlinks is used as-is (no copy);
* otherwise the tree is copied into a temp directory with symlinks resolved:

  - a link whose target stays inside the tree is *dereferenced* (its target
    content is materialized in place), so the agent still sees the file;
  - a link that escapes the tree, dangles, or forms a cycle is *dropped* and
    never followed. Refusing to follow out-of-tree links preserves the walker's
    path-escape safety and keeps host/out-of-tree content from leaking into the
    (hostile) sandbox.

Regular files are hard-linked when possible (falling back to a copy across
devices), so the staged tree adds negligible disk for the non-symlink bulk.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from pathlib import Path


logger = logging.getLogger(__name__)

_STAGING_PREFIX = "strix-localdir-"
_DIR_ACCESS_MODE = os.R_OK | os.X_OK
_FILE_ACCESS_MODE = os.R_OK


def _is_within(target: Path, root: Path) -> bool:
    """Return whether ``target`` is ``root`` itself or nested under it."""
    if target == root:
        return True
    try:
        target.relative_to(root)
    except ValueError:
        return False
    return True


def tree_has_symlink(root: Path) -> bool:
    """Return whether ``root`` contains any symlink (file or directory)."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        for name in (*dirnames, *filenames):
            if (base / name).is_symlink():
                return True
    return False


def _needs_safe_staging(root: Path) -> bool:
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                if _entry_needs_safe_staging(entry):
                    return True
    except OSError:
        return True
    return False


def _entry_needs_safe_staging(entry: os.DirEntry[str]) -> bool:
    entry_path = Path(entry.path)
    try:
        if entry.is_symlink():
            return True
        if entry.is_dir(follow_symlinks=False):
            return not os.access(entry_path, _DIR_ACCESS_MODE) or _needs_safe_staging(entry_path)
        return entry.is_file(follow_symlinks=False) and not os.access(entry_path, _FILE_ACCESS_MODE)
    except OSError:
        return True


def _link_or_copy(src: Path, dst: Path) -> None:
    """Hard-link ``src`` to ``dst``, falling back to a content copy."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst, follow_symlinks=True)


def _stage_dir(src: Path, dst: Path, root: Path, seen: frozenset[Path]) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    try:
        entries = list(os.scandir(src))
    except OSError as exc:
        logger.warning("staging: skipping unreadable directory %s: %s", src, exc)
        return

    for entry in entries:
        _stage_entry(entry, dst, root, seen)


def _stage_entry(entry: os.DirEntry[str], dst: Path, root: Path, seen: frozenset[Path]) -> None:
    entry_path = Path(entry.path)
    dest_path = dst / entry.name

    try:
        is_symlink = entry.is_symlink()
        is_dir = entry.is_dir(follow_symlinks=False)
        is_file = entry.is_file(follow_symlinks=False)
    except OSError as exc:
        logger.warning("staging: skipping unreadable entry %s: %s", entry_path, exc)
        return

    if is_symlink:
        _stage_symlink(entry_path, dest_path, root, seen)
    elif is_dir:
        _stage_child_dir(entry_path, dest_path, root, seen)
    elif is_file:
        _stage_file(entry_path, dest_path)
    else:
        # Sockets, FIFOs, devices — not part of a source tree; skip.
        logger.debug("staging: skipping non-regular entry %s", entry_path)


def _stage_symlink(entry_path: Path, dest_path: Path, root: Path, seen: frozenset[Path]) -> None:
    target = Path(os.path.realpath(entry_path))
    if not _is_within(target, root):
        logger.warning("staging: dropping out-of-tree symlink %s -> %s", entry_path, target)
        return
    if not target.exists():
        logger.warning("staging: dropping dangling symlink %s", entry_path)
        return
    if target in seen:
        logger.warning("staging: dropping cyclic symlink %s -> %s", entry_path, target)
        return
    if target.is_dir():
        _stage_dir(target, dest_path, root, seen | {target})
        return
    _stage_file(target, dest_path)


def _stage_child_dir(entry_path: Path, dest_path: Path, root: Path, seen: frozenset[Path]) -> None:
    if not os.access(entry_path, _DIR_ACCESS_MODE):
        logger.warning("staging: skipping unreadable directory %s", entry_path)
        return
    _stage_dir(entry_path, dest_path, root, seen)


def _stage_file(entry_path: Path, dest_path: Path) -> None:
    if not os.access(entry_path, _FILE_ACCESS_MODE):
        logger.warning("staging: skipping unreadable file %s", entry_path)
        return
    _link_or_copy(entry_path, dest_path)


def stage_symlink_safe_dir(src_root: Path) -> tuple[Path, Path | None]:
    """Return ``(upload_path, staged_temp)`` for uploading ``src_root``.

    ``upload_path`` is safe to hand to ``LocalDir``. When the tree contains no
    symlinks it is ``src_root`` itself and ``staged_temp`` is ``None``.
    Otherwise a symlink-safe copy is materialized in a temp directory and both
    returned values point at it; the caller owns removing ``staged_temp`` once
    the upload completes.
    """
    root = src_root.resolve()
    if not _needs_safe_staging(root):
        return root, None

    staged = Path(tempfile.mkdtemp(prefix=_STAGING_PREFIX)).resolve()
    try:
        _stage_dir(root, staged, root, frozenset({root}))
    except OSError:
        shutil.rmtree(staged, ignore_errors=True)
        raise
    logger.info("staging: materialized symlink-safe copy of %s at %s", root, staged)
    return staged, staged
