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


def _link_or_copy(src: Path, dst: Path) -> None:
    """Hard-link ``src`` to ``dst``, falling back to a content copy."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst, follow_symlinks=True)


def _stage_dir(src: Path, dst: Path, root: Path, seen: frozenset[Path]) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in os.scandir(src):
        entry_path = Path(entry.path)
        dest_path = dst / entry.name

        if entry.is_symlink():
            target = Path(os.path.realpath(entry_path))
            if not _is_within(target, root):
                logger.warning("staging: dropping out-of-tree symlink %s -> %s", entry_path, target)
                continue
            if not target.exists():
                logger.warning("staging: dropping dangling symlink %s", entry_path)
                continue
            if target in seen:
                logger.warning("staging: dropping cyclic symlink %s -> %s", entry_path, target)
                continue
            if target.is_dir():
                _stage_dir(target, dest_path, root, seen | {target})
            else:
                _link_or_copy(target, dest_path)
        elif entry.is_dir(follow_symlinks=False):
            _stage_dir(entry_path, dest_path, root, seen)
        elif entry.is_file(follow_symlinks=False):
            _link_or_copy(entry_path, dest_path)
        else:
            # Sockets, FIFOs, devices — not part of a source tree; skip.
            logger.debug("staging: skipping non-regular entry %s", entry_path)


def stage_symlink_safe_dir(src_root: Path) -> tuple[Path, Path | None]:
    """Return ``(upload_path, staged_temp)`` for uploading ``src_root``.

    ``upload_path`` is safe to hand to ``LocalDir``. When the tree contains no
    symlinks it is ``src_root`` itself and ``staged_temp`` is ``None``.
    Otherwise a symlink-safe copy is materialized in a temp directory and both
    returned values point at it; the caller owns removing ``staged_temp`` once
    the upload completes.
    """
    root = src_root.resolve()
    if not tree_has_symlink(root):
        return root, None

    staged = Path(tempfile.mkdtemp(prefix=_STAGING_PREFIX))
    try:
        _stage_dir(root, staged, root, frozenset({root}))
    except OSError:
        shutil.rmtree(staged, ignore_errors=True)
        raise
    logger.info("staging: materialized symlink-safe copy of %s at %s", root, staged)
    return staged, staged
