"""Shared on-disk store for subscription OAuth credentials.

Every subscription provider (ChatGPT/Codex, Grok) keeps its record under its own
key in a single ``~/.strix/subscription-auth.json`` file. Reads and writes go
through here so that:

* tokens are written owner-only (mode 0600) from the moment the file is created,
  never briefly exposed with umask-derived permissions, and
* concurrent read-modify-write mutations — even across different providers or
  processes — are serialized, so one provider's update can't clobber another's.

The lock is reentrant, so a provider may nest a ``save`` inside a longer
``guard`` (e.g. refreshing a token then persisting it) without deadlocking.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Iterator
    from io import TextIOWrapper


class StoreLockError(RuntimeError):
    """The cross-process store lock could not be acquired.

    Raised instead of silently proceeding, so a read-modify-write never runs
    unlocked (which would let concurrent provider logins/refreshes/logouts race).
    """


def read(path: Path) -> dict[str, Any]:
    """The store's contents, or an empty dict when absent/unreadable."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def write(path: Path, data: dict[str, Any]) -> None:
    """Atomically replace the store, owner-only from creation.

    The temp file is created with a random name via ``mkstemp`` (mode 0600, no
    symlink following), so a local attacker can't pre-plant a symlink at a
    predictable path to divert the token write.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=path.name, suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
        tmp.replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    with contextlib.suppress(OSError):
        path.chmod(0o600)


class _StoreLock:
    """A reentrant lock serializing store mutations within (thread lock) and
    across (flock) Strix processes. Nesting reuses the single held file lock, so
    a provider can persist a record inside a longer critical section."""

    def __init__(self) -> None:
        self._thread_lock = threading.RLock()
        self._flock_handle: TextIOWrapper | None = None
        self._depth = 0

    @contextlib.contextmanager
    def hold(self, path: Path) -> Iterator[None]:
        with self._thread_lock:
            if self._depth == 0:
                self._flock_handle = _acquire_flock(path)
            self._depth += 1
            try:
                yield
            finally:
                self._depth -= 1
                if self._depth == 0:
                    self._release_flock()

    def _release_flock(self) -> None:
        handle = self._flock_handle
        self._flock_handle = None
        if handle is None:
            return
        try:
            import fcntl

            with contextlib.suppress(OSError):
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except ImportError:
            pass
        finally:
            handle.close()


_store_lock = _StoreLock()


def guard(path: Path) -> contextlib.AbstractContextManager[None]:
    """Serialize store mutation across threads and processes (reentrant)."""
    return _store_lock.hold(path)


def _acquire_flock(path: Path) -> TextIOWrapper:
    """Hold an exclusive cross-process lock on the store, or raise.

    Never returns without the lock held: a missing ``fcntl`` or a failed
    ``flock`` raises :class:`StoreLockError` so the caller aborts rather than
    mutating the store unlocked.
    """
    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - non-POSIX
        msg = "cross-process credential locking requires fcntl (a POSIX platform)"
        raise StoreLockError(msg) from exc
    lock_path = path.with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    # O_NOFOLLOW rejects a pre-positioned symlink at the predictable lock path
    # (so an attacker can't redirect the open), and no O_TRUNC since the lock
    # file is only an flock anchor whose contents we never use.
    try:
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        msg = f"could not open lock file {lock_path}: {exc}"
        raise StoreLockError(msg) from exc
    handle = os.fdopen(fd, "r+")
    try:
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                break
            except InterruptedError:  # EINTR — retry the blocking acquire
                continue
    except OSError as exc:
        handle.close()
        msg = f"could not lock {lock_path}: {exc}"
        raise StoreLockError(msg) from exc
    return handle
