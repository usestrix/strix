"""Bounded, atomic storage for human review decisions, separate from scan output."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Generator


MAX_STORE_BYTES = 16 * 1024 * 1024
LOCK_TIMEOUT = 3.0
_locks: dict[Path, threading.Lock] = {}
_locks_guard = threading.Lock()


class TriageError(Exception):
    """A user-actionable review failure with a stable interface error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except FileNotFoundError:
        return True
    except OSError:
        return False


def can_write_triage(run_dir: Path) -> bool:
    """Read-only capability check. Never creates a sidecar or lockfile."""
    try:
        if run_dir.is_symlink() or not run_dir.is_dir() or not (run_dir / "run.json").is_file():
            return False
        if not run_dir.stat().st_mode & 0o222 or not os.access(run_dir, os.W_OK):
            return False
        for name in ("triage.json", "triage.lock", "run.json", "vulnerabilities.json"):
            path = run_dir / name
            if not regular_file(path):
                return False
            if (
                name in {"triage.json", "triage.lock"}
                and path.exists()
                and (not path.stat().st_mode & 0o222 or not os.access(path, os.W_OK))
            ):
                return False
    except OSError:
        return False
    return True


def read_json(path: Path, *, default: Any, limit: int = MAX_STORE_BYTES) -> Any:
    """Read a regular file only, rejecting links/devices and malformed contents."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        if not regular_file(path):
            raise TriageError("invalid_triage", "Run data must be a regular file, not a link.")
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise TriageError("invalid_triage", "Run data is not a supported regular file.")
            content = stream.read(limit + 1)
        if len(content) > limit:
            raise TriageError("invalid_triage", "Run data exceeds the supported size.")
        return json.loads(content)
    except FileNotFoundError:
        return default
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise TriageError(
            "invalid_triage", "Run data is malformed; no decisions were changed."
        ) from exc
    except OSError as exc:
        raise TriageError("unavailable", "Could not read the run's review data.") from exc


def triage_stamp(run_dir: Path) -> tuple[int, int]:
    """Opaque token for review/evidence changes, including resumed finished runs."""
    stamps: list[tuple[int, int, int]] = []
    for name in ("triage.json", "vulnerabilities.json", "run.json"):
        try:
            info = (run_dir / name).lstat()
            stamps.append((info.st_mtime_ns, info.st_size, info.st_ino))
        except FileNotFoundError:
            stamps.append((0, 0, 0))
        except OSError:
            stamps.append((-1, -1, -1))
    digest = hashlib.sha256(repr(stamps).encode("ascii")).digest()
    # Keep each number exactly representable in browser JavaScript.
    return int.from_bytes(digest[:6]), int.from_bytes(digest[6:12])


def _file_lock(descriptor: int, *, unlock: bool = False) -> None:
    if sys.platform == "win32":
        import msvcrt  # noqa: PLC0415

        # The CRT permits locking beyond EOF, so even an empty file has byte zero
        # available as a stable lock region. Always unlock that same region.
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK if unlock else msvcrt.LK_NBLCK, 1)
    else:
        import fcntl  # noqa: PLC0415

        fcntl.flock(descriptor, fcntl.LOCK_UN if unlock else fcntl.LOCK_EX | fcntl.LOCK_NB)


@contextlib.contextmanager
def locked_store(run_dir: Path) -> Generator[None]:
    """Serialize threads and processes using a stable inode, never the replaced JSON."""
    if not can_write_triage(run_dir):
        raise TriageError("read_only", "This run is read-only or has unsafe review file paths.")
    with _locks_guard:
        thread_lock = _locks.setdefault(run_dir.resolve(), threading.Lock())
    if not thread_lock.acquire(timeout=LOCK_TIMEOUT):
        raise TriageError("unavailable", "Another review is being saved. Try again.")
    descriptor: int | None = None
    acquired = False
    try:
        path = run_dir / "triage.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags, 0o600)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise TriageError("read_only", "The review lock must be a regular file.")
        deadline = time.monotonic() + LOCK_TIMEOUT
        while True:
            try:
                _file_lock(descriptor)
                acquired = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TriageError(
                        "unavailable", "Could not lock review data. Try again."
                    ) from None
                time.sleep(0.025)
        yield
    except PermissionError as exc:
        raise TriageError("read_only", "This run's review data is read-only.") from exc
    except OSError as exc:
        raise TriageError(
            "unavailable", "Could not save the review. Reload before retrying."
        ) from exc
    finally:
        if descriptor is not None:
            if acquired:
                with contextlib.suppress(OSError):
                    _file_lock(descriptor, unlock=True)
            with contextlib.suppress(OSError):
                os.close(descriptor)
        thread_lock.release()


def write_store(run_dir: Path, document: dict[str, Any]) -> None:
    """Commit complete JSON durably; callers must hold locked_store."""
    payload = json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")
    if len(payload) > MAX_STORE_BYTES:
        raise TriageError("invalid_triage", "Review history exceeds the supported size.")
    path = run_dir / "triage.json"
    if not regular_file(path):
        raise TriageError("invalid_triage", "Review data must be a regular file, not a link.")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=run_dir, prefix=".triage-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        if os.name != "nt":
            descriptor = os.open(run_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
