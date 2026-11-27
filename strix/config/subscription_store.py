"""The credential file every subscription provider (codex, mistral) keeps its
OAuth record in, keyed by provider.

Every read-modify-write of the file runs under ``locked()``, one lock shared by
all providers within (thread lock) and across (flock) Strix processes. Refresh
tokens are single-use, so a write that started from a stale copy of the file
would restore a peer provider's spent token and force a fresh sign-in.
"""

from __future__ import annotations

import contextlib
import json
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from strix.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from collections.abc import Iterator


# Kept separate from cli-config.json so OAuth tokens never land in the env-var config.
AUTH_PATH = Path.home() / ".strix" / "subscription-auth.json"

_lock = threading.Lock()


def _read_all() -> dict[str, Any]:
    try:
        data = json.loads(AUTH_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def read(provider: str) -> Any:
    return _read_all().get(provider)


def put(provider: str, record: dict[str, Any] | None) -> None:
    """Store ``record`` for ``provider``, or remove it when None. Hold ``locked()``."""
    data = _read_all()
    if record is not None:
        data[provider] = record
    elif provider in data:
        del data[provider]
    else:
        return
    if data:
        write_secret_text(AUTH_PATH, json.dumps(data, indent=2))
        return
    with contextlib.suppress(OSError):
        AUTH_PATH.unlink()


@contextlib.contextmanager
def locked() -> Iterator[None]:
    with _lock:
        try:
            import fcntl

            lock_path = AUTH_PATH.with_suffix(".lock")
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            handle = lock_path.open("w")
        except (ImportError, OSError):
            yield
            return
        try:
            with contextlib.suppress(OSError):
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()
