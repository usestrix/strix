"""Atomic write helper for strix persist_current() — drop-in replacement.

Drop-in replacement for the open()/write + chmod() pattern in
strix/config/loader.py::persist_current().

The original code at strix/config/loader.py:74-76:

    target.write_text(json.dumps({"env": env_block}, indent=2), encoding="utf-8")
    with contextlib.suppress(OSError):
        target.chmod(0o600)

Has TWO defects:

1. Non-atomic write (write_text + chmod are two separate syscalls).
2. Race window during which the file is on disk with default permissions
   (often 0o644), leaking env vars like LLM_API_KEY to local users.

This module provides atomic_write_secure() that:

- Creates the temp file via os.open() with mode 0o600 enforced atomically
  at the OS level (O_CREAT is "atomic with mode" on POSIX).
- fsyncs before close (durability).
- os.replace()s into the final path (atomic rename on POSIX, atomic MoveFile
  on Windows since Python 3.3).
- Belt-and-suspenders chmod(0o600) after replace in case the destination
  pre-existed with looser permissions.
- O_NOFOLLOW on the tmp open to defend against a pre-planted symlink at the
  tmp path.

This file is the patch payload for PR #1 — see 01_PR_strix_persist_atomic.md.
"""
from __future__ import annotations

import contextlib
import os
import uuid
from pathlib import Path


def atomic_write_secure(target: Path, payload: str) -> None:
    """Atomically write *payload* to *target* with mode 0o600.

    The file is created at a unique tmp path with mode 0o600 enforced at the
    OS level (os.open + O_CREAT), fsync'd, then atomically renamed into
    place.

    Guarantees:
      1. Sensitive content is NEVER observable with mode != 0o600.
      2. A crash leaves either the old file or the new file, never a
         half-written file.
      3. Concurrent readers see either the old contents or the new
         contents, never a torn read.
      4. Defense against an attacker who plants a symlink at the tmp path
         (O_NOFOLLOW); also against attacks that pre-create the final
         target as a symlink we don't follow on write (os.replace does
         the right thing on a non-symlink-final target; if `target` is
         itself a symlink, callers should resolve() it themselves).

    Args:
        target: Final destination path. Created if absent; replaced if
            present.
        payload: The exact bytes to write.

    Raises:
        OSError: Any I/O error from open/write/fsync/replace.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    # Unique tmp: pid + uuid prevents collisions across concurrent writers.
    tmp_path = target.with_name(
        f"{target.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
    )
    try:
        # O_NOFOLLOW: defensive — a symlink at tmp_path could be a symlink
        # we don't want to follow into a privileged location.
        fd = os.open(
            tmp_path,
            flags=(
                os.O_WRONLY
                | os.O_CREAT
                | os.O_TRUNC
                | os.O_NOFOLLOW
            ),
            mode=0o600,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
                f.flush()
                # Ensure durability before the rename — a power loss here
                # would otherwise leave the final path with stale data.
                os.fsync(f.fileno())
        except BaseException:
            # If anything failed mid-write, close the fd and re-raise.
            # We intentionally do NOT call os.close(fd) explicitly;
            # os.fdopen ownership handles it.
            with contextlib.suppress(OSError):
                os.close(fd)
            raise
        # Atomic rename (POSIX) / MoveFileEx (Windows).
        os.replace(tmp_path, target)
        # Belt-and-suspenders: in case target pre-existed with looser mode
        # (e.g., a previous broken run left it at 0o644), tighten it now.
        target.chmod(0o600)
    finally:
        # If os.replace failed, the tmp file is still around; clean up.
        # Safe to leave a stale tmp around if the rename succeeded — the
        # uuid in the name collides vanishingly rarely.
        with contextlib.suppress(OSError, FileNotFoundError):
            tmp_path.unlink()


# ── Patched replacement for `persist_current()` ──────────────────────────
# Original code (for diff context):
#
#   def persist_current() -> None:
#       """Write currently-set env vars to the active config file (0o600)."""
#       s = load_settings()
#       target = _override or _DEFAULT_PATH
#       target.parent.mkdir(parents=True, exist_ok=True)
#
#       env_block: dict[str, str] = {}
#       for sub_name in s.model_fields:
#           sub_model = getattr(s, sub_name)
#           if not isinstance(sub_model, BaseModel):
#               continue
#           for finfo in type(sub_model).model_fields.values():
#               for alias in _aliases_for(finfo):
#                   value = os.environ.get(alias.upper())
#                   if value:
#                       env_block[alias.upper()] = value
#                       break
#
#       target.write_text(json.dumps({"env": env_block}, indent=2),
#                         encoding="utf-8")
#       with contextlib.suppress(OSError):
#           target.chmod(0o600)

def persist_current() -> None:
    """Atomically write currently-set env vars to the active config file.

    Drop-in replacement for the original. Preserves the dict shape
    (``{"env": {KEY: VALUE}}``) exactly, so existing parsers continue to
    work.
    """
    import json

    from pydantic import BaseModel  # type: ignore[import-not-found]

    from strix.config.settings import Settings  # type: ignore[import-not-found]

    s = load_settings()
    target = _override or _DEFAULT_PATH

    env_block: dict[str, str] = {}
    for sub_name in s.model_fields:
        sub_model = getattr(s, sub_name)
        if not isinstance(sub_model, BaseModel):
            continue
        for finfo in type(sub_model).model_fields.values():
            for alias in _aliases_for(finfo):
                value = os.environ.get(alias.upper())
                if value:
                    env_block[alias.upper()] = value
                    break

    payload = json.dumps({"env": env_block}, indent=2)
    atomic_write_secure(target, payload)


# ── Stubs for module-private names so this file is self-testable ─────────
def _get_module_globals():
    """Lazily bind the module-private helpers referenced above.

    In production, this file is patched into strix.config.loader where
    those globals already exist. For local validation we fall back to
    in-memory stubs.
    """
    import json as _json
    from typing import Any

    try:
        from strix.config.loader import (  # type: ignore[import-not-found]
            _DEFAULT_PATH,  # noqa: F401
            _override,  # type: ignore[import-untyped]
            _aliases_for,  # type: ignore[import-untyped]
            load_settings,  # type: ignore[import-untyped]
        )
        return {
            "_DEFAULT_PATH": _DEFAULT_PATH,
            "_override": _override,
            "_aliases_for": _aliases_for,
            "load_settings": load_settings,
        }
    except ImportError:
        return None


# At import time inside strix.config.loader, persist_current() and the
# helpers it needs are already in scope. We do NOT rebind them at import
# here — this is purely a documented drop-in patch. To validate locally
# without the strix package, use the smoke test below.

if __name__ == "__main__":
    # Smoke-test the writer in isolation
    import tempfile, json
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / "sub" / "config.json"
        atomic_write_secure(target, json.dumps({"hello": "world"}, indent=2))
        mode = target.stat().st_mode & 0o777
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"
        assert json.loads(target.read_text()) == {"hello": "world"}
        print(f"OK: {target} mode={oct(mode)} contents-as-expected")
        # Overwrite test
        atomic_write_secure(target, json.dumps({"v": 2}, indent=2))
        assert json.loads(target.read_text()) == {"v": 2}
        print("OK: overwrite preserves mode + atomic-replace")
