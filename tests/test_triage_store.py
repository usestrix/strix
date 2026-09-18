"""Native operating-system locking invariants for the local review sidecar."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from strix.report.triage_store import _file_lock


if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize("contents", [b"", b"existing lock file"])
def test_file_lock_excludes_other_handles_and_releases(tmp_path: Path, contents: bytes) -> None:
    """Exercise fcntl on POSIX and the real msvcrt implementation on Windows."""
    path = tmp_path / "triage.lock"
    path.write_bytes(contents)
    first = os.open(path, os.O_RDWR)
    try:
        second = os.open(path, os.O_RDWR)
        try:
            _file_lock(first)
            try:
                with pytest.raises(OSError):
                    _file_lock(second)
                # Locking/unlocking must agree on byte zero, regardless of position.
                os.lseek(first, 100, os.SEEK_SET)
            finally:
                _file_lock(first, unlock=True)
            _file_lock(second)
            _file_lock(second, unlock=True)
        finally:
            os.close(second)
    finally:
        os.close(first)
    assert path.read_bytes() == contents
