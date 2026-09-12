from __future__ import annotations

import json
import os
import stat
import sys
from typing import TYPE_CHECKING

import pytest

from strix.utils.secret_files import SECRET_FILE_MODE, write_secret_text


if TYPE_CHECKING:
    from pathlib import Path


posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX permission bits are not modelled on Windows"
)


def test_content_round_trips(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "auth.json"
    payload = json.dumps({"token": "s3cret", "refresh": "r3fresh"})
    write_secret_text(target, payload)
    assert json.loads(target.read_text(encoding="utf-8"))["token"] == "s3cret"  # noqa: S105


@posix_only
def test_file_is_owner_only(tmp_path: Path) -> None:
    target = tmp_path / "auth.json"
    write_secret_text(target, "{}")
    assert stat.S_IMODE(target.stat().st_mode) == SECRET_FILE_MODE


@posix_only
def test_a_permissive_umask_cannot_widen_the_file(tmp_path: Path) -> None:
    previous = os.umask(0)
    try:
        target = tmp_path / "auth.json"
        write_secret_text(target, "{}")
        assert stat.S_IMODE(target.stat().st_mode) == SECRET_FILE_MODE
    finally:
        os.umask(previous)


@posix_only
def test_a_stale_temporary_does_not_leak_its_mode(tmp_path: Path) -> None:
    target = tmp_path / "auth.json"
    stale = target.with_suffix(target.suffix + ".tmp")
    stale.write_text("leftover", encoding="utf-8")
    stale.chmod(0o666)

    write_secret_text(target, "{}")
    assert stat.S_IMODE(target.stat().st_mode) == SECRET_FILE_MODE


def test_overwriting_an_existing_record_keeps_it_restricted(tmp_path: Path) -> None:
    target = tmp_path / "auth.json"
    write_secret_text(target, json.dumps({"v": 1}))
    write_secret_text(target, json.dumps({"v": 2}))
    assert json.loads(target.read_text(encoding="utf-8"))["v"] == 2
    if sys.platform != "win32":
        assert stat.S_IMODE(target.stat().st_mode) == SECRET_FILE_MODE
