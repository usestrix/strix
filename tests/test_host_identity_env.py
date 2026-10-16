import os
import sys
from types import SimpleNamespace

import pytest

from strix.runtime import session_manager

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="sandbox uid mapping is Linux-only"
)


def _as(monkeypatch, uid: int, gid: int) -> None:
    monkeypatch.setattr(os, "getuid", lambda: uid)
    monkeypatch.setattr(os, "getgid", lambda: gid)


def test_system_account_uid_skips_mapping(monkeypatch):
    _as(monkeypatch, 997, 980)
    assert session_manager._host_identity_env() == {}


def test_uid_below_login_range_skips_mapping(monkeypatch):
    _as(monkeypatch, 999, 999)
    assert session_manager._host_identity_env() == {}


def test_homeless_uid_skips_mapping(monkeypatch):
    _as(monkeypatch, 1500, 1500)
    monkeypatch.setattr(
        "pwd.getpwuid", lambda uid: SimpleNamespace(pw_dir="/nonexistent")
    )
    assert session_manager._host_identity_env() == {}


def test_regular_user_is_mapped(monkeypatch):
    _as(monkeypatch, 1500, 1500)
    monkeypatch.setattr(
        "pwd.getpwuid", lambda uid: SimpleNamespace(pw_dir="/home/dev")
    )
    assert session_manager._host_identity_env() == {
        "STRIX_HOST_UID": "1500",
        "STRIX_HOST_GID": "1500",
    }
