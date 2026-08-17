"""Shared subscription credential store: secure writes and cross-provider locking."""

from __future__ import annotations

import fcntl
import stat
from typing import TYPE_CHECKING

import pytest

from strix.config import codex, grok, subscription_store


if TYPE_CHECKING:
    from pathlib import Path


def test_write_creates_owner_only_file(tmp_path: Path) -> None:
    path = tmp_path / ".strix" / "subscription-auth.json"
    subscription_store.write(path, {"grok": {"type": "oauth", "access": "a", "refresh": "r"}})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # No stray temp file is left behind.
    assert not path.with_suffix(".json.tmp").exists()


def test_write_does_not_follow_a_symlink_at_target(tmp_path: Path) -> None:
    store_dir = tmp_path / ".strix"
    store_dir.mkdir()
    outside = tmp_path / "attacker-target.json"
    path = store_dir / "subscription-auth.json"
    path.symlink_to(outside)  # attacker pre-plants a symlink at the store path

    subscription_store.write(path, {"grok": {"type": "oauth", "access": "a", "refresh": "r"}})

    # The atomic rename replaced the symlink with a real file; nothing was
    # written through it to the attacker-chosen location.
    assert not path.is_symlink()
    assert not outside.exists()
    assert subscription_store.read(path)["grok"]["access"] == "a"


def test_providers_share_store_without_clobbering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = tmp_path / ".strix" / "subscription-auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", store)
    monkeypatch.setattr(grok, "AUTH_PATH", store)

    codex.save_record({"type": "oauth", "access": "c", "refresh": "r", "account_id": "acct"})
    grok.save_record({"type": "oauth", "access": "g", "refresh": "r"})

    data = subscription_store.read(store)
    assert data["codex"]["access"] == "c"
    assert data["grok"]["access"] == "g"

    # Logging one provider out leaves the other's credential intact.
    grok.logout()
    remaining = subscription_store.read(store)
    assert "grok" not in remaining
    assert remaining["codex"]["access"] == "c"


def test_guard_is_reentrant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = tmp_path / ".strix" / "subscription-auth.json"
    monkeypatch.setattr(grok, "AUTH_PATH", store)
    # Persisting while already holding the guard must not deadlock — this mirrors
    # a token refresh saving its new record inside the refresh critical section.
    with subscription_store.guard(store):
        grok.save_record({"type": "oauth", "access": "g", "refresh": "r"})
    record = grok.read_record()
    assert record is not None
    assert record["access"] == "g"


def test_mutation_aborts_when_lock_cannot_be_acquired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = tmp_path / ".strix" / "subscription-auth.json"
    monkeypatch.setattr(grok, "AUTH_PATH", store)

    def _no_lock(*_args: object, **_kwargs: object) -> None:
        raise OSError("no locks available")

    monkeypatch.setattr(fcntl, "flock", _no_lock)

    # Rather than silently doing an unlocked read-modify-write, the store raises
    # and writes nothing.
    with pytest.raises(subscription_store.StoreLockError):
        grok.save_record({"type": "oauth", "access": "g", "refresh": "r"})
    assert not store.exists()


def test_lock_file_rejects_a_pre_positioned_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store_dir = tmp_path / ".strix"
    store_dir.mkdir()
    store = store_dir / "subscription-auth.json"
    monkeypatch.setattr(grok, "AUTH_PATH", store)
    # Attacker pre-plants a symlink where the lock file would be created.
    outside = tmp_path / "attacker-target"
    store.with_suffix(".lock").symlink_to(outside)

    with pytest.raises(subscription_store.StoreLockError):
        grok.save_record({"type": "oauth", "access": "g", "refresh": "r"})
    # The symlink target was never created/truncated through the lock open.
    assert not outside.exists()
