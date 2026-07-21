"""Tests for viewer auth state and the relay client mapping."""

from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from strix.viewer import auth


def _iso(delta: timedelta) -> str:
    return (datetime.now(UTC) + delta).isoformat()


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _tmp_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    monkeypatch.setattr(auth, "AUTH_PATH", home / ".strix" / "viewer-auth.json")
    return auth.AUTH_PATH


def test_write_read_forget_roundtrip() -> None:
    assert auth.read_auth() is None
    assert auth.is_verified() is False

    auth.write_auth(email="user@example.com", token="tok-123", verified_at=_iso(timedelta(days=30)))

    record = auth.read_auth()
    assert record is not None
    assert record["email"] == "user@example.com"
    assert record["token"] == "tok-123"
    assert auth.is_verified() is True

    auth.forget()
    assert auth.read_auth() is None
    assert auth.is_verified() is False
    # Forget is a no-op when the file is already gone.
    auth.forget()


def test_is_verified_enforces_expiry() -> None:
    # An expired record still reads back, but no longer unlocks history.
    auth.write_auth(email="a@b.com", token="t", verified_at=_iso(timedelta(hours=-1)))
    assert auth.read_auth() is not None
    assert auth.is_verified() is False

    # A future expiry unlocks it.
    auth.write_auth(email="a@b.com", token="t", verified_at=_iso(timedelta(hours=1)))
    assert auth.is_verified() is True


def test_is_verified_fails_closed_when_expiry_absent_or_unparseable() -> None:
    # No/blank expiry: fail closed rather than unlocking history forever.
    auth.write_auth(email="a@b.com", token="t", verified_at="")
    assert auth.read_auth() is not None
    assert auth.is_verified() is False

    # Garbage expiry likewise requires re-verification.
    auth.write_auth(email="a@b.com", token="t", verified_at="not-a-date")
    assert auth.is_verified() is False


def test_is_verified_accepts_epoch_expiry() -> None:
    # A relay expiry expressed as epoch seconds must not be misread as missing.
    future = (datetime.now(UTC) + timedelta(hours=1)).timestamp()
    past = (datetime.now(UTC) - timedelta(hours=1)).timestamp()

    # As a numeric string (how write_auth persists it).
    auth.write_auth(email="a@b.com", token="t", verified_at=str(future))
    assert auth.is_verified() is True
    auth.write_auth(email="a@b.com", token="t", verified_at=str(past))
    assert auth.is_verified() is False

    # As a raw JSON number, if a record is written that way.
    auth.AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    auth.AUTH_PATH.write_text(
        f'{{"email": "a@b.com", "token": "t", "verified_at": {future}}}', encoding="utf-8"
    )
    assert auth.is_verified() is True


def test_write_auth_is_0600() -> None:
    auth.write_auth(email="a@b.com", token="t", verified_at="")
    mode = stat.S_IMODE(auth.AUTH_PATH.stat().st_mode)
    assert mode == 0o600


def test_read_auth_rejects_incomplete_record() -> None:
    auth.AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    auth.AUTH_PATH.write_text('{"email": "a@b.com"}', encoding="utf-8")
    assert auth.read_auth() is None
    assert auth.is_verified() is False


def _stub_post(monkeypatch: pytest.MonkeyPatch, status: int, body: dict[str, Any]) -> None:
    def fake(path: str, payload: dict[str, Any], *, timeout: int) -> tuple[int, dict[str, Any]]:
        return status, body

    monkeypatch.setattr(auth, "_post_json", fake)


def test_otp_start_maps_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_post(monkeypatch, 200, {"ok": True})
    auth.otp_start("a@b.com")  # no raise

    _stub_post(monkeypatch, 429, {"error": "rate_limited"})
    with pytest.raises(auth.RelayError) as exc:
        auth.otp_start("a@b.com")
    assert exc.value.code == "rate_limited"

    _stub_post(monkeypatch, 400, {})
    with pytest.raises(auth.RelayError) as exc:
        auth.otp_start("bad")
    assert exc.value.code == "invalid_email"


def test_otp_verify_success_and_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    expires = _iso(timedelta(hours=1))
    _stub_post(monkeypatch, 200, {"token": "t", "email": "a@b.com", "expires_at": expires})
    result = auth.otp_verify("a@b.com", "123456")
    assert result["token"] == "t"

    _stub_post(monkeypatch, 403, {"error": "invalid_code"})
    with pytest.raises(auth.RelayError) as exc:
        auth.otp_verify("a@b.com", "000000")
    assert exc.value.code == "invalid_code"


def test_otp_verify_rejects_token_without_usable_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    # A 200 with a token but no valid expiry must not be reported as success,
    # otherwise the caller would store a record that immediately reads unverified.
    for expires in (None, "", "later"):
        _stub_post(monkeypatch, 200, {"token": "t", "email": "a@b.com", "expires_at": expires})
        with pytest.raises(auth.RelayError) as exc:
            auth.otp_verify("a@b.com", "123456")
        assert exc.value.code == "unavailable"


def test_report_send_never_includes_password(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake(path: str, payload: dict[str, Any], *, timeout: int) -> tuple[int, dict[str, Any]]:
        captured["payload"] = payload
        return 200, {"ok": True}

    monkeypatch.setattr(auth, "_post_json", fake)
    auth.report_send("tok", b"%PDF-fake", "strix-report-x.pdf", "x", "https://example.com")

    payload = captured["payload"]
    assert set(payload) == {"token", "pdf_base64", "filename", "run_name", "target"}
    # The password is generated locally and must never appear in the relay body.
    assert "password" not in payload
    assert all("password" not in str(k).lower() for k in payload)


def test_report_send_reverify_on_401(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_post(monkeypatch, 401, {"error": "invalid_token"})
    with pytest.raises(auth.RelayError) as exc:
        auth.report_send("tok", b"x", "f.pdf", "r", "t")
    assert exc.value.code == "reverify"
