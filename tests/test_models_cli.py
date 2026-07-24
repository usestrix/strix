"""Tests for the `strix models` listing command (subscription + API-key)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.auth import codex
from strix.config.models import RECOMMENDED_MODEL_NAMES
from strix.interface import models_cli


if TYPE_CHECKING:
    import pytest


def test_help_returns_zero() -> None:
    assert models_cli.run_models(["--help"]) == 0


def test_lists_without_sign_in(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Signed out: the command still works — it previews subscription models and
    # lists API-key models (which need no sign-in).
    monkeypatch.setattr(codex, "is_authenticated", lambda: False)
    assert models_cli.run_models([]) == 0
    out = capsys.readouterr().out
    assert "Subscription models" in out
    assert "API-key models" in out
    assert "strix auth login chatgpt" in out  # the signed-out prompt
    # A recommended API model appears in the API section.
    assert RECOMMENDED_MODEL_NAMES[0].split("/")[-1] in out


def test_lists_when_signed_in_uses_live_catalog(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(codex, "is_authenticated", lambda: True)
    monkeypatch.setattr(codex, "refresh_subscription_models", lambda: ("gpt-5.4", "gpt-5.9-live"))
    assert models_cli.run_models([]) == 0
    out = capsys.readouterr().out
    # A slug only present in the (mocked) live catalog shows up — proving the
    # command reflects the backend, not just the static fallback.
    assert "gpt-5.9-live" in out
