"""Tests for the Stripe Link wallet setup path of `strix cloud billing topup`."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, Any

from rich.console import Console

from strix.interface.cloud import billing


if TYPE_CHECKING:
    import pytest


_MIN_LINK_CONTEXT_CHARS = 100


def _completed(stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["link-cli"], returncode=0, stdout=stdout, stderr="")


def test_payment_context_is_long_enough_for_link_approval() -> None:
    context = billing._payment_context({"credits": 5})
    assert len(context) >= _MIN_LINK_CONTEXT_CHARS
    assert "5" in context


def test_mppx_wallet_configured_follows_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MPPX_ACCOUNT", raising=False)
    monkeypatch.delenv("MPPX_STRIPE_SECRET_KEY", raising=False)
    assert billing._mppx_wallet_configured() is False
    monkeypatch.setenv("MPPX_ACCOUNT", "agent")
    assert billing._mppx_wallet_configured() is True


def test_link_wallet_authenticated_reads_status_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        billing,
        "_run_link_cli",
        lambda *_args, **_kwargs: _completed('[{"authenticated": true}]'),
    )
    assert billing._link_wallet_authenticated("npx") is True


def test_link_wallet_authenticated_handles_unusable_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(billing, "_run_link_cli", lambda *_args, **_kwargs: _completed("not json"))
    assert billing._link_wallet_authenticated("npx") is False


def test_link_wallet_authenticated_handles_launch_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise OSError

    monkeypatch.setattr(billing, "_run_link_cli", explode)
    assert billing._link_wallet_authenticated("npx") is False


def test_pending_spend_request_reads_the_created_record() -> None:
    stdout = (
        '[{"id": "lsrq_123", "status": "pending_approval", '
        '"approval_url": "https://app.link.com/activity/approve/lsrq_123"}]'
    )
    assert billing._pending_spend_request(stdout) == (
        "lsrq_123",
        "https://app.link.com/activity/approve/lsrq_123",
    )
    assert billing._pending_spend_request('[{"id": "lsrq_1", "status": "approved"}]') is None
    assert billing._pending_spend_request("not json") is None


def test_pending_spend_request_tolerates_banner_text_around_pretty_json() -> None:
    stdout = (
        "Update available for @stripe/link-cli: 0.13.1 -> 0.16.0\n"
        "[\n  {\n"
        '    "id": "lsrq_9",\n'
        '    "status": "pending_approval",\n'
        '    "approval_url": "https://app.link.com/activity/approve/lsrq_9"\n'
        "  }\n]"
    )
    assert billing._pending_spend_request(stdout) == (
        "lsrq_9",
        "https://app.link.com/activity/approve/lsrq_9",
    )


def test_final_spend_request_status_reads_the_last_poll_line() -> None:
    stdout = '{"status": "pending_approval"}\n{"status": "approved"}\n'
    assert billing._final_spend_request_status(stdout) == "approved"
    assert billing._final_spend_request_status("") is None


def test_final_spend_request_status_unwraps_chunk_envelopes() -> None:
    stdout = (
        '{"type":"chunk","data":{"id":"lsrq_9","status":"pending_approval"}}\n'
        '{"type":"chunk","data":{"id":"lsrq_9","status":"approved"}}\n'
        '{"type":"done","ok":true,"meta":{"command":"spend-request retrieve"}}\n'
    )
    assert billing._final_spend_request_status(stdout) == "approved"


def test_prepare_link_wallet_skips_login_when_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(billing, "_link_wallet_authenticated", lambda _npx: True)
    assert billing._prepare_link_wallet(Console(), "npx", as_json=True) is None


def test_prepare_link_wallet_explains_setup_without_a_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(billing, "_link_wallet_authenticated", lambda _npx: False)
    message = billing._prepare_link_wallet(Console(), "npx", as_json=True)
    assert message is not None
    assert "https://link.com/agents" in message
