"""Tests for exception-chain helpers and preflight debug logging."""

from __future__ import annotations

import logging
import ssl
from typing import TYPE_CHECKING

from strix.interface.main import (
    _exception_messages,
    _format_connection_error_detail,
)
from strix.telemetry import logging as tlog
from strix.telemetry.logging import attach_preflight_logging, debug_logging_enabled


if TYPE_CHECKING:
    import pytest


def _remove_preflight_handlers() -> None:
    for tracked_name in ("strix", "openai.agents"):
        tracked = logging.getLogger(tracked_name)
        for handler in list(tracked.handlers):
            if getattr(handler, tlog._PREFLIGHT_HANDLER_TAG, False):
                tracked.removeHandler(handler)
                handler.close()


def test_exception_messages_walks_cause_chain_to_ssl_error() -> None:
    root = ssl.SSLCertVerificationError("certificate verify failed")
    middle = ConnectionError("TLS handshake failed")
    middle.__cause__ = root
    exc = ConnectionError("Connection error.")
    exc.__cause__ = middle

    messages = _exception_messages(exc)

    assert "Connection error." in messages
    assert "TLS handshake failed" in messages
    assert any("certificate verify failed" in message for message in messages)


def test_format_connection_error_detail_includes_chain_when_debug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = ssl.SSLCertVerificationError("certificate verify failed")
    exc = ConnectionError("Connection error.")
    exc.__cause__ = root

    monkeypatch.delenv("STRIX_DEBUG", raising=False)
    assert _format_connection_error_detail(exc) == "Connection error."

    monkeypatch.setenv("STRIX_DEBUG", "1")
    detail = _format_connection_error_detail(exc)
    assert "Connection error." in detail
    assert "certificate verify failed" in detail


def test_debug_logging_enabled_reads_strix_debug(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_DEBUG", raising=False)
    assert debug_logging_enabled() is False
    assert debug_logging_enabled(debug=True) is True

    monkeypatch.setenv("STRIX_DEBUG", "yes")
    assert debug_logging_enabled() is True


def test_attach_preflight_logging_emits_debug_to_stderr(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("STRIX_DEBUG", "1")
    try:
        attach_preflight_logging()
        logging.getLogger("strix").debug("LLM warm-up failed")
        captured = capsys.readouterr()
        assert "LLM warm-up failed" in captured.err
    finally:
        _remove_preflight_handlers()
