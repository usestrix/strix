"""Tests for StrixTUIApp._notify_scan_error — Fix 2: in-TUI error display."""

from __future__ import annotations

from unittest.mock import MagicMock

from strix.interface.tui.app import StrixTUIApp


def _mock_app() -> MagicMock:
    return MagicMock(spec=StrixTUIApp)


def test_notify_scan_error_dispatches_toast() -> None:
    """_notify_scan_error must call notify via call_from_thread with error text."""
    app = _mock_app()
    exc = RuntimeError("something went wrong")

    StrixTUIApp._notify_scan_error(app, exc)

    app.call_from_thread.assert_called_once_with(
        app.notify,
        "Scan failed: RuntimeError: something went wrong",
        severity="error",
    )


def test_notify_scan_error_suppresses_call_from_thread_failure() -> None:
    """If call_from_thread itself raises, the exception must be swallowed."""
    app = _mock_app()
    app.call_from_thread.side_effect = RuntimeError("TUI not ready")

    # Must not propagate the exception.
    StrixTUIApp._notify_scan_error(app, ValueError("boom"))


def test_notify_scan_error_formats_exception_type() -> None:
    """Toast text must include the exception's class name and message."""
    app = _mock_app()
    exc = ConnectionError("host unreachable")

    StrixTUIApp._notify_scan_error(app, exc)

    args = app.call_from_thread.call_args.args
    assert "ConnectionError" in args[1]
    assert "host unreachable" in args[1]
