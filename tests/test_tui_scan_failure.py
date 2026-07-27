"""Tests for surfacing scan-level failures in the TUI."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

from strix.interface.tui.app import StrixTUIApp


if TYPE_CHECKING:
    from pathlib import Path

    import pytest


SCAN_FAILURE_TEXT = "model context input is too large"


def test_tui_records_scan_failure_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    app = StrixTUIApp(
        SimpleNamespace(
            run_name="scan-error-test",
            targets_info=[],
            instruction=None,
            diff_scope={"active": False},
            scan_mode="deep",
            non_interactive=False,
            local_sources=[],
            scope_mode="auto",
            diff_base=None,
            user_explicit_instruction=None,
        )
    )
    app._scan_error = RuntimeError(SCAN_FAILURE_TEXT)
    app._scan_error_noted = False
    app.selected_agent_id = None
    app._displayed_events = []

    app._record_scan_error_if_needed()
    app._record_scan_error_if_needed()

    scan_agent = app.live_view.agents["scan"]
    events = app.live_view.events_for_agent("scan")

    assert scan_agent["status"] == "failed"
    assert scan_agent["error_message"] == SCAN_FAILURE_TEXT
    assert app.selected_agent_id == "scan"
    assert len(events) == 1
    assert "Scan failed" in events[0]["data"]["content"]
    assert SCAN_FAILURE_TEXT in events[0]["data"]["content"]
