from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

from rich.console import Console
from rich.panel import Panel

from strix.interface import cli


def test_cli_report_callbacks_render_new_and_updated_findings() -> None:
    report_state = SimpleNamespace(
        vulnerability_found_callback=None,
        vulnerability_updated_callback=None,
    )
    console = Mock(spec=Console)

    cli._configure_report_callbacks(cast("Any", report_state), console)

    report = {"id": "vuln-0001", "title": "Unsafe redirect"}
    report_state.vulnerability_found_callback(report)
    report_state.vulnerability_updated_callback(report)

    panels = [call.args[0] for call in console.print.call_args_list if call.args]
    assert all(isinstance(panel, Panel) for panel in panels)
    assert panels[0].title == "[bold red]VULN-0001"
    assert panels[1].title == "[bold yellow]VULN-0001 — UPDATED FINDING"
