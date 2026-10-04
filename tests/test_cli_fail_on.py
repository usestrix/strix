"""Tests for the --fail-on headless severity gate."""

from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace
from typing import Any

import pytest


cli_main: Any = importlib.import_module("strix.interface.main")
cli_args: Any = importlib.import_module("strix.interface.cli_args")


def _stub_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(max_local_copy_mb=1024)),
    )


def _reports(*severities: str | None) -> list[dict[str, Any]]:
    return [{"id": f"vuln-{i:04d}", "severity": sev} for i, sev in enumerate(severities, 1)]


def test_no_findings_never_fail() -> None:
    assert not cli_main.findings_fail_build([], None)
    assert not cli_main.findings_fail_build([], "info")


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info", "none"])
def test_without_threshold_any_finding_fails(severity: str) -> None:
    assert cli_main.findings_fail_build(_reports(severity), None)


@pytest.mark.parametrize(
    ("fail_on", "severity", "expected"),
    [
        ("high", "critical", True),
        ("high", "high", True),
        ("high", "medium", False),
        ("high", "low", False),
        ("high", "info", False),
        ("critical", "high", False),
        ("critical", "critical", True),
        ("info", "info", True),
        ("info", "low", True),
        ("medium", "HIGH", True),
        ("medium", " Low ", False),
    ],
)
def test_threshold_compares_severity(fail_on: str, severity: str, expected: bool) -> None:
    assert cli_main.findings_fail_build(_reports(severity), fail_on) is expected


def test_one_finding_at_threshold_fails_a_mixed_run() -> None:
    assert cli_main.findings_fail_build(_reports("info", "low", "high"), "high")


@pytest.mark.parametrize("severity", ["severe", "", None])
def test_unrecognized_severity_fails_closed(severity: str | None) -> None:
    assert cli_main.findings_fail_build(_reports(severity), "critical")


def test_none_severity_passes_any_threshold() -> None:
    assert not cli_main.findings_fail_build(_reports("none"), "info")


def test_parse_fail_on_is_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys, "argv", ["strix", "-t", "https://test.com/", "-n", "--fail-on", "HIGH"]
    )

    args = cli_main.parse_arguments()

    assert args.fail_on == "high"


def test_parse_fail_on_defaults_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["strix", "-t", "https://test.com/", "-n"])

    assert cli_main.parse_arguments().fail_on is None


def test_parse_fail_on_rejects_unknown_severity(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys, "argv", ["strix", "-t", "https://test.com/", "-n", "--fail-on", "severe"]
    )

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "--fail-on" in capsys.readouterr().err


def test_parse_fail_on_requires_non_interactive(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(cli_args, "terminal_attached", lambda: True)
    monkeypatch.setattr(sys, "argv", ["strix", "-t", "https://test.com/", "--fail-on", "high"])

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "--fail-on only applies to headless runs" in capsys.readouterr().err


def test_parse_fail_on_without_a_terminal_waits_for_the_headless_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(cli_args, "terminal_attached", lambda: False)
    monkeypatch.setattr(sys, "argv", ["strix", "-t", "https://test.com/", "--fail-on", "high"])

    args = cli_main.parse_arguments()

    assert args.fail_on == "high"
    assert args.non_interactive is False
