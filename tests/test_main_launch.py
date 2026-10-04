from __future__ import annotations

import argparse
import importlib
import sys
from types import SimpleNamespace
from typing import Any

import pytest


cli_main: Any = importlib.import_module("strix.interface.main")
report_state_module: Any = importlib.import_module("strix.report.state")


def _launch(monkeypatch: pytest.MonkeyPatch, *, needs_setup: bool) -> list[str]:
    calls: list[str] = []
    args = argparse.Namespace(
        non_interactive=False,
        needs_setup=needs_setup,
        run_name=None,
        fail_on=None,
    )

    async def run_tui(_args: argparse.Namespace) -> None:
        calls.append("tui")

    monkeypatch.setattr(sys, "argv", ["strix", "--target", "https://example.com"])
    monkeypatch.setattr(cli_main, "setup_console_logging", lambda: None)
    monkeypatch.setattr(cli_main, "start_import_warmup", lambda: None)
    monkeypatch.setattr(cli_main, "parse_arguments", lambda: args)
    monkeypatch.setattr(cli_main, "start_background_check", lambda: None)
    monkeypatch.setattr(cli_main, "prompt_update_if_available", lambda _console: False)
    monkeypatch.setattr(cli_main, "check_docker_installed", lambda: None)
    monkeypatch.setattr(cli_main, "pull_docker_image", lambda: None)
    monkeypatch.setattr(cli_main, "validate_environment", lambda: None)
    monkeypatch.setattr(cli_main, "wait_for_import_warmup", lambda: None)
    monkeypatch.setattr(cli_main, "_bootstrap_scan", lambda _args: calls.append("bootstrap"))
    monkeypatch.setattr(cli_main, "run_tui", run_tui)
    monkeypatch.setattr(cli_main, "notify_update", lambda _console: None)

    cli_main.main()
    return calls


def test_direct_launch_verifies_the_model_before_the_tui(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _launch(monkeypatch, needs_setup=False) == ["bootstrap", "tui"]


def test_start_screen_launch_defers_the_model_check_to_the_tui(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _launch(monkeypatch, needs_setup=True) == ["tui"]


def test_direct_launch_with_a_bad_key_prints_the_panel_and_exits_before_the_tui(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    failure = cli_main.ModelConnectionError("openai/gpt-4o", RuntimeError("Error code: 401"))

    async def warm_up_llm() -> None:
        raise failure

    monkeypatch.setattr(cli_main, "warm_up_llm", warm_up_llm)
    monkeypatch.setattr(cli_main, "report_error", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        cli_main,
        "_print_model_connection_error",
        lambda exc, model: calls.append(f"panel:{model}:{exc}"),
    )
    monkeypatch.setattr(cli_main, "persist_current", lambda: calls.append("persist"))
    monkeypatch.setattr(cli_main, "prepare_run", lambda _args: calls.append("prepare"))
    monkeypatch.setattr(cli_main, "set_scan_phase", lambda _phase: None)

    with pytest.raises(SystemExit) as exit_info:
        cli_main._bootstrap_scan(argparse.Namespace(non_interactive=False, needs_setup=False))

    assert exit_info.value.code == 1
    assert calls == ["panel:openai/gpt-4o:Error code: 401"]


def test_tui_startup_failure_marks_the_prepared_run_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    report_state = SimpleNamespace(cleanup=lambda status: calls.append(f"cleanup:{status}"))
    args = argparse.Namespace(
        non_interactive=False, needs_setup=False, run_name="run", fail_on=None
    )

    async def run_tui(_args: argparse.Namespace) -> None:
        raise cli_main.InteractiveSetupUnavailableError("no sidecar")

    monkeypatch.setattr(sys, "argv", ["strix", "--target", "https://example.com"])
    monkeypatch.setattr(cli_main, "setup_console_logging", lambda: None)
    monkeypatch.setattr(cli_main, "start_import_warmup", lambda: None)
    monkeypatch.setattr(cli_main, "parse_arguments", lambda: args)
    monkeypatch.setattr(cli_main, "start_background_check", lambda: None)
    monkeypatch.setattr(cli_main, "prompt_update_if_available", lambda _console: False)
    monkeypatch.setattr(cli_main, "check_docker_installed", lambda: None)
    monkeypatch.setattr(cli_main, "pull_docker_image", lambda: None)
    monkeypatch.setattr(cli_main, "validate_environment", lambda: None)
    monkeypatch.setattr(cli_main, "wait_for_import_warmup", lambda: None)
    monkeypatch.setattr(cli_main, "_bootstrap_scan", lambda _args: calls.append("bootstrap"))
    monkeypatch.setattr(cli_main, "run_tui", run_tui)
    monkeypatch.setattr(cli_main, "report_error", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli_main, "_print_error_panel", lambda *_args: calls.append("panel"))
    monkeypatch.setattr(cli_main.posthog, "end", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli_main.scarf, "end", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(report_state_module, "get_global_report_state", lambda: report_state)

    with pytest.raises(SystemExit) as exit_info:
        cli_main.main()

    assert exit_info.value.code == 1
    assert calls == ["bootstrap", "panel", "cleanup:failed"]
