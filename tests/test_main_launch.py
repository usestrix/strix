from __future__ import annotations

import argparse
import asyncio
import importlib
import sys
from types import SimpleNamespace
from typing import Any

import pytest


cli_main: Any = importlib.import_module("strix.interface.main")
cli_args: Any = importlib.import_module("strix.interface.cli_args")
report_state_module: Any = importlib.import_module("strix.report.state")
interactive: Any = importlib.import_module("strix.interface.interactive")
tui_runtime: Any = importlib.import_module("strix.interface.tui.runtime")
tui_sidecar: Any = importlib.import_module("strix.interface.tui.sidecar")


def _launch(
    monkeypatch: pytest.MonkeyPatch,
    *,
    needs_setup: bool,
    resume_picker: bool = False,
    terminal: bool = True,
    args: argparse.Namespace | None = None,
) -> list[str]:
    calls: list[str] = []
    if args is None:
        args = argparse.Namespace(
            non_interactive=False,
            needs_setup=needs_setup,
            resume_picker=resume_picker,
            run_name=None,
            fail_on=None,
        )

    async def run_tui(_args: argparse.Namespace) -> None:
        calls.append("tui")

    async def run_cli(_args: argparse.Namespace) -> None:
        calls.append("cli")

    monkeypatch.setattr(sys, "argv", ["strix", "--target", "https://example.com"])
    monkeypatch.setattr(cli_main, "terminal_attached", lambda: terminal)
    monkeypatch.setattr("strix.interface.cli.run_cli", run_cli)
    monkeypatch.setattr(cli_main, "report_error", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli_main, "_print_error_panel", lambda title, _msg: calls.append(title))
    monkeypatch.setattr(cli_main, "display_completion_message", lambda *_args: None)
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
    monkeypatch.setattr(cli_main, "_pick_run_to_resume", lambda _args: calls.append("pick"))
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


def test_bare_resume_picks_a_run_before_the_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _launch(monkeypatch, needs_setup=False, resume_picker=True) == [
        "pick",
        "bootstrap",
        "tui",
    ]


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
        lambda exc: calls.append(f"panel:{exc}"),
    )
    monkeypatch.setattr(cli_main, "persist_current", lambda: calls.append("persist"))
    monkeypatch.setattr(cli_main, "prepare_run", lambda _args: calls.append("prepare"))
    monkeypatch.setattr(cli_main, "set_scan_phase", lambda _phase: None)

    with pytest.raises(SystemExit) as exit_info:
        cli_main._bootstrap_scan(argparse.Namespace(non_interactive=False, needs_setup=False))

    assert exit_info.value.code == 1
    assert calls == ["panel:Error code: 401"]


def test_tui_startup_failure_marks_the_prepared_run_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    report_state = SimpleNamespace(cleanup=lambda status: calls.append(f"cleanup:{status}"))
    args = argparse.Namespace(
        non_interactive=False, needs_setup=False, resume_picker=False, run_name="run", fail_on=None
    )

    async def run_tui(_args: argparse.Namespace) -> None:
        raise cli_main.InteractiveSetupUnavailableError("no sidecar")

    monkeypatch.setattr(sys, "argv", ["strix", "--target", "https://example.com"])
    monkeypatch.setattr(cli_main, "terminal_attached", lambda: True)
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


def test_no_terminal_with_a_target_runs_headless_with_a_notice(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    args = argparse.Namespace(
        non_interactive=False, needs_setup=False, resume_picker=False, run_name=None, fail_on=None
    )

    calls = _launch(monkeypatch, needs_setup=False, terminal=False, args=args)

    assert calls == ["bootstrap", "cli"]
    assert args.non_interactive is True
    assert "No terminal attached, running headless (same as -n)." in capsys.readouterr().out


def test_no_terminal_fallback_keeps_the_fail_on_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    report_state = SimpleNamespace(
        cleanup=lambda status: calls.append(f"cleanup:{status}"),
        vulnerability_reports=[{"id": "vuln-0001", "severity": "high"}],
    )
    args = argparse.Namespace(
        non_interactive=False,
        needs_setup=False,
        resume_picker=False,
        run_name="run",
        fail_on="high",
    )
    monkeypatch.setattr(cli_main.posthog, "end", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli_main.scarf, "end", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(report_state_module, "get_global_report_state", lambda: report_state)

    with pytest.raises(SystemExit) as exit_info:
        _launch(monkeypatch, needs_setup=False, terminal=False, args=args)

    assert exit_info.value.code == 2
    assert args.non_interactive is True


def test_no_terminal_without_a_target_stops_with_the_headless_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panels: list[tuple[str, str]] = []
    args = argparse.Namespace(
        non_interactive=False, needs_setup=True, resume_picker=False, run_name=None, fail_on=None
    )
    monkeypatch.setattr(cli_main, "terminal_attached", lambda: False)
    monkeypatch.setattr(cli_main, "report_error", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        cli_main, "_print_error_panel", lambda title, msg: panels.append((title, msg))
    )

    with pytest.raises(SystemExit) as exit_info:
        cli_main._fall_back_to_headless(args)

    assert exit_info.value.code == 1
    assert panels == [
        (
            "NO TERMINAL ATTACHED",
            "The interactive interface needs a terminal and no target was given.\n"
            "Pass -t <target> -n to run headless.",
        )
    ]
    assert args.non_interactive is False


def test_no_terminal_leaves_a_bare_resume_to_the_picker(monkeypatch: pytest.MonkeyPatch) -> None:
    args = argparse.Namespace(
        non_interactive=False, needs_setup=False, resume_picker=True, run_name=None, fail_on=None
    )
    monkeypatch.setattr(cli_main, "terminal_attached", lambda: False)

    cli_main._fall_back_to_headless(args)

    assert args.non_interactive is False


def test_terminal_attached_needs_a_tty_on_both_ends_and_a_real_term(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def stream(*, tty: bool) -> SimpleNamespace:
        return SimpleNamespace(isatty=lambda: tty)

    monkeypatch.delenv("TERM", raising=False)
    monkeypatch.setattr(sys, "stdin", stream(tty=True))
    monkeypatch.setattr(sys, "stdout", stream(tty=True))
    assert cli_args.terminal_attached() is True

    monkeypatch.setattr(sys, "stdout", stream(tty=False))
    assert cli_args.terminal_attached() is False

    monkeypatch.setattr(sys, "stdout", stream(tty=True))
    monkeypatch.setattr(sys, "stdin", stream(tty=False))
    assert cli_args.terminal_attached() is False

    monkeypatch.setattr(sys, "stdin", stream(tty=True))
    monkeypatch.setenv("TERM", "dumb")
    assert cli_args.terminal_attached() is False


def test_tui_process_dying_after_startup_prints_a_panel_instead_of_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    panels: list[tuple[str, str]] = []
    report_state = SimpleNamespace(cleanup=lambda status: calls.append(f"cleanup:{status}"))
    args = argparse.Namespace(
        non_interactive=False, needs_setup=False, resume_picker=False, run_name="run", fail_on=None
    )

    async def run_tui(_args: argparse.Namespace) -> None:
        raise cli_main.InteractiveInterfaceExitedError("Bubble Tea TUI exited with status 1")

    monkeypatch.setattr(sys, "argv", ["strix", "--target", "https://example.com"])
    monkeypatch.setattr(cli_main, "terminal_attached", lambda: True)
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
    monkeypatch.setattr(
        cli_main, "_print_error_panel", lambda title, msg: panels.append((title, msg))
    )
    monkeypatch.setattr(cli_main.posthog, "end", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli_main.scarf, "end", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(report_state_module, "get_global_report_state", lambda: report_state)

    with pytest.raises(SystemExit) as exit_info:
        cli_main.main()

    assert exit_info.value.code == 1
    assert calls == ["bootstrap", "cleanup:failed"]
    assert panels == [
        (
            "INTERACTIVE INTERFACE STOPPED",
            "Bubble Tea TUI exited with status 1.\n"
            "If Strix runs without a terminal (CI, nohup, pipes), pass -n to run headless.",
        )
    ]


def test_run_tui_maps_a_dead_sidecar_to_the_interface_exited_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run_go_tui(_args: argparse.Namespace) -> None:
        tui_sidecar.check_return_code(1)

    monkeypatch.setattr(tui_runtime, "run_go_tui", run_go_tui)

    with pytest.raises(interactive.InteractiveInterfaceExitedError, match="status 1"):
        asyncio.run(interactive.run_tui(argparse.Namespace()))
