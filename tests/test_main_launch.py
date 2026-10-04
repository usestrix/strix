from __future__ import annotations

import argparse
import importlib
import sys
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    import pytest


cli_main: Any = importlib.import_module("strix.interface.main")


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
    monkeypatch.setattr(cli_main, "configure_dependency_logging", lambda: None)
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
