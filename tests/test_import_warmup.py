"""Tests for background import warm-up synchronization."""

from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace
from typing import Any

import pytest


cli_main: Any = importlib.import_module("strix.interface.main")
warmup: Any = importlib.import_module("strix.llm.warmup")


class ExpectedStopError(Exception):
    """Stop the CLI after verifying startup ordering."""


def test_main_waits_for_import_warmup_before_scan_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    joined = False

    class FakeThread:
        def join(self) -> None:
            nonlocal joined
            joined = True

    monkeypatch.setattr(warmup, "start_import_warmup", FakeThread)
    monkeypatch.setattr(cli_main, "configure_dependency_logging", lambda: None)
    monkeypatch.setattr(
        cli_main,
        "parse_arguments",
        lambda: SimpleNamespace(non_interactive=True, needs_setup=False),
    )
    monkeypatch.setattr(cli_main, "start_background_check", lambda: None)
    monkeypatch.setattr(cli_main, "check_docker_installed", lambda: None)
    monkeypatch.setattr(cli_main, "pull_docker_image", lambda: None)
    monkeypatch.setattr(sys, "argv", ["strix", "-n", "-t", "example.com"])

    def stop_after_bootstrap(_args: object) -> None:
        assert joined
        raise ExpectedStopError

    monkeypatch.setattr(cli_main, "_bootstrap_scan", stop_after_bootstrap)

    with pytest.raises(ExpectedStopError):
        cli_main.main()
