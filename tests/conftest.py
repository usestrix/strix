"""Shared test fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_mcp_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Keep the whole suite from reading the developer's real MCP config.

    ``run_strix_scan`` connects the MCP servers listed in
    ``~/.strix/mcp-servers.json`` and threads an inventory of them into the
    prompt context. Without isolation, any test that drives the runner on a
    machine that has a real config would do real network I/O and see MCP
    connections it never asked for. Point the loader at a path that does not
    exist so it resolves to "no connections", and clear the per-run selection
    env vars. Tests that exercise the loader itself set their own
    ``STRIX_MCP_CONFIG`` after this runs and so override it.
    """
    missing = tmp_path_factory.mktemp("mcp-isolation") / "no-servers.json"
    monkeypatch.setenv("STRIX_MCP_CONFIG", str(missing))
    monkeypatch.delenv("STRIX_MCP_ONLY", raising=False)
    monkeypatch.delenv("STRIX_MCP_EXCLUDE", raising=False)


@pytest.fixture(autouse=True)
def _plain_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make Rich output identical on every developer's machine.

    Many CLI tests force ``isatty()`` to ``True`` to exercise the human-readable
    code path and then assert on the plain text. Rich picks its color system
    from ``TERM``, ``COLORTERM``, and ``FORCE_COLOR``, so on a real terminal
    those assertions would meet ANSI escape codes instead of the words they
    look for. A dumb terminal renders the same text without any styling.
    """
    monkeypatch.setenv("TERM", "dumb")
    for name in ("COLORTERM", "FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _isolate_wallet_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a developer's real mppx wallet out of the top-up tests.

    ``strix cloud billing topup`` chooses the Stripe Link flow or the
    preconfigured mppx wallet from these variables, so leaving them set would
    silently switch which branch a test runs.
    """
    for name in ("MPPX_ACCOUNT", "MPPX_STRIPE_SECRET_KEY", "MPPX_STRIPE_PAYMENT_METHOD"):
        monkeypatch.delenv(name, raising=False)
