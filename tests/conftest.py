"""Shared test fixtures."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.config import loader


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _isolate_cli_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[None]:
    """Keep the whole suite from reading the developer's real cli-config.json.

    Strix persists the last ``STRIX_LLM`` into ``~/.strix/cli-config.json``, so a
    developer who has run any subscription backend once has a config that changes
    what ``load_settings()`` resolves, and with it what a ``ReportState`` built in
    a test believes about auth mode and cost. Point the loader at a path that does
    not exist. ``load_settings`` memoizes into ``loader._cached`` by direct
    assignment, which monkeypatch cannot track, so that is reset on both sides.
    """
    missing = tmp_path_factory.mktemp("cli-config-isolation") / "cli-config.json"
    monkeypatch.setattr(loader, "_override", missing)
    loader._cached = None
    yield
    loader._cached = None


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
