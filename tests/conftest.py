"""Shared test fixtures."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


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


@pytest.fixture(autouse=True)
def _isolate_git_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Run every `git` subprocess against empty global and system config.

    Several tests build a throwaway repository and assert on what Git reports
    about it. Git layers the developer's own configuration under that, so a
    global `core.excludesFile` silently removes files from the source
    selection tests, and `commit.gpgSign` or a `core.hooksPath` can fail the
    commit outright. Point both config layers at a path that does not exist
    and supply the identity the commits need, so the repository a test sees is
    the one it created.
    """
    empty = tmp_path_factory.mktemp("git-isolation") / "absent.gitconfig"
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Strix Tests")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "tests@example.com")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Strix Tests")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "tests@example.com")


@pytest.fixture
def write_control_character_file() -> Callable[[Path, str, str], Path]:
    """Create a file whose *name* carries terminal control characters, or skip.

    A few tests prove that Strix never echoes a filename back to the terminal
    with its escape sequences intact, so they need a hostile name on disk to
    have something to render. Windows rejects those characters in a filename
    outright, so the file cannot be created and the injection the test guards
    against is not reachable on that platform. Skip with the real `OSError`
    rather than assert, so the POSIX contract keeps being exercised where it
    applies and Windows does not report a product failure it does not have.
    """

    def _write(directory: Path, name: str, content: str = "{}") -> Path:
        path = directory / name
        try:
            path.write_text(content, encoding="utf-8")
        except OSError as exc:  # pragma: no cover - platform dependent
            pytest.skip(f"this filesystem rejects control characters in filenames: {exc}")
        return path

    return _write


@pytest.fixture
def assert_secret_file_permissions() -> Callable[[Path], None]:
    """Assert a secret file is owner-only, or skip where that cannot hold.

    `write_secret_text` opens secret files with `SECRET_FILE_MODE` (0o600).
    Windows does not implement POSIX mode bits: `os.open` maps the mode down to
    a single read-only flag, so `stat()` reports 0o666 no matter what was
    requested, and confidentiality comes from the ACL on the user profile
    instead. Asserting 0o600 there would fail forever without saying anything
    about whether the file is actually protected.

    Keep the POSIX assertion exact, and on Windows skip with that reason
    spelled out, so the mode check is never quietly downgraded to something
    weaker that still looks green.
    """

    def _assert(path: Path) -> None:
        assert path.is_file(), f"{path} was not written"
        if os.name == "nt":  # pragma: no cover - platform dependent
            pytest.skip(
                "Windows ignores POSIX mode bits, so a secret file always reports "
                "0o666; its confidentiality comes from the user-profile ACL, which "
                "this test does not assert"
            )
        assert path.stat().st_mode & 0o777 == 0o600, (
            f"{path} is {path.stat().st_mode & 0o777:#o}, expected 0o600"
        )

    return _assert
