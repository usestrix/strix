"""The import warm-up thread must never race the main thread into the engine.

Two threads that enter the same package graph from different modules hold
each other's import locks (warm-up: ``strix.core.runner`` -> ``agents``;
main: ``agents.models.interface``). CPython breaks such a cycle by failing one
of the imports, so the main thread waits for the warm-up before its first
engine import.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import threading
from typing import TYPE_CHECKING

from strix.llm import warmup


if TYPE_CHECKING:
    import pytest


def _run(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )


def test_strix_report_does_not_import_the_agents_graph() -> None:
    result = _run(
        """
        import sys

        import strix.report

        agents_modules = [m for m in sys.modules if m == "agents" or m.startswith("agents.")]
        assert not agents_modules, agents_modules
        assert "strix.report.dedupe" not in sys.modules
        """
    )
    assert result.returncode == 0, result.stderr


def test_check_duplicate_resolves_lazily() -> None:
    result = _run(
        """
        import strix.report
        from strix.report import check_duplicate
        from strix.report.dedupe import check_duplicate as direct

        assert strix.report.check_duplicate is direct is check_duplicate
        """
    )
    assert result.returncode == 0, result.stderr


def test_wait_for_import_warmup_lets_main_thread_import_the_agents_graph() -> None:
    result = _run(
        """
        import sys

        from strix.llm.warmup import start_import_warmup, wait_for_import_warmup

        # Same shape as the CLI: warm-up starts, then the main thread needs a
        # module from the middle of the agents graph.
        start_import_warmup()
        wait_for_import_warmup()

        from agents.models.interface import ModelTracing  # noqa: F401

        assert "agents" in sys.modules
        assert "agents.models" in sys.modules
        assert "strix.core.runner" in sys.modules
        """
    )
    assert result.returncode == 0, result.stderr


def test_wait_for_import_warmup_blocks_until_the_thread_finishes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()
    monkeypatch.setattr(warmup, "_warm", lambda _modules: release.wait())
    monkeypatch.setattr(warmup, "_thread", None)
    warmup.start_import_warmup(())

    waiter = threading.Thread(target=warmup.wait_for_import_warmup)
    waiter.start()
    waiter.join(0.2)
    assert waiter.is_alive(), "returned before the warm-up finished"

    release.set()
    waiter.join(5)
    assert not waiter.is_alive()


def test_failed_warm_import_does_not_raise() -> None:
    warmup._warm(("strix_no_such_module_for_warmup_test",))


def test_wait_for_import_warmup_is_a_no_op_without_a_thread() -> None:
    warmup.wait_for_import_warmup()
