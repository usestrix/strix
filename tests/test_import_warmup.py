"""The import warm-up thread must never leave the import system poisoned.

Field failure: the warm-up thread's ``strix.core.runner`` import and the main
thread's ``strix.report`` import both walked the agents SDK graph, and the two
held each other's import locks (report -> dedupe -> agents while runner ->
hooks -> report.state). CPython's deadlock avoidance breaks such a cycle by
failing one import, which strands finished submodules in ``sys.modules`` with
their parent package gone — and the next import of one of those submodules
crashes with "partially initialized module".
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

from strix.llm import warmup


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


def test_failed_warm_import_purges_orphaned_submodules() -> None:
    result = _run(
        """
        import sys

        from strix.llm.warmup import _warm

        # A package whose import fails after a submodule already completed:
        # CPython removes the package but leaves the submodule stranded.
        import pathlib
        import tempfile

        root = pathlib.Path(tempfile.mkdtemp())
        pkg = root / "stranded_pkg"
        pkg.mkdir()
        (pkg / "ok.py").write_text("VALUE = 1")
        (pkg / "__init__.py").write_text("from . import ok\\nraise RuntimeError('boom')")
        sys.path.insert(0, str(root))

        _warm(("stranded_pkg",))

        assert "stranded_pkg" not in sys.modules
        assert "stranded_pkg.ok" not in sys.modules, "orphan survived the purge"

        # And the subtree imports cleanly afterwards up to the real error.
        try:
            import stranded_pkg  # noqa: F401
        except RuntimeError:
            pass
        else:
            raise AssertionError("expected the package's own error")
        """
    )
    assert result.returncode == 0, result.stderr


def test_purge_does_not_touch_preexisting_or_healthy_modules() -> None:
    before = frozenset(sys.modules) - {"strix.llm.warmup"}
    warmup._purge_orphaned_modules(before)
    assert "strix.llm.warmup" in sys.modules  # parent chain intact -> kept
    assert "strix" in sys.modules
