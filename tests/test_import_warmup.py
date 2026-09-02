"""The import warm-up thread must never leave the import system poisoned.

Field failure: the warm-up thread's ``strix.core.runner`` import and the main
thread's ``strix.report`` import both walked the agents SDK graph, and the two
held each other's import locks (report -> dedupe -> agents while runner ->
hooks -> report.state). CPython's deadlock avoidance breaks such a cycle by
failing one import, which strands finished submodules in ``sys.modules`` with
their parent package gone — and the next import of one of those submodules
crashes with "partially initialized module".

Second field failure: with the sandbox image already present, ``main()`` got
from ``start_import_warmup()`` to ``warm_up_llm`` (the first agents-SDK import
on the main thread) in a few hundred milliseconds, while the warm-up thread was
still inside the agents package. The two imports deadlocked on each other's
module locks, CPython failed the warm-up's import to break the cycle, and the
main thread died with ``KeyError: 'agents.models'``. The main thread must wait
for the warm-up before it imports from that graph.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
import textwrap
from typing import TYPE_CHECKING

import pytest

from strix.llm import warmup


if TYPE_CHECKING:
    from pathlib import Path


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


def test_wait_for_import_warmup_returns_once_the_thread_has_finished() -> None:
    result = _run(
        """
        import pathlib
        import sys
        import tempfile

        from strix.llm import warmup

        root = pathlib.Path(tempfile.mkdtemp())
        (root / "slow_pkg").mkdir()
        (root / "slow_pkg" / "__init__.py").write_text(
            "import time\\ntime.sleep(0.5)\\nREADY = True"
        )
        sys.path.insert(0, str(root))

        thread = warmup.start_import_warmup(("slow_pkg",))
        assert thread.is_alive()
        warmup.wait_for_import_warmup()
        assert not thread.is_alive()
        assert sys.modules["slow_pkg"].READY
        """
    )
    assert result.returncode == 0, result.stderr


def test_wait_for_import_warmup_without_a_warm_up_is_a_noop() -> None:
    result = _run(
        """
        from strix.llm import warmup

        warmup.wait_for_import_warmup()
        assert warmup._thread is None
        """
    )
    assert result.returncode == 0, result.stderr


def test_main_waits_for_the_import_warm_up_before_entering_the_scan_phase(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # ``strix.interface`` re-exports the ``main`` function under the module's name.
    main_mod = importlib.import_module("strix.interface.main")

    (tmp_path / "slow_pkg").mkdir()
    (tmp_path / "slow_pkg" / "__init__.py").write_text("import time\ntime.sleep(0.5)\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "slow_pkg", raising=False)
    monkeypatch.setattr(warmup, "_thread", None)
    real_start = warmup.start_import_warmup
    monkeypatch.setattr(warmup, "start_import_warmup", lambda: real_start(("slow_pkg",)))

    for name in (
        "start_background_check",
        "check_docker_installed",
        "pull_docker_image",
        "validate_environment",
    ):
        monkeypatch.setattr(main_mod, name, lambda: None)

    seen: dict[str, bool] = {}

    def fake_bootstrap(_args: object) -> None:
        thread = warmup._thread
        seen["warmup_alive"] = thread is not None and thread.is_alive()
        seen["warmed"] = "slow_pkg" in sys.modules
        raise SystemExit(0)

    monkeypatch.setattr(main_mod, "_bootstrap_scan", fake_bootstrap)
    monkeypatch.setattr(sys, "argv", ["strix", "-n", "--target", str(tmp_path)])

    with pytest.raises(SystemExit):
        main_mod.main()

    assert seen == {"warmup_alive": False, "warmed": True}
