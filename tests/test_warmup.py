from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_start_import_warmup_preimports_agents_sdk_synchronously() -> None:
    """``start_import_warmup`` must import the thread-unsafe ``agents`` SDK on
    the caller's thread before spawning the daemon warm-up thread.

    ``openai-agents`` has an internal import cycle that is not thread-safe: if
    the warm-up thread and the main thread import the ``agents`` package
    concurrently, CPython can hand one of them a partially initialized module
    (``ImportError: cannot import name 'AgentOutputSchemaBase' ... circular
    import``). Warming ``agents`` synchronously closes that race window.

    Run in a fresh interpreter with an empty ``modules`` set so the daemon
    thread warms nothing: ``agents`` can then only be in ``sys.modules`` because
    the synchronous pre-import ran.
    """
    child = textwrap.dedent(
        """
        import sys

        assert "agents" not in sys.modules
        from strix.llm.warmup import start_import_warmup

        # Importing the warm-up module alone must not pull the agents SDK.
        assert "agents" not in sys.modules
        start_import_warmup(modules=())
        assert "agents" in sys.modules, "agents SDK was not pre-imported synchronously"
        print("OK")
        """
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", child],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK" in result.stdout
