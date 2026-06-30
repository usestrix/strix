"""Tests for clean process exit on unhandled provider errors in ``main``."""

import importlib
from argparse import Namespace
from collections.abc import Iterator
from unittest.mock import MagicMock

import httpx
import openai
import pytest


# ``strix.interface.__init__`` rebinds the ``main`` attribute to the function,
# shadowing the submodule, so import the module object explicitly.
main_module = importlib.import_module("strix.interface.main")


def _build_args() -> Namespace:
    return Namespace(
        config=None,
        resume="test-run",
        run_name=None,
        targets_info=[],
        instruction=None,
        scan_mode="default",
        non_interactive=True,
    )


def _bad_request_error() -> openai.BadRequestError:
    response = httpx.Response(400, request=httpx.Request("POST", "http://test"))
    return openai.BadRequestError(message="bad request", response=response, body=None)


@pytest.fixture
def _patched_main(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    settings = MagicMock()
    monkeypatch.setattr(main_module, "parse_arguments", _build_args)
    monkeypatch.setattr(main_module, "check_docker_installed", lambda: None)
    monkeypatch.setattr(main_module, "pull_docker_image", lambda: None)
    monkeypatch.setattr(main_module, "validate_environment", lambda: None)
    monkeypatch.setattr(main_module, "persist_current", lambda: None)
    monkeypatch.setattr(main_module, "load_settings", lambda: settings)
    monkeypatch.setattr(main_module, "get_global_report_state", lambda: None)
    monkeypatch.setattr(main_module, "posthog", MagicMock())
    monkeypatch.setattr(main_module, "scarf", MagicMock())

    # The first ``asyncio.run`` call is the LLM warm-up (let it pass); the
    # second drives the scan and is where an unhandled provider error surfaces.
    state = {"calls": 0}

    def fake_run(coro: object) -> None:
        if hasattr(coro, "close"):
            coro.close()  # never execute the coroutine body
        state["calls"] += 1
        if state["calls"] == 1:
            return
        raise _bad_request_error()

    monkeypatch.setattr(main_module.asyncio, "run", fake_run)
    yield


def test_bad_request_error_exits_cleanly(_patched_main: None) -> None:
    """An unhandled ``BadRequestError`` must exit(1), not re-raise."""
    with pytest.raises(SystemExit) as exc_info:
        main_module.main()

    assert exc_info.value.code == 1
    assert not isinstance(exc_info.value, openai.BadRequestError)
