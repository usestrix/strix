from __future__ import annotations

import argparse
import importlib
import sys
from types import ModuleType
from typing import Any

import pytest

import strix.interface


def _reload_dispatch_module() -> ModuleType:
    sys.modules.pop("strix.interface.interactive", None)
    return importlib.import_module("strix.interface.interactive")


def _args(*, needs_setup: bool = False) -> argparse.Namespace:
    return argparse.Namespace(needs_setup=needs_setup)


def _install_dispatch_stubs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    go_error: type[Exception] | None = None,
) -> tuple[list[tuple[str, Any]], type[Exception]]:
    calls: list[tuple[str, Any]] = []
    go_module = ModuleType("strix.interface.go_tui")
    textual_module = ModuleType("strix.interface.tui")

    class GoTuiPreActivationError(RuntimeError):
        pass

    async def run_go_tui(args: Any) -> None:
        calls.append(("go", args))
        if go_error is not None:
            raise go_error("Go TUI failed")

    async def run_textual_tui(args: Any) -> None:
        calls.append(("textual", args))

    go_module.GoTuiPreActivationError = GoTuiPreActivationError
    go_module.run_go_tui = run_go_tui
    textual_module.run_tui = run_textual_tui
    monkeypatch.setitem(sys.modules, "strix.interface.go_tui", go_module)
    monkeypatch.setitem(sys.modules, "strix.interface.tui", textual_module)
    monkeypatch.setattr(strix.interface, "go_tui", go_module, raising=False)
    monkeypatch.setattr(strix.interface, "tui", textual_module, raising=False)
    return calls, GoTuiPreActivationError


def test_textual_package_keeps_main_exports() -> None:
    sys.modules.pop("strix.interface.tui", None)

    tui = importlib.import_module("strix.interface.tui")

    assert tui.__all__ == ["StrixTUIApp", "run_tui"]
    assert tui.StrixTUIApp.__name__ == "StrixTUIApp"


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["1", " true ", "TRUE", "Yes", "ON"])
async def test_textual_toggle_accepts_normalized_true_values(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    calls, _compatibility_error = _install_dispatch_stubs(monkeypatch)
    monkeypatch.setenv("STRIX_TEXTUAL_TUI", value)
    args = _args()

    await _reload_dispatch_module().run_tui(args)

    assert calls == [("textual", args)]


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "truthy"])
async def test_textual_toggle_keeps_false_values_false(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    calls, _compatibility_error = _install_dispatch_stubs(monkeypatch)
    monkeypatch.setenv("STRIX_TEXTUAL_TUI", value)
    args = _args()

    await _reload_dispatch_module().run_tui(args)

    assert calls == [("go", args)]


@pytest.mark.asyncio
async def test_go_compatibility_error_falls_back_once_for_prepared_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, compatibility_error = _install_dispatch_stubs(monkeypatch)
    args = _args()

    async def incompatible_go_tui(run_args: Any) -> None:
        calls.append(("go", run_args))
        raise compatibility_error("unsupported protocol")

    sys.modules["strix.interface.go_tui"].run_go_tui = incompatible_go_tui
    monkeypatch.delenv("STRIX_TEXTUAL_TUI", raising=False)

    await _reload_dispatch_module().run_tui(args)

    assert calls == [("go", args), ("textual", args)]


@pytest.mark.asyncio
async def test_setup_required_go_failure_reports_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, compatibility_error = _install_dispatch_stubs(monkeypatch)
    args = _args(needs_setup=True)

    async def incompatible_go_tui(run_args: Any) -> None:
        calls.append(("go", run_args))
        raise compatibility_error("sidecar missing")

    sys.modules["strix.interface.go_tui"].run_go_tui = incompatible_go_tui
    monkeypatch.delenv("STRIX_TEXTUAL_TUI", raising=False)
    module = _reload_dispatch_module()
    with pytest.raises(module.InteractiveSetupUnavailableError):
        await module.run_tui(args)

    assert calls == [("go", args)]


@pytest.mark.asyncio
async def test_explicit_textual_rejects_setup_required_args(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, _compatibility_error = _install_dispatch_stubs(monkeypatch)
    monkeypatch.setenv("STRIX_TEXTUAL_TUI", "1")
    args = _args(needs_setup=True)

    module = _reload_dispatch_module()
    with pytest.raises(module.InteractiveSetupUnavailableError):
        await module.run_tui(args)

    assert calls == []


def test_targetless_textual_request_does_not_bypass_setup_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_TEXTUAL_TUI", "1")
    monkeypatch.setattr(sys, "argv", ["strix"])

    assert _reload_dispatch_module().textual_tui_requested() is True


def test_prepared_textual_request_still_bypasses_go_startup_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_TEXTUAL_TUI", "1")
    monkeypatch.setattr(sys, "argv", ["strix", "--target", "https://example.com"])

    assert _reload_dispatch_module().textual_tui_requested() is True


def test_explicit_textual_targetless_cli_requires_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_TEXTUAL_TUI", "1")
    monkeypatch.setattr(sys, "argv", ["strix"])
    interface_main = importlib.import_module("strix.interface.main")

    with pytest.raises(SystemExit, match="2"):
        interface_main.parse_arguments()


@pytest.mark.asyncio
async def test_go_runtime_failure_does_not_fall_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, _compatibility_error = _install_dispatch_stubs(
        monkeypatch,
        go_error=RuntimeError,
    )
    monkeypatch.delenv("STRIX_TEXTUAL_TUI", raising=False)
    args = _args()

    with pytest.raises(RuntimeError, match="Go TUI failed"):
        await _reload_dispatch_module().run_tui(args)

    assert calls == [("go", args)]
