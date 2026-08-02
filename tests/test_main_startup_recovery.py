"""Startup orchestration tests for recoverable provider authentication failures."""

from __future__ import annotations

import argparse
import importlib
import sys
from typing import TYPE_CHECKING, Any

import pytest

from strix import config
from strix.config import ProviderAuthState
from strix.config.settings import Settings


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


main_module: Any = importlib.import_module("strix.interface.main")
cli_args_module: Any = importlib.import_module("strix.interface.cli_args")
models_module: Any = importlib.import_module("strix.config.models")
MODEL = "anthropic/claude-opus-4-7"
TARGET = {
    "type": "web_application",
    "details": {"target": "https://example.com"},
    "original": "https://example.com",
}


@pytest.fixture(autouse=True)
def _isolated_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "STRIX_LLM",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "LLM_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    config.apply_config_override(tmp_path / "cli-config.json")
    config.clear_provider_credentials_invalid("anthropic")
    config.reset_settings_cache()


def _args(*, non_interactive: bool = False) -> argparse.Namespace:
    return argparse.Namespace(
        non_interactive=non_interactive,
        resume=None,
        needs_setup=False,
        setup_invalid_provider=None,
        setup_guidance=None,
        targets_info=[TARGET.copy()],
        scan_mode="deep",
        instruction=None,
        scope_mode="full",
        diff_base=None,
        user_explicit_instruction=None,
        max_budget_usd=None,
        max_turns=100,
        run_name=None,
    )


def _install_startup_doubles(
    monkeypatch: pytest.MonkeyPatch,
    *,
    args: argparse.Namespace,
    settings: Settings,
    failures: dict[str, BaseException],
) -> tuple[dict[str, int], list[argparse.Namespace]]:
    calls = {"prepare": 0, "telemetry": 0, "persist": 0}
    tui_args: list[argparse.Namespace] = []

    class FakeModel:
        def __init__(self, model_name: str) -> None:
            self.model_name = model_name

        async def get_response(self, **_kwargs: Any) -> None:
            failure = failures.get(self.model_name)
            if failure is not None:
                raise failure

    class FakeProvider:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def get_model(self, model_name: str) -> FakeModel:
            return FakeModel(model_name)

    def count(name: str) -> Callable[[argparse.Namespace], None]:
        def record(_args: argparse.Namespace) -> None:
            calls[name] += 1

        return record

    async def run_interface(run_args: argparse.Namespace) -> None:
        tui_args.append(run_args)

    monkeypatch.setattr(main_module, "parse_arguments", lambda: args)
    monkeypatch.setattr(main_module, "load_settings", lambda: settings)
    monkeypatch.setattr(models_module, "configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr(models_module, "StrixProvider", FakeProvider)
    monkeypatch.setattr(main_module, "start_background_check", lambda: None)
    monkeypatch.setattr(main_module, "prompt_update_if_available", lambda _console: False)
    monkeypatch.setattr(main_module, "check_docker_installed", lambda: None)
    monkeypatch.setattr(main_module, "pull_docker_image", lambda: None)
    monkeypatch.setattr(main_module, "validate_environment", lambda: None)
    monkeypatch.setattr(main_module, "prepare_run", count("prepare"))
    monkeypatch.setattr(main_module, "telemetry_start", count("telemetry"))
    monkeypatch.setattr(
        main_module,
        "persist_current",
        lambda **_kwargs: calls.__setitem__("persist", calls["persist"] + 1),
    )
    monkeypatch.setattr(main_module, "run_tui", run_interface)
    monkeypatch.setattr("strix.interface.cli.run_cli", run_interface)
    return calls, tui_args


def test_successful_startup_persists_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _args(non_interactive=True)
    settings = Settings.model_validate({"llm": {"model": MODEL, "timeout": 1}})
    calls, tui_args = _install_startup_doubles(
        monkeypatch,
        args=args,
        settings=settings,
        failures={},
    )
    monkeypatch.setattr(
        main_module,
        "provider_auth_status",
        lambda _provider: config.ProviderAuthStatus(
            state=ProviderAuthState.CONFIGURED,
            detail="configured",
        ),
    )

    def record_persist() -> None:
        calls["persist"] += 1

    monkeypatch.setattr(main_module, "persist_current", record_persist)

    main_module.main()

    assert tui_args == [args]
    assert calls == {"prepare": 1, "telemetry": 1, "persist": 1}


def test_interactive_startup_defers_preparation_to_the_tui(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Interactive launches paint the TUI before any model round trip."""
    config.set_provider_api_key("anthropic", "configured-key")
    args = _args()
    calls, tui_args = _install_startup_doubles(
        monkeypatch,
        args=args,
        settings=Settings.model_validate({"llm": {"model": MODEL, "timeout": 1}}),
        failures={MODEL: RuntimeError("HTTP 401 Unauthorized")},
    )

    main_module.main()

    assert tui_args == [args]
    assert args.needs_setup is False
    assert args.run_name is None
    assert calls == {"prepare": 0, "telemetry": 0, "persist": 0}


def test_noninteractive_rejected_saved_key_is_fatal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config.set_provider_api_key("anthropic", "rejected-saved-key")
    args = _args(non_interactive=True)
    calls, tui_args = _install_startup_doubles(
        monkeypatch,
        args=args,
        settings=Settings.model_validate({"llm": {"model": MODEL, "timeout": 1}}),
        failures={MODEL: RuntimeError("HTTP 401 Unauthorized")},
    )

    with pytest.raises(SystemExit, match="1"):
        main_module.main()

    assert args.needs_setup is False
    assert tui_args == []
    assert calls == {"prepare": 0, "telemetry": 0, "persist": 0}


@pytest.mark.parametrize(
    "failure",
    [
        TimeoutError("connection timed out"),
        RuntimeError("429 rate limit exceeded"),
        RuntimeError("403 model access denied"),
    ],
)
def test_ordinary_model_connection_failures_do_not_enter_setup(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: BaseException,
) -> None:
    config.set_provider_api_key("anthropic", "configured-key")
    args = _args(non_interactive=True)
    calls, tui_args = _install_startup_doubles(
        monkeypatch,
        args=args,
        settings=Settings.model_validate({"llm": {"model": MODEL, "timeout": 1}}),
        failures={MODEL: failure},
    )

    with pytest.raises(SystemExit, match="1"):
        main_module.main()

    assert "LLM CONNECTION FAILED" in capsys.readouterr().out
    assert args.needs_setup is False
    assert config.provider_auth_status("anthropic").state is ProviderAuthState.CONFIGURED
    assert tui_args == []
    assert calls == {"prepare": 0, "telemetry": 0, "persist": 0}


def test_parse_arguments_keeps_interactive_targetless_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", ["strix"])

    args = main_module.parse_arguments()

    assert args.needs_setup is True
    assert args.targets_info == []


def test_parse_arguments_still_requires_target_noninteractively(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["strix", "--non-interactive"])

    with pytest.raises(SystemExit, match="2"):
        main_module.parse_arguments()

    assert "the following arguments are required" in capsys.readouterr().err


def test_legacy_max_budget_flag_remains_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--target", "example.com", "--max-budget-usd", "12.5"],
    )

    args = main_module.parse_arguments()

    assert args.max_budget_usd == 12.5


def test_parse_arguments_applies_custom_config_before_loading_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "custom.json"
    calls: list[str] = []

    def fake_validate(_raw_path: str) -> Path:
        calls.append("validate")
        return config_path

    monkeypatch.setattr(cli_args_module, "validate_config_file", fake_validate)
    monkeypatch.setattr(
        cli_args_module,
        "apply_config_override",
        lambda _path: calls.append("apply"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--config", str(config_path), "--target", "https://example.com"],
    )

    main_module.parse_arguments()

    assert calls == ["validate", "apply"]
