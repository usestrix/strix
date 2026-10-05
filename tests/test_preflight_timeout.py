"""The startup model check has its own short timeout; scan requests keep LLM_TIMEOUT."""

from __future__ import annotations

import asyncio
import importlib
import time
from typing import TYPE_CHECKING, Any

import pytest

from strix.config import load_settings, loader
from strix.interface import scan_setup
from strix.interface.scan_setup import preflight_model_connection, preflight_request


# ``strix.interface`` re-exports the ``main`` function, which shadows the submodule name.
cli_main: Any = importlib.import_module("strix.interface.main")


if TYPE_CHECKING:
    from pathlib import Path


def _fresh_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", tmp_path / "no-cli-config.json")


class _NeverAnswers:
    def __init__(self) -> None:
        self.request_timeouts: list[float | None] = []

    async def get_response(self, *, model_settings: Any, **_: Any) -> None:
        self.request_timeouts.append((model_settings.extra_args or {}).get("timeout"))
        await asyncio.sleep(3600)


def test_preflight_timeout_defaults_to_30s_and_is_separate_from_llm_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("LLM_PREFLIGHT_TIMEOUT", raising=False)
    monkeypatch.setenv("LLM_TIMEOUT", "600")
    _fresh_settings(monkeypatch, tmp_path)
    llm = load_settings().llm
    assert llm.timeout == 600
    assert llm.preflight_timeout == 30

    monkeypatch.setenv("LLM_PREFLIGHT_TIMEOUT", "7")
    _fresh_settings(monkeypatch, tmp_path)
    assert load_settings().llm.preflight_timeout == 7


def test_preflight_request_fails_after_its_own_timeout_with_a_clear_message() -> None:
    model = _NeverAnswers()
    started = time.monotonic()
    with pytest.raises(TimeoutError) as excinfo:
        asyncio.run(
            preflight_request(
                model,  # type: ignore[arg-type]
                model_name="openai/gpt-4o",
                extra_headers=None,
                timeout=1,
                api_base_setting="DEDUPE_LLM_API_BASE",
            )
        )
    assert time.monotonic() - started < 5
    message = str(excinfo.value)
    assert "openai/gpt-4o did not answer within 1s" in message
    assert "LLM_PREFLIGHT_TIMEOUT" in message
    assert "Check DEDUPE_LLM_API_BASE" in message
    assert model.request_timeouts == [1]


def test_preflight_model_connection_uses_the_preflight_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-4o")
    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    monkeypatch.setenv("LLM_TIMEOUT", "600")
    monkeypatch.setenv("LLM_PREFLIGHT_TIMEOUT", "12")
    _fresh_settings(monkeypatch, tmp_path)
    seen: dict[str, Any] = {}

    async def fake_request(_model: Any, **kwargs: Any) -> None:
        seen.update(kwargs)

    monkeypatch.setattr(scan_setup, "preflight_request", fake_request)
    asyncio.run(preflight_model_connection("openai/gpt-4o", settings=load_settings()))
    assert seen["timeout"] == 12
    assert seen["model_name"] == "openai/gpt-4o"
    assert seen["api_base_setting"] == "LLM_API_BASE"


def test_warm_up_checks_the_dedupe_model_with_its_own_headers_and_the_preflight_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-4o")
    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    monkeypatch.setenv("LLM_EXTRA_HEADERS", '{"X-Main": "1"}')
    monkeypatch.setenv("LLM_TIMEOUT", "600")
    monkeypatch.setenv("LLM_PREFLIGHT_TIMEOUT", "9")
    monkeypatch.setenv("STRIX_DEDUPE_MODEL", "anthropic/claude-sonnet-4-5")
    monkeypatch.setenv("DEDUPE_LLM_EXTRA_HEADERS", '{"X-Dedupe": "1"}')
    _fresh_settings(monkeypatch, tmp_path)

    dedupe_model = object()
    calls: list[tuple[object, dict[str, Any]]] = []

    async def record(model: Any, **kwargs: Any) -> None:
        calls.append((model, kwargs))

    monkeypatch.setattr(scan_setup, "preflight_request", record)
    monkeypatch.setattr(cli_main, "preflight_request", record)
    monkeypatch.setattr("strix.config.models.configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr(
        "strix.report.dedupe.resolve_dedupe_model", lambda _dedupe, _name: dedupe_model
    )

    asyncio.run(cli_main.warm_up_llm())

    assert [kwargs["model_name"] for _, kwargs in calls] == [
        "openai/gpt-4o",
        "anthropic/claude-sonnet-4-5",
    ]
    assert [kwargs["timeout"] for _, kwargs in calls] == [9, 9]
    assert [kwargs["extra_headers"] for _, kwargs in calls] == [{"X-Main": "1"}, {"X-Dedupe": "1"}]
    assert [kwargs["api_base_setting"] for _, kwargs in calls] == [
        "LLM_API_BASE",
        "DEDUPE_LLM_API_BASE",
    ]
    assert calls[1][0] is dedupe_model
