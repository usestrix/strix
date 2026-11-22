from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

import pytest
from agents.models import _openai_shared

from strix.config import codex, connections, load_settings, loader
from strix.config.models import configure_sdk_model_defaults


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_ENV_KEYS = (
    "STRIX_LLM",
    "STRIX_REASONING_EFFORT",
    "EXA_API_KEY",
    "PERPLEXITY_API_KEY",
    *connections._API_KEY_ALIASES,
    *connections._API_BASE_ALIASES,
    *(key for provider in connections.PROVIDERS for key in provider.env_keys),
)


@pytest.fixture(autouse=True)
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    path = tmp_path / "cli-config.json"
    monkeypatch.setattr(loader, "_override", path)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(connections, "_shell_env", None)
    monkeypatch.setattr(connections, "_live_catalogs", {})
    monkeypatch.setattr(codex, "is_authenticated", lambda: False)
    yield path
    for key in _ENV_KEYS:
        os.environ.pop(key, None)
    loader._cached = None


def _document(path: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return document


def test_nothing_is_connected_on_a_fresh_install() -> None:
    directory = connections.provider_directory()

    assert [entry["name"] for entry in directory["popular"]][:2] == [
        "Vercel AI Gateway",
        "OpenRouter",
    ]
    assert not any(entry["connected"] for group in directory.values() for entry in group)
    assert connections.model_picker()["providers"] == []
    assert connections.current_selection() is None


def test_connect_then_select_configures_the_run_and_persists(isolated: Path) -> None:
    connections.connect("anthropic", api_key=" sk-ant ")
    models = connections.provider_models("anthropic")
    assert models
    assert all(model.startswith("anthropic/") for model in models)

    connections.select_model("anthropic", models[0])

    llm = load_settings().llm
    assert (llm.model, llm.api_key, llm.api_base) == (models[0], "sk-ant", None)
    document = _document(isolated)
    assert document["env"] == {"STRIX_LLM": models[0], "LLM_API_KEY": "sk-ant"}
    assert document["providers"] == {"anthropic": {"api_key": "sk-ant", "api_base": None}}
    assert document["models"]["recent"] == [{"provider": "anthropic", "model": models[0]}]
    assert isolated.stat().st_mode & 0o777 == 0o600


def test_switching_provider_swaps_the_key_and_drops_the_old_base() -> None:
    connections.connect("ollama", api_base="http://localhost:11434")
    connections.connect("anthropic", api_key="sk-ant")
    connections.select_model("ollama", "ollama/qwen3")
    assert load_settings().llm.api_base == "http://localhost:11434"

    connections.select_model("anthropic", "anthropic/claude-sonnet-5-5")

    llm = load_settings().llm
    assert (llm.api_key, llm.api_base) == ("sk-ant", None)
    assert "LLM_API_BASE" not in os.environ
    assert [entry["provider"] for entry in connections.model_picker()["recent"]] == [
        "anthropic",
        "ollama",
    ]


def test_provider_key_in_the_shell_counts_as_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or")
    monkeypatch.setattr(connections, "_live_models", lambda *_: ["openrouter/a/b"])

    picker = connections.model_picker()
    assert [(entry["id"], entry["models"]) for entry in picker["providers"]] == [
        ("openrouter", ["openrouter/a/b"])
    ]

    connections.select_model("openrouter", "openrouter/a/b")
    assert load_settings().llm.api_key == "sk-or"


def test_legacy_env_connection_is_listed_as_current(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-5-5")
    monkeypatch.setenv("LLM_API_KEY", "sk-legacy")

    assert connections.current_selection() == {
        "provider": "anthropic",
        "model": "anthropic/claude-opus-5-5",
    }
    creds = connections.credentials("anthropic")
    assert creds is not None
    assert creds.api_key == "sk-legacy"


def test_select_requires_a_connected_provider() -> None:
    with pytest.raises(ValueError, match="Anthropic is not connected"):
        connections.select_model("anthropic", "anthropic/claude-sonnet-5-5")


def test_connect_validates_inputs() -> None:
    with pytest.raises(ValueError, match="API key is required"):
        connections.connect("anthropic", api_key=" ")
    with pytest.raises(ValueError, match="Base URL must start"):
        connections.connect("custom", api_base="localhost:8000")
    with pytest.raises(ValueError, match="Unknown provider"):
        connections.connect("nope", api_key="x")


def test_disconnect_and_favorites_round_trip() -> None:
    connections.connect("anthropic", api_key="sk-ant")
    assert connections.toggle_favorite("anthropic", "anthropic/claude-opus-5-5") is True
    assert connections.model_picker()["favorite"] == [
        {"provider": "anthropic", "model": "anthropic/claude-opus-5-5"}
    ]
    assert connections.toggle_favorite("anthropic", "anthropic/claude-opus-5-5") is False

    connections.disconnect("anthropic")
    assert connections.credentials("anthropic") is None


def test_settings_persist_and_validate(isolated: Path) -> None:
    connections.set_setting("effort", "low")
    connections.set_setting("exa", "exa-key")
    assert load_settings().llm.reasoning_effort == "low"
    assert _document(isolated)["env"] == {
        "STRIX_REASONING_EFFORT": "low",
        "EXA_API_KEY": "exa-key",
    }
    connections.set_setting("exa", None)
    assert "EXA_API_KEY" not in _document(isolated)["env"]
    with pytest.raises(ValueError, match="Effort must be one of"):
        connections.set_setting("effort", "extreme")


def test_persist_current_keeps_connections(isolated: Path) -> None:
    connections.connect("anthropic", api_key="sk-ant")
    connections.select_model("anthropic", "anthropic/claude-sonnet-5-5")

    loader.persist_current()

    document = _document(isolated)
    assert document["providers"]["anthropic"]["api_key"] == "sk-ant"
    assert document["env"]["STRIX_LLM"] == "anthropic/claude-sonnet-5-5"


def test_catalog_skips_dated_snapshots_and_non_chat_models() -> None:
    connections.connect("openai", api_key="sk-o")
    models = connections.provider_models("openai")

    assert "openai/gpt-5.4" in models
    assert not any(model.endswith("-2026-03-05") for model in models)
    assert not any("realtime" in model or model.startswith("openai/ft:") for model in models)


def test_keyless_server_never_inherits_the_previous_key() -> None:
    connections.connect("openai", api_key="sk-openai")
    connections.select_model("openai", "openai/gpt-5.5")
    configure_sdk_model_defaults(load_settings())
    assert _openai_shared.get_default_openai_key() == "sk-openai"

    connections.connect("custom", api_base="http://localhost:8000/v1")
    connections.select_model("custom", "openai/local-model")
    assert _openai_shared.get_default_openai_key() is None
    assert os.environ.get("OPENAI_API_KEY") is None
    assert load_settings().llm.api_key == "not-needed"
    assert load_settings().llm.api_base == "http://localhost:8000/v1"


def test_switching_away_keeps_a_connection_saved_only_in_the_env_block(isolated: Path) -> None:
    isolated.write_text(
        json.dumps({"env": {"STRIX_LLM": "anthropic/claude-opus-5-5", "LLM_API_KEY": "sk-old"}}),
        encoding="utf-8",
    )
    loader.reload_settings()
    connections.connect("openrouter", api_key="sk-or")
    connections.select_model("openrouter", "openrouter/z-ai/glm-5.3")

    assert _document(isolated)["providers"]["anthropic"] == {"api_key": "sk-old", "api_base": None}
    creds = connections.credentials("anthropic")
    assert creds is not None
    assert creds.api_key == "sk-old"
