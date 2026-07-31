"""Tests for strix.config.loader: JSON overrides, alias resolution, persistence."""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

import pytest
from pydantic import AliasChoices, Field, ValidationError
from pydantic.fields import FieldInfo

from strix.config import loader
from strix.config.settings import ContextSettings


if TYPE_CHECKING:
    from pathlib import Path


_LLM_ENV_KEYS = [
    "STRIX_LLM",
    "LLM_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "LLM_API_BASE",
    "LLM_EXTRA_HEADERS",
    "LLM_DISABLE_STREAMING",
    "OPENAI_API_BASE",
    "OPENAI_BASE_URL",
    "LITELLM_BASE_URL",
    "OLLAMA_API_BASE",
    "STRIX_REASONING_EFFORT",
    "STRIX_FORCE_REQUIRED_TOOL_CHOICE",
    "LLM_TIMEOUT",
    "DEDUPE_LLM_EXTRA_HEADERS",
    "PERPLEXITY_API_KEY",
    "STRIX_IMAGE",
    "STRIX_RUNTIME_BACKEND",
    "STRIX_MAX_LOCAL_COPY_MB",
    "STRIX_TELEMETRY",
]


@pytest.fixture(autouse=True)
def _reset_loader_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset module globals and clear known env vars for deterministic runs."""
    known_keys = {key.upper() for key in _LLM_ENV_KEYS}
    for key in list(os.environ):
        if key.upper() in known_keys:
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)


def test_read_json_overrides_missing_file(tmp_path: Path) -> None:
    assert loader._read_json_overrides(tmp_path / "nope.json") == {}


def test_read_json_overrides_corrupt_json(tmp_path: Path) -> None:
    path = tmp_path / "cli-config.json"
    path.write_text("{not valid json", encoding="utf-8")
    assert loader._read_json_overrides(path) == {}


def test_read_json_overrides_non_dict_env(tmp_path: Path) -> None:
    path = tmp_path / "cli-config.json"
    path.write_text(json.dumps({"env": ["not", "a", "dict"]}), encoding="utf-8")
    assert loader._read_json_overrides(path) == {}


def test_read_json_overrides_maps_to_nested_settings(tmp_path: Path) -> None:
    path = tmp_path / "cli-config.json"
    path.write_text(
        json.dumps({"env": {"STRIX_LLM": "my-model", "PERPLEXITY_API_KEY": "pk"}}),
        encoding="utf-8",
    )
    assert loader._read_json_overrides(path) == {
        "llm": {"model": "my-model"},
        "integrations": {"perplexity_api_key": "pk"},
    }


def test_read_json_overrides_skips_keys_already_in_environ(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STRIX_LLM", "from-env")
    path = tmp_path / "cli-config.json"
    path.write_text(json.dumps({"env": {"STRIX_LLM": "from-file"}}), encoding="utf-8")
    assert loader._read_json_overrides(path) == {}


def test_read_json_overrides_env_wins_across_field_aliases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
    path = tmp_path / "cli-config.json"
    path.write_text(json.dumps({"env": {"LLM_API_KEY": "sk-file"}}), encoding="utf-8")
    assert loader._read_json_overrides(path) == {}


def test_read_json_overrides_env_wins_case_insensitively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("strix_llm", "from-env")
    path = tmp_path / "cli-config.json"
    path.write_text(json.dumps({"env": {"STRIX_LLM": "from-file"}}), encoding="utf-8")
    assert loader._read_json_overrides(path) == {}


def test_openai_key_remains_available_on_compatibility_settings_surface(tmp_path: Path) -> None:
    path = tmp_path / "cli-config.json"
    path.write_text(json.dumps({"env": {"OPENAI_API_KEY": "sk-file"}}), encoding="utf-8")
    assert loader._read_json_overrides(path) == {"llm": {"api_key": "sk-file"}}


def test_tool_output_max_bytes_rejects_sub_notice_values() -> None:
    with pytest.raises(ValidationError):
        ContextSettings(STRIX_TOOL_OUTPUT_MAX_BYTES=64)


def test_tool_output_max_bytes_accepts_floor() -> None:
    assert ContextSettings(STRIX_TOOL_OUTPUT_MAX_BYTES=1024).tool_output_max_bytes == 1024


def test_aliases_for_simple_alias() -> None:
    finfo = FieldInfo(alias="SIMPLE_ALIAS")
    assert loader._aliases_for(finfo) == ["SIMPLE_ALIAS"]


def test_aliases_for_alias_choices() -> None:
    finfo: FieldInfo = Field(  # type: ignore[assignment]
        default=None,
        validation_alias=AliasChoices("FIRST", "SECOND"),
    )
    assert loader._aliases_for(finfo) == ["FIRST", "SECOND"]


def test_aliases_for_string_validation_alias() -> None:
    finfo: FieldInfo = Field(default=None, validation_alias="STR_ALIAS")  # type: ignore[assignment]
    assert loader._aliases_for(finfo) == ["STR_ALIAS"]


def test_aliases_for_no_alias() -> None:
    assert loader._aliases_for(FieldInfo()) == []


def test_apply_override_and_load_settings_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "cli-config.json"
    path.write_text(
        json.dumps({"env": {"STRIX_LLM": "round-trip-model", "PERPLEXITY_API_KEY": "pk"}}),
        encoding="utf-8",
    )

    loader.apply_config_override(path)
    settings = loader.load_settings()

    assert settings.llm.model == "round-trip-model"
    assert settings.integrations.perplexity_api_key == "pk"
    assert loader.load_settings() is settings


def test_apply_config_override_invalidates_cache(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    first.write_text(json.dumps({"env": {"STRIX_LLM": "first-model"}}), encoding="utf-8")
    second = tmp_path / "second.json"
    second.write_text(json.dumps({"env": {"STRIX_LLM": "second-model"}}), encoding="utf-8")

    loader.apply_config_override(first)
    assert loader.load_settings().llm.model == "first-model"

    loader.apply_config_override(second)
    assert loader.load_settings().llm.model == "second-model"


def test_load_settings_does_not_export_json_api_keys(tmp_path: Path) -> None:
    path = tmp_path / "cli-config.json"
    path.write_text(
        json.dumps(
            {
                "env": {
                    "OPENAI_API_KEY": "sk-openai-file",
                    "ANTHROPIC_API_KEY": "sk-anthropic-file",
                }
            }
        ),
        encoding="utf-8",
    )
    loader.apply_config_override(path)

    loader.load_settings()

    assert "OPENAI_API_KEY" not in os.environ
    assert "ANTHROPIC_API_KEY" not in os.environ


def test_resolve_env_value_uses_alias_order_and_ignores_empty_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "cli-config.json"
    path.write_text(
        json.dumps({"env": {"FIRST_ALIAS": "first-file", "SECOND_ALIAS": "second-file"}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("first_alias", "")
    loader.apply_config_override(path)

    assert loader.resolve_env_value("SECOND_ALIAS", "FIRST_ALIAS") == "second-file"


def test_update_config_env_merges_deletes_and_preserves_top_level_fields(tmp_path: Path) -> None:
    path = tmp_path / "cli-config.json"
    path.write_text(
        json.dumps(
            {
                "env": {"KEEP": "keep", "replace_me": "old", "DELETE_ME": "delete"},
                "custom_providers": [{"id": "custom-one"}],
                "metadata": {"owner": "test"},
            }
        ),
        encoding="utf-8",
    )
    loader.apply_config_override(path)

    loader.update_config_env({"REPLACE_ME": "new", "ADDED": "added", "delete_me": None})

    assert json.loads(path.read_text(encoding="utf-8")) == {
        "env": {"KEEP": "keep", "REPLACE_ME": "new", "ADDED": "added"},
        "custom_providers": [{"id": "custom-one"}],
        "metadata": {"owner": "test"},
    }


@pytest.mark.parametrize("preexisting", [False, True])
def test_update_config_env_sets_secure_mode(tmp_path: Path, preexisting: bool) -> None:
    path = tmp_path / "cli-config.json"
    if preexisting:
        path.write_text(json.dumps({"env": {}}), encoding="utf-8")
        path.chmod(0o644)
    loader.apply_config_override(path)

    loader.update_config_env({"SECRET": "value"})

    assert path.stat().st_mode & 0o777 == 0o600


def test_update_config_env_invalidates_settings_cache(tmp_path: Path) -> None:
    path = tmp_path / "cli-config.json"
    path.write_text(json.dumps({"env": {"STRIX_LLM": "before"}}), encoding="utf-8")
    loader.apply_config_override(path)
    assert loader.load_settings().llm.model == "before"

    loader.update_config_env({"STRIX_LLM": "after"})

    assert loader.load_settings().llm.model == "after"


def test_custom_provider_mutation_preserves_env(tmp_path: Path) -> None:
    path = tmp_path / "cli-config.json"
    path.write_text(json.dumps({"env": {"STRIX_LLM": "openai/test"}}), encoding="utf-8")
    loader.apply_config_override(path)

    loader.mutate_custom_provider_records(
        lambda records: records.append({"id": "custom-one", "name": "One"})
    )

    assert loader.read_config_env() == {"STRIX_LLM": "openai/test"}
    assert loader.read_custom_provider_records() == [{"id": "custom-one", "name": "One"}]


def test_persist_current_writes_env_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "persisted-model")
    target = tmp_path / "sub" / "cli-config.json"
    loader.apply_config_override(target)

    loader.persist_current()

    assert target.exists()
    assert json.loads(target.read_text(encoding="utf-8")) == {
        "env": {"STRIX_LLM": "persisted-model"}
    }


def test_persist_current_sets_0600_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "persisted-model")
    target = tmp_path / "cli-config.json"
    loader.apply_config_override(target)

    loader.persist_current()

    assert target.stat().st_mode & 0o777 == 0o600


def test_persist_current_preserves_tui_values_and_unrelated_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "cli-config.json"
    target.write_text(
        json.dumps(
            {
                "env": {
                    "STRIX_LLM": "file-only-model",
                    "ANTHROPIC_API_KEY": "file-only-secret",
                },
                "custom_providers": [{"id": "custom-one"}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("STRIX_TELEMETRY", "false")
    loader.apply_config_override(target)

    loader.persist_current()

    assert json.loads(target.read_text(encoding="utf-8")) == {
        "env": {
            "STRIX_LLM": "file-only-model",
            "ANTHROPIC_API_KEY": "file-only-secret",
            "STRIX_TELEMETRY": "false",
        },
        "custom_providers": [{"id": "custom-one"}],
    }
