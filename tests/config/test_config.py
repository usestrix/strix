"""Unit tests for strix.config.config module."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from strix.config.config import (
    STRIX_API_BASE,
    Config,
    apply_saved_config,
    resolve_llm_config,
    save_current_config,
)


@pytest.fixture
def tmp_config_dir(tmp_path: Path) -> Path:
    """Create a temporary config directory and override Config to use it."""
    config_dir = tmp_path / ".strix"
    config_dir.mkdir()
    return config_dir


@pytest.fixture
def config_with_tmp_dir(tmp_config_dir: Path) -> type[Config]:
    """Patch Config to use a temporary config directory.

    Overrides both config_file (via _config_file_override) and config_dir
    (via monkeypatch-style patching) so that save() writes to tmp_path
    instead of the real ~/.strix directory.
    """
    config_file = tmp_config_dir / "cli-config.json"
    Config._config_file_override = config_file
    original_config_dir = Config.config_dir
    Config.config_dir = classmethod(lambda _cls: tmp_config_dir)  # type: ignore[assignment]
    yield Config
    Config._config_file_override = None
    Config.config_dir = original_config_dir  # type: ignore[method-assign]


@pytest.fixture
def clean_env() -> None:
    """Remove all tracked env vars before test, restore after."""
    tracked = Config.tracked_vars()
    saved = {k: os.environ[k] for k in tracked if k in os.environ}
    for k in tracked:
        os.environ.pop(k, None)
    yield
    for k in tracked:
        os.environ.pop(k, None)
    os.environ.update(saved)


class TestTrackedNames:
    """Tests for Config._tracked_names and tracked_vars."""

    def test_tracked_names_returns_list_of_strings(self) -> None:
        names = Config._tracked_names()
        assert isinstance(names, list)
        assert all(isinstance(n, str) for n in names)

    def test_tracked_names_excludes_private(self) -> None:
        names = Config._tracked_names()
        assert all(not n.startswith("_") for n in names)

    def test_tracked_vars_are_uppercase(self) -> None:
        tracked = Config.tracked_vars()
        assert all(v == v.upper() for v in tracked)

    def test_tracked_vars_includes_known_vars(self) -> None:
        tracked = Config.tracked_vars()
        assert "STRIX_LLM" in tracked
        assert "LLM_API_KEY" in tracked
        assert "STRIX_TELEMETRY" in tracked
        assert "STRIX_IMAGE" in tracked

    def test_tracked_names_count_matches_tracked_vars(self) -> None:
        assert len(Config._tracked_names()) == len(Config.tracked_vars())


@pytest.mark.usefixtures("clean_env")
class TestLlmEnvVars:
    """Tests for Config._llm_env_vars and _llm_env_changed."""

    def test_llm_env_vars_returns_set(self) -> None:
        result = Config._llm_env_vars()
        assert isinstance(result, set)

    def test_llm_env_vars_are_uppercase(self) -> None:
        for var in Config._llm_env_vars():
            assert var == var.upper()

    def test_llm_env_vars_includes_core_llm_settings(self) -> None:
        llm_vars = Config._llm_env_vars()
        assert "STRIX_LLM" in llm_vars
        assert "LLM_API_KEY" in llm_vars
        assert "LLM_API_BASE" in llm_vars

    def test_llm_env_changed_no_env_set(self) -> None:
        saved = {"STRIX_LLM": "openai/gpt-5"}
        assert Config._llm_env_changed(saved) is False

    def test_llm_env_changed_same_value(self) -> None:
        os.environ["STRIX_LLM"] = "openai/gpt-5"
        saved = {"STRIX_LLM": "openai/gpt-5"}
        assert Config._llm_env_changed(saved) is False

    def test_llm_env_changed_different_value(self) -> None:
        os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4-6"
        saved = {"STRIX_LLM": "openai/gpt-5"}
        assert Config._llm_env_changed(saved) is True

    def test_llm_env_changed_new_var_not_in_saved(self) -> None:
        os.environ["STRIX_LLM"] = "openai/gpt-5"
        saved: dict[str, Any] = {}
        assert Config._llm_env_changed(saved) is True

    def test_llm_env_changed_empty_saved(self) -> None:
        assert Config._llm_env_changed({}) is False


@pytest.mark.usefixtures("clean_env")
class TestGet:
    """Tests for Config.get."""

    def test_get_returns_env_var_when_set(self) -> None:
        os.environ["STRIX_LLM"] = "test-model"
        assert Config.get("strix_llm") == "test-model"

    def test_get_returns_default_when_env_not_set(self) -> None:
        assert Config.get("strix_reasoning_effort") == "high"

    def test_get_returns_none_for_unset_nullable(self) -> None:
        assert Config.get("strix_llm") is None

    def test_get_env_overrides_default(self) -> None:
        os.environ["STRIX_REASONING_EFFORT"] = "low"
        assert Config.get("strix_reasoning_effort") == "low"

    def test_get_unknown_name_returns_none(self) -> None:
        assert Config.get("nonexistent_config_key") is None


class TestConfigDir:
    """Tests for Config.config_dir and config_file."""

    def test_config_dir_is_under_home(self) -> None:
        config_dir = Config.config_dir()
        assert config_dir == Path.home() / ".strix"

    def test_config_file_default(self) -> None:
        saved = Config._config_file_override
        Config._config_file_override = None
        try:
            config_file = Config.config_file()
            assert config_file == Path.home() / ".strix" / "cli-config.json"
        finally:
            Config._config_file_override = saved

    def test_config_file_override(self, tmp_path: Path) -> None:
        override = tmp_path / "custom-config.json"
        Config._config_file_override = override
        try:
            assert Config.config_file() == override
        finally:
            Config._config_file_override = None


class TestLoad:
    """Tests for Config.load."""

    def test_load_returns_empty_when_no_file(
        self,
        config_with_tmp_dir: type[Config],
    ) -> None:
        result = config_with_tmp_dir.load()
        assert result == {}

    def test_load_returns_saved_data(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        config_data = {"env": {"STRIX_LLM": "openai/gpt-5"}}
        config_file = tmp_config_dir / "cli-config.json"
        config_file.write_text(json.dumps(config_data), encoding="utf-8")
        result = config_with_tmp_dir.load()
        assert result == config_data

    def test_load_returns_empty_on_corrupted_json(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        config_file = tmp_config_dir / "cli-config.json"
        config_file.write_text("{invalid json", encoding="utf-8")
        result = config_with_tmp_dir.load()
        assert result == {}

    def test_load_returns_empty_on_empty_file(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        config_file = tmp_config_dir / "cli-config.json"
        config_file.write_text("", encoding="utf-8")
        result = config_with_tmp_dir.load()
        assert result == {}


class TestSave:
    """Tests for Config.save."""

    def test_save_creates_config_file(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        config_data = {"env": {"STRIX_LLM": "openai/gpt-5"}}
        result = config_with_tmp_dir.save(config_data)
        assert result is True
        config_file = tmp_config_dir / "cli-config.json"
        assert config_file.exists()
        saved = json.loads(config_file.read_text(encoding="utf-8"))
        assert saved == config_data

    def test_save_creates_directory_if_missing(self, tmp_path: Path) -> None:
        new_dir = tmp_path / "new_strix_dir"
        config_file = new_dir / "cli-config.json"
        with patch.object(Config, "config_dir", return_value=new_dir):
            Config._config_file_override = config_file
            try:
                result = Config.save({"env": {}})
            finally:
                Config._config_file_override = None
        assert result is True
        assert new_dir.exists()

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod not reliable on Windows")
    def test_save_sets_file_permissions(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        config_with_tmp_dir.save({"env": {}})
        config_file = tmp_config_dir / "cli-config.json"
        mode = config_file.stat().st_mode
        assert mode & 0o777 == 0o600

    def test_save_overwrites_existing(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        config_with_tmp_dir.save({"env": {"OLD": "data"}})
        config_with_tmp_dir.save({"env": {"NEW": "data"}})
        config_file = tmp_config_dir / "cli-config.json"
        saved = json.loads(config_file.read_text(encoding="utf-8"))
        assert saved == {"env": {"NEW": "data"}}
        assert "OLD" not in saved.get("env", {})


@pytest.mark.usefixtures("clean_env")
class TestApplySaved:
    """Tests for Config.apply_saved."""

    def test_apply_saved_sets_env_vars(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        config_file = tmp_config_dir / "cli-config.json"
        config_file.write_text(
            json.dumps({"env": {"STRIX_LLM": "openai/gpt-5"}}),
            encoding="utf-8",
        )
        applied = config_with_tmp_dir.apply_saved()
        assert "STRIX_LLM" in applied
        assert os.environ["STRIX_LLM"] == "openai/gpt-5"

    def test_apply_saved_does_not_override_existing_env(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        os.environ["STRIX_LLM"] = "my-local-model"
        config_file = tmp_config_dir / "cli-config.json"
        config_file.write_text(
            json.dumps({"env": {"STRIX_LLM": "saved-model"}}),
            encoding="utf-8",
        )
        applied = config_with_tmp_dir.apply_saved()
        assert "STRIX_LLM" not in applied
        assert os.environ["STRIX_LLM"] == "my-local-model"

    def test_apply_saved_force_overrides_non_llm_env(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        """Force applies saved non-LLM vars even when already set in env."""
        os.environ["STRIX_TELEMETRY"] = "0"
        config_file = tmp_config_dir / "cli-config.json"
        config_file.write_text(
            json.dumps({"env": {"STRIX_TELEMETRY": "1"}}),
            encoding="utf-8",
        )
        applied = config_with_tmp_dir.apply_saved(force=True)
        assert applied["STRIX_TELEMETRY"] == "1"
        assert os.environ["STRIX_TELEMETRY"] == "1"

    def test_apply_saved_llm_change_clears_saved_llm_vars(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        """When current LLM env differs from saved, saved LLM vars are dropped."""
        os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4-6"
        config_file = tmp_config_dir / "cli-config.json"
        config_file.write_text(
            json.dumps({"env": {"STRIX_LLM": "openai/gpt-5"}}),
            encoding="utf-8",
        )
        applied = config_with_tmp_dir.apply_saved(force=True)
        assert "STRIX_LLM" not in applied

    def test_apply_saved_returns_empty_when_no_config(
        self,
        config_with_tmp_dir: type[Config],
    ) -> None:
        applied = config_with_tmp_dir.apply_saved()
        assert applied == {}

    def test_apply_saved_does_not_apply_cleared_env_vars(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        """When an env var is set to empty string, it is not applied from saved."""
        config_file = tmp_config_dir / "cli-config.json"
        config_file.write_text(
            json.dumps({"env": {"STRIX_TELEMETRY": "1"}}),
            encoding="utf-8",
        )
        os.environ["STRIX_TELEMETRY"] = ""
        applied = config_with_tmp_dir.apply_saved()
        assert "STRIX_TELEMETRY" not in applied

    def test_apply_saved_handles_invalid_env_type(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        config_file = tmp_config_dir / "cli-config.json"
        config_file.write_text(
            json.dumps({"env": "not-a-dict"}),
            encoding="utf-8",
        )
        applied = config_with_tmp_dir.apply_saved()
        assert applied == {}

    def test_apply_saved_ignores_untracked_vars(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        config_file = tmp_config_dir / "cli-config.json"
        config_file.write_text(
            json.dumps({"env": {"UNTRACKED_VAR": "value"}}),
            encoding="utf-8",
        )
        applied = config_with_tmp_dir.apply_saved()
        assert "UNTRACKED_VAR" not in applied
        assert "UNTRACKED_VAR" not in os.environ


@pytest.mark.usefixtures("clean_env")
class TestCaptureAndSaveCurrent:
    """Tests for Config.capture_current and save_current."""

    def test_capture_current_captures_set_vars(self) -> None:
        os.environ["STRIX_LLM"] = "test-model"
        os.environ["LLM_API_KEY"] = "test-key"
        captured = Config.capture_current()
        assert captured["env"]["STRIX_LLM"] == "test-model"
        assert captured["env"]["LLM_API_KEY"] == "test-key"

    def test_capture_current_skips_unset_vars(self) -> None:
        captured = Config.capture_current()
        assert "STRIX_LLM" not in captured.get("env", {})

    def test_capture_current_skips_empty_vars(self) -> None:
        os.environ["STRIX_LLM"] = ""
        captured = Config.capture_current()
        assert "STRIX_LLM" not in captured.get("env", {})

    def test_save_current_persists_to_file(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        os.environ["STRIX_LLM"] = "openai/gpt-5"
        result = config_with_tmp_dir.save_current()
        assert result is True
        config_file = tmp_config_dir / "cli-config.json"
        saved = json.loads(config_file.read_text(encoding="utf-8"))
        assert saved["env"]["STRIX_LLM"] == "openai/gpt-5"

    def test_save_current_merges_with_existing(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        config_file = tmp_config_dir / "cli-config.json"
        config_file.write_text(
            json.dumps({"env": {"LLM_API_KEY": "existing-key"}}),
            encoding="utf-8",
        )
        os.environ["STRIX_LLM"] = "new-model"
        config_with_tmp_dir.save_current()
        saved = json.loads(config_file.read_text(encoding="utf-8"))
        assert saved["env"]["LLM_API_KEY"] == "existing-key"
        assert saved["env"]["STRIX_LLM"] == "new-model"

    def test_save_current_removes_empty_vars(
        self,
        config_with_tmp_dir: type[Config],
        tmp_config_dir: Path,
    ) -> None:
        config_file = tmp_config_dir / "cli-config.json"
        config_file.write_text(
            json.dumps({"env": {"STRIX_LLM": "old-model"}}),
            encoding="utf-8",
        )
        os.environ["STRIX_LLM"] = ""
        config_with_tmp_dir.save_current()
        saved = json.loads(config_file.read_text(encoding="utf-8"))
        assert "STRIX_LLM" not in saved["env"]


@pytest.mark.usefixtures("clean_env")
class TestResolveLlmConfig:
    """Tests for resolve_llm_config function."""

    def test_returns_none_tuple_when_no_model(self) -> None:
        model, api_key, api_base = resolve_llm_config()
        assert model is None
        assert api_key is None
        assert api_base is None

    def test_strix_model_uses_strix_api_base(self) -> None:
        os.environ["STRIX_LLM"] = "strix/some-model"
        os.environ["LLM_API_KEY"] = "test-key"
        model, api_key, api_base = resolve_llm_config()
        assert model == "strix/some-model"
        assert api_key == "test-key"
        assert api_base == STRIX_API_BASE

    def test_non_strix_model_uses_llm_api_base(self) -> None:
        os.environ["STRIX_LLM"] = "openai/gpt-5"
        os.environ["LLM_API_BASE"] = "https://custom.api.com"
        model, api_key, api_base = resolve_llm_config()
        assert model == "openai/gpt-5"
        assert api_base == "https://custom.api.com"

    def test_non_strix_model_falls_back_to_openai_base(self) -> None:
        os.environ["STRIX_LLM"] = "openai/gpt-5"
        os.environ["OPENAI_API_BASE"] = "https://openai.proxy.com"
        _, _, api_base = resolve_llm_config()
        assert api_base == "https://openai.proxy.com"

    def test_non_strix_model_falls_back_to_litellm_base(self) -> None:
        os.environ["STRIX_LLM"] = "openai/gpt-5"
        os.environ["LITELLM_BASE_URL"] = "https://litellm.proxy.com"
        _, _, api_base = resolve_llm_config()
        assert api_base == "https://litellm.proxy.com"

    def test_non_strix_model_falls_back_to_ollama_base(self) -> None:
        os.environ["STRIX_LLM"] = "ollama/llama3"
        os.environ["OLLAMA_API_BASE"] = "http://localhost:11434"
        _, _, api_base = resolve_llm_config()
        assert api_base == "http://localhost:11434"

    def test_non_strix_model_no_base_returns_none(self) -> None:
        os.environ["STRIX_LLM"] = "openai/gpt-5"
        _, _, api_base = resolve_llm_config()
        assert api_base is None

    def test_api_base_priority_order(self) -> None:
        os.environ["STRIX_LLM"] = "openai/gpt-5"
        os.environ["LLM_API_BASE"] = "https://first.com"
        os.environ["OPENAI_API_BASE"] = "https://second.com"
        os.environ["LITELLM_BASE_URL"] = "https://third.com"
        os.environ["OLLAMA_API_BASE"] = "https://fourth.com"
        _, _, api_base = resolve_llm_config()
        assert api_base == "https://first.com"


@pytest.mark.usefixtures("config_with_tmp_dir", "clean_env")
class TestModuleLevelFunctions:
    """Tests for module-level convenience functions."""

    def test_apply_saved_config_delegates(self) -> None:
        result = apply_saved_config()
        assert isinstance(result, dict)

    def test_save_current_config_delegates(self) -> None:
        result = save_current_config()
        assert isinstance(result, bool)
