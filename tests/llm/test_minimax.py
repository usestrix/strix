"""Tests for MiniMax model integration."""

import os

import pytest

from strix.config.config import Config, _is_minimax_model, resolve_llm_config
from strix.llm.config import LLMConfig
from strix.llm.utils import STRIX_MODEL_MAP, resolve_strix_model


class TestMiniMaxModelMap:
    """Tests for MiniMax entries in STRIX_MODEL_MAP."""

    def test_minimax_m3_in_model_map(self):
        assert "minimax-m3" in STRIX_MODEL_MAP
        assert STRIX_MODEL_MAP["minimax-m3"] == "openai/MiniMax-M3"

    def test_minimax_m27_in_model_map(self):
        assert "minimax-m2.7" in STRIX_MODEL_MAP
        assert STRIX_MODEL_MAP["minimax-m2.7"] == "openai/MiniMax-M2.7"

    def test_minimax_m27_highspeed_in_model_map(self):
        assert "minimax-m2.7-highspeed" in STRIX_MODEL_MAP
        assert STRIX_MODEL_MAP["minimax-m2.7-highspeed"] == "openai/MiniMax-M2.7-highspeed"

    def test_minimax_m3_is_first(self):
        """MiniMax-M3 is the default and should be listed before older models."""
        minimax_keys = [k for k in STRIX_MODEL_MAP if k.startswith("minimax-")]
        assert minimax_keys[0] == "minimax-m3"


class TestMiniMaxModelResolution:
    """Tests for resolving strix/ MiniMax models."""

    def test_resolve_strix_minimax_m3(self):
        api_model, canonical = resolve_strix_model("strix/minimax-m3")
        assert api_model == "openai/minimax-m3"
        assert canonical == "openai/MiniMax-M3"

    def test_resolve_strix_minimax_m27(self):
        api_model, canonical = resolve_strix_model("strix/minimax-m2.7")
        assert api_model == "openai/minimax-m2.7"
        assert canonical == "openai/MiniMax-M2.7"

    def test_resolve_strix_minimax_m27_highspeed(self):
        api_model, canonical = resolve_strix_model("strix/minimax-m2.7-highspeed")
        assert api_model == "openai/minimax-m2.7-highspeed"
        assert canonical == "openai/MiniMax-M2.7-highspeed"

    def test_resolve_direct_minimax_model_passthrough(self):
        api_model, canonical = resolve_strix_model("openai/MiniMax-M3")
        assert api_model == "openai/MiniMax-M3"
        assert canonical == "openai/MiniMax-M3"


class TestIsMiniMaxModel:
    """Tests for MiniMax model detection."""

    def test_detects_minimax_m3_openai_prefix(self):
        assert _is_minimax_model("openai/MiniMax-M3")

    def test_detects_minimax_openai_prefix(self):
        assert _is_minimax_model("openai/MiniMax-M2.7")

    def test_detects_minimax_case_insensitive(self):
        assert _is_minimax_model("openai/minimax-m3")

    def test_detects_minimax_strix_prefix(self):
        assert _is_minimax_model("strix/minimax-m3")

    def test_non_minimax_model(self):
        assert not _is_minimax_model("openai/gpt-5.4")

    def test_non_minimax_anthropic(self):
        assert not _is_minimax_model("anthropic/claude-sonnet-4-6")


class TestMiniMaxConfigResolution:
    """Tests for MiniMax auto-detection in resolve_llm_config."""

    def test_auto_detect_minimax_api_key(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("STRIX_LLM", "openai/MiniMax-M3")
        monkeypatch.setenv("MINIMAX_API_KEY", "test-minimax-key")
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        monkeypatch.delenv("LLM_API_BASE", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
        monkeypatch.delenv("OLLAMA_API_BASE", raising=False)

        model, api_key, api_base = resolve_llm_config()

        assert model == "openai/MiniMax-M3"
        assert api_key == "test-minimax-key"
        assert api_base == "https://api.minimax.io/v1"

    def test_llm_api_key_takes_precedence_over_minimax_key(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("STRIX_LLM", "openai/MiniMax-M3")
        monkeypatch.setenv("LLM_API_KEY", "llm-key-takes-precedence")
        monkeypatch.setenv("MINIMAX_API_KEY", "minimax-key")
        monkeypatch.delenv("LLM_API_BASE", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
        monkeypatch.delenv("OLLAMA_API_BASE", raising=False)

        model, api_key, api_base = resolve_llm_config()

        assert api_key == "llm-key-takes-precedence"
        assert api_base == "https://api.minimax.io/v1"

    def test_custom_api_base_takes_precedence(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("STRIX_LLM", "openai/MiniMax-M3")
        monkeypatch.setenv("MINIMAX_API_KEY", "test-key")
        monkeypatch.setenv("LLM_API_BASE", "https://custom-proxy.com/v1")
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
        monkeypatch.delenv("OLLAMA_API_BASE", raising=False)

        model, api_key, api_base = resolve_llm_config()

        assert api_base == "https://custom-proxy.com/v1"

    def test_no_minimax_key_no_auto_detect(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("STRIX_LLM", "openai/gpt-5.4")
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        monkeypatch.delenv("MINIMAX_API_KEY", raising=False)
        monkeypatch.delenv("LLM_API_BASE", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
        monkeypatch.delenv("OLLAMA_API_BASE", raising=False)

        model, api_key, api_base = resolve_llm_config()

        assert model == "openai/gpt-5.4"
        assert api_key is None
        assert api_base is None

    def test_minimax_auto_base_url_when_no_base_set(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("STRIX_LLM", "openai/MiniMax-M2.7-highspeed")
        monkeypatch.setenv("LLM_API_KEY", "some-key")
        monkeypatch.delenv("LLM_API_BASE", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
        monkeypatch.delenv("OLLAMA_API_BASE", raising=False)

        model, api_key, api_base = resolve_llm_config()

        assert api_base == "https://api.minimax.io/v1"


class TestMiniMaxLLMConfig:
    """Tests for LLMConfig with MiniMax models."""

    def test_llm_config_minimax_direct(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("STRIX_LLM", "openai/MiniMax-M3")
        monkeypatch.setenv("LLM_API_KEY", "test-key")
        monkeypatch.delenv("LLM_API_BASE", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
        monkeypatch.delenv("OLLAMA_API_BASE", raising=False)

        config = LLMConfig()

        assert config.model_name == "openai/MiniMax-M3"
        assert config.litellm_model == "openai/MiniMax-M3"
        assert config.api_key == "test-key"
        assert config.api_base == "https://api.minimax.io/v1"

    def test_llm_config_minimax_strix_shortcut(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("STRIX_LLM", "strix/minimax-m3")
        monkeypatch.setenv("MINIMAX_API_KEY", "minimax-key")
        monkeypatch.delenv("LLM_API_KEY", raising=False)
        monkeypatch.delenv("LLM_API_BASE", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
        monkeypatch.delenv("OLLAMA_API_BASE", raising=False)

        config = LLMConfig()

        assert config.model_name == "strix/minimax-m3"
        assert config.litellm_model == "openai/minimax-m3"
        assert config.canonical_model == "openai/MiniMax-M3"
        assert config.api_key == "minimax-key"
