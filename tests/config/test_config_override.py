import json
import os

from strix.config.config import Config, apply_saved_config


def test_apply_config_override_clears_default_only_vars(monkeypatch, tmp_path) -> None:
    from strix.interface.main import apply_config_override

    default_cfg = tmp_path / "cli-config.json"
    default_cfg.write_text(
        json.dumps({"env": {"LLM_API_BASE": "https://default.api", "STRIX_LLM": "default-model"}}),
        encoding="utf-8",
    )
    custom_cfg = tmp_path / "custom.json"
    custom_cfg.write_text(json.dumps({"env": {"STRIX_LLM": "custom-model"}}), encoding="utf-8")

    monkeypatch.setattr(Config, "_config_file_override", None)
    monkeypatch.setattr(Config, "_applied_from_default", {})
    monkeypatch.setattr(Config, "config_dir", classmethod(lambda cls: tmp_path))
    for var_name in Config._llm_env_vars():
        monkeypatch.delenv(var_name, raising=False)

    apply_saved_config()

    assert os.environ.get("LLM_API_BASE") == "https://default.api"

    apply_config_override(str(custom_cfg))

    assert os.environ.get("STRIX_LLM") == "custom-model"
    assert "LLM_API_BASE" not in os.environ
