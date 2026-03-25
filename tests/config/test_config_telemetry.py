import json

from strix.config.config import Config, resolve_llm_config


def test_traceloop_vars_are_tracked() -> None:
    tracked = Config.tracked_vars()

    assert "STRIX_OTEL_TELEMETRY" in tracked
    assert "STRIX_POSTHOG_TELEMETRY" in tracked
    assert "TRACELOOP_BASE_URL" in tracked
    assert "TRACELOOP_API_KEY" in tracked
    assert "TRACELOOP_HEADERS" in tracked


def test_apply_saved_uses_legacy_env_style_config(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "cli-config.json"
    config_path.write_text(
        json.dumps(
            {
                "env": {
                    "TRACELOOP_BASE_URL": "https://otel.example.com",
                    "TRACELOOP_API_KEY": "api-key",
                    "TRACELOOP_HEADERS": "x-test=value",
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(Config, "_config_file_override", config_path)
    monkeypatch.setattr(Config, "_cached_config", None)

    applied = Config.apply_saved()

    assert applied["TRACELOOP_BASE_URL"] == "https://otel.example.com"
    assert applied["TRACELOOP_API_KEY"] == "api-key"
    assert applied["TRACELOOP_HEADERS"] == "x-test=value"
    assert Config.get_str("traceloop_base_url") == "https://otel.example.com"


def test_config_values_ignore_process_environment(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "telemetry": {
                    "traceloop_base_url": "https://file.example.com",
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(Config, "_config_file_override", config_path)
    monkeypatch.setattr(Config, "_cached_config", None)
    monkeypatch.setenv("TRACELOOP_BASE_URL", "https://env.example.com")

    Config.reload()

    assert Config.get_str("traceloop_base_url") == "https://file.example.com"


def test_resolve_llm_config_reads_openai_compatible_provider(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "llm": {
                    "model": "astron-code-latest",
                    "api_key": "test-key",
                    "api_base": "https://maas-coding-api.cn-huabei-1.xf-yun.com/v2",
                    "openai_compatible_provider": "AstronCodingPlan",
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(Config, "_config_file_override", config_path)
    monkeypatch.setattr(Config, "_cached_config", None)

    model, api_key, api_base, provider = resolve_llm_config()

    assert model == "astron-code-latest"
    assert api_key == "test-key"
    assert api_base == "https://maas-coding-api.cn-huabei-1.xf-yun.com/v2"
    assert provider == "AstronCodingPlan"
