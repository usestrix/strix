import json

from strix.config.config import Config


def test_traceloop_vars_are_tracked() -> None:
    tracked = Config.tracked_vars()

    assert "STRIX_OTEL_TELEMETRY" in tracked
    assert "STRIX_POSTHOG_TELEMETRY" in tracked
    assert "TRACELOOP_BASE_URL" in tracked
    assert "TRACELOOP_API_KEY" in tracked
    assert "TRACELOOP_HEADERS" in tracked


def test_apply_saved_uses_saved_traceloop_vars(monkeypatch, tmp_path) -> None:
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
    monkeypatch.delenv("TRACELOOP_BASE_URL", raising=False)
    monkeypatch.delenv("TRACELOOP_API_KEY", raising=False)
    monkeypatch.delenv("TRACELOOP_HEADERS", raising=False)

    applied = Config.apply_saved()

    assert applied["TRACELOOP_BASE_URL"] == "https://otel.example.com"
    assert applied["TRACELOOP_API_KEY"] == "api-key"
    assert applied["TRACELOOP_HEADERS"] == "x-test=value"


def test_apply_saved_respects_existing_env_traceloop_vars(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "cli-config.json"
    config_path.write_text(
        json.dumps({"env": {"TRACELOOP_BASE_URL": "https://otel.example.com"}}),
        encoding="utf-8",
    )

    monkeypatch.setattr(Config, "_config_file_override", config_path)
    monkeypatch.setenv("TRACELOOP_BASE_URL", "https://env.example.com")

    applied = Config.apply_saved(force=False)

    assert "TRACELOOP_BASE_URL" not in applied
