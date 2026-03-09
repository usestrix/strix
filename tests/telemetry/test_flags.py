from strix.telemetry.flags import is_otel_enabled, is_posthog_enabled


def test_flags_fallback_to_strix_telemetry(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")

    assert is_otel_enabled() is False
    assert is_posthog_enabled() is False


def test_otel_flag_overrides_global_telemetry(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_OTEL_TELEMETRY", "1")
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)

    assert is_otel_enabled() is True
    assert is_posthog_enabled() is False


def test_posthog_flag_overrides_global_telemetry(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_POSTHOG_TELEMETRY", "1")
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)

    assert is_otel_enabled() is False
    assert is_posthog_enabled() is True
