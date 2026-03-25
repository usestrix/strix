from strix.telemetry.flags import is_otel_enabled, is_posthog_enabled


def test_flags_fallback_to_strix_telemetry(write_config) -> None:
    write_config({"telemetry": {"enabled": False}})

    assert is_otel_enabled() is False
    assert is_posthog_enabled() is False


def test_otel_flag_overrides_global_telemetry(write_config) -> None:
    write_config({"telemetry": {"enabled": False, "otel_enabled": True}})

    assert is_otel_enabled() is True
    assert is_posthog_enabled() is False


def test_posthog_flag_overrides_global_telemetry(write_config) -> None:
    write_config({"telemetry": {"enabled": False, "posthog_enabled": True}})

    assert is_otel_enabled() is False
    assert is_posthog_enabled() is True
