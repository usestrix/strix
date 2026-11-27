"""``STRIX_SANDBOX_LOG_MAX_SIZE`` / ``_MAX_FILE`` bound the sandbox json-file log."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from strix.runtime import docker_client


if TYPE_CHECKING:
    from docker.types import LogConfig


_SIZE_ENV = "STRIX_SANDBOX_LOG_MAX_SIZE"
_FILE_ENV = "STRIX_SANDBOX_LOG_MAX_FILE"


def _log_config(monkeypatch: pytest.MonkeyPatch, **env: str | None) -> LogConfig | None:
    for name, value in env.items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    kwargs: dict[str, Any] = {}
    docker_client._apply_log_limits(kwargs)
    return kwargs.get("log_config")


def test_unset_uses_the_default_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    log_config = _log_config(monkeypatch, **{_SIZE_ENV: None, _FILE_ENV: None})
    assert log_config is not None
    assert log_config.config == {"max-size": "50m", "max-file": "3"}


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_max_size_falls_back_to_the_default(
    monkeypatch: pytest.MonkeyPatch, blank: str
) -> None:
    # Docker rejects ``max-size: ""`` when it starts the container, so a blank
    # value must behave like an unset one, the same way max-file already does.
    log_config = _log_config(monkeypatch, **{_SIZE_ENV: blank, _FILE_ENV: blank})
    assert log_config is not None
    assert log_config.config == {"max-size": "50m", "max-file": "3"}


@pytest.mark.parametrize("off", ["0", "off", "OFF", "none", "unlimited"])
def test_opt_out_values_leave_docker_default(monkeypatch: pytest.MonkeyPatch, off: str) -> None:
    assert _log_config(monkeypatch, **{_SIZE_ENV: off}) is None


def test_explicit_values_are_passed_through(monkeypatch: pytest.MonkeyPatch) -> None:
    log_config = _log_config(monkeypatch, **{_SIZE_ENV: " 10m ", _FILE_ENV: "5"})
    assert log_config is not None
    assert log_config.config == {"max-size": "10m", "max-file": "5"}
