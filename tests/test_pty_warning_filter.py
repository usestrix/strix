import logging
from collections.abc import Iterator

import pytest

from strix.telemetry import logging as tlog


_SDK_LOGGER = "agents.sandbox.sandboxes.docker"


@pytest.fixture
def sdk_logger() -> Iterator[logging.Logger]:
    logger = logging.getLogger(_SDK_LOGGER)
    original = list(logger.filters)
    logger.filters.clear()
    tlog._silence_pty_threshold_warning.cache_clear()
    yield logger
    logger.filters[:] = original
    tlog._silence_pty_threshold_warning.cache_clear()


def _record(msg: str, *args: object) -> logging.LogRecord:
    return logging.LogRecord(_SDK_LOGGER, logging.WARNING, __file__, 0, msg, args, None)


def test_installed_filter_drops_pty_threshold_warning(sdk_logger: logging.Logger) -> None:
    tlog._silence_pty_threshold_warning()
    record = _record("PTY process count reached warning threshold: %s active sessions", 62)
    assert not sdk_logger.filter(record)


def test_installed_filter_keeps_other_warnings(sdk_logger: logging.Logger) -> None:
    tlog._silence_pty_threshold_warning()
    assert sdk_logger.filter(_record("something else went wrong"))


def test_install_is_idempotent(sdk_logger: logging.Logger) -> None:
    tlog._silence_pty_threshold_warning()
    tlog._silence_pty_threshold_warning()
    assert len(sdk_logger.filters) == 1
