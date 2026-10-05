"""Per-scan logging setup."""

from __future__ import annotations

import contextlib
import logging
import os
import sys
import warnings
from contextvars import ContextVar
from pathlib import Path  # noqa: TC003  used at runtime by ``setup_scan_logging``
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Callable


_SCAN_ID: ContextVar[str | None] = ContextVar("strix_scan_id", default=None)
_AGENT_ID: ContextVar[str | None] = ContextVar("strix_agent_id", default=None)


def set_scan_id(scan_id: str) -> None:
    """Set the scan_id seen on every log record from this point in the task tree."""
    _SCAN_ID.set(scan_id)


def set_agent_id(agent_id: str | None) -> None:
    """Set or clear the agent_id seen on every log record from this point.

    ``None`` clears (renders as ``-`` in the log line). Mutations are
    isolated to the current asyncio task and tasks created from it after
    the call.
    """
    _AGENT_ID.set(agent_id)


class _StrixContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.scan_id = _SCAN_ID.get() or "-"
        record.agent_id = _AGENT_ID.get() or "-"
        return True


_FORMAT = "%(asctime)s.%(msecs)03d %(levelname)-7s %(scan_id)s %(agent_id)s %(name)s: %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


# Third-party loggers that get noisy at DEBUG. Capped so the file isn't
# drowned in their internals when STRIX_DEBUG=1.
_NOISY_LIBS: tuple[str, ...] = (
    "httpx",
    "httpcore",
    "urllib3",
    "litellm",
    "openai",
    "anthropic",
)


_HANDLER_TAG = "_strix_scan_handler"
_STREAM_TAG = "_strix_stream_handler"


# ``openai.agents`` is the openai-agents SDK's canonical logger root.
_TRACKED_ROOTS: tuple[str, ...] = ("strix", "openai.agents")

_STDOUT_QUIET_ROOTS: frozenset[str] = frozenset({"openai.agents"})


class _StdoutQuietFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.WARNING:
            return True
        return not any(
            record.name == root or record.name.startswith(root + ".")
            for root in _STDOUT_QUIET_ROOTS
        )


def configure_dependency_logging() -> None:
    """Quiet dependency logging/warnings that obscure Strix scan logs."""
    litellm = sys.modules.get("litellm")
    if litellm is not None:
        with contextlib.suppress(Exception):
            litellm._logging._disable_debugging()

    logging.getLogger("asyncio").setLevel(logging.CRITICAL)
    logging.getLogger("asyncio").propagate = False
    warnings.filterwarnings("ignore", category=RuntimeWarning, module="asyncio")
    _route_unraisable_to_log()


def _route_unraisable_to_log() -> None:
    def hook(u: sys.UnraisableHookArgs) -> None:
        with contextlib.suppress(BaseException):
            logger = logging.getLogger("strix.telemetry")
            if logger.hasHandlers():
                logger.warning(
                    u.err_msg or f"Exception ignored in {u.object!r}",
                    exc_info=(u.exc_type, u.exc_value, u.exc_traceback),  # type: ignore[arg-type]
                )

    sys.unraisablehook = hook


class _CurrentStderrHandler(logging.StreamHandler):  # type: ignore[type-arg]
    def __init__(self, level: int) -> None:
        logging.Handler.__init__(self, level)

    @property
    def stream(self) -> object:
        return sys.stderr

    @stream.setter
    def stream(self, _value: object) -> None:
        pass


def _debug_enabled(debug: bool | None) -> bool:
    if debug is not None:
        return debug
    return (os.environ.get("STRIX_DEBUG") or "").strip().lower() in {"1", "true", "yes", "on"}


def _stream_handler(debug: bool) -> logging.Handler:
    handler = _CurrentStderrHandler(logging.DEBUG if debug else logging.ERROR)
    handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))
    handler.addFilter(_StrixContextFilter())
    handler.addFilter(_StdoutQuietFilter())
    setattr(handler, _STREAM_TAG, True)
    return handler


def _has_stream_handler(tracked: logging.Logger) -> bool:
    return any(getattr(handler, _STREAM_TAG, False) for handler in tracked.handlers)


def setup_console_logging(*, debug: bool | None = None) -> None:
    configure_dependency_logging()
    for name in _TRACKED_ROOTS:
        tracked = logging.getLogger(name)
        tracked.setLevel(logging.DEBUG)
        tracked.propagate = False
        if not _has_stream_handler(tracked):
            tracked.addHandler(_stream_handler(_debug_enabled(debug)))


def setup_scan_logging(run_dir: Path, *, debug: bool | None = None) -> Callable[[], None]:
    """Attach scan-scoped handlers; return a teardown callable.

    Args:
        run_dir: Per-scan output directory. ``{run_dir}/strix.log`` is
            created if missing and opened append-mode (so re-runs of the
            same scan_id concatenate cleanly).
        debug: When ``True``, stderr handler runs at DEBUG instead of
            ERROR. ``None`` (default) reads ``STRIX_DEBUG`` env: ``1`` /
            ``true`` / ``yes`` / ``on`` enables debug.

    Returns:
        A no-arg callable that flushes/closes/removes the handlers this
        call attached. Idempotent — calling twice is a no-op the second
        time. Safe to call from a ``finally`` block.
    """
    configure_dependency_logging()

    debug = _debug_enabled(debug)

    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / "strix.log"

    file_handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))
    file_handler.addFilter(_StrixContextFilter())
    setattr(file_handler, _HANDLER_TAG, True)

    tracked_loggers = [logging.getLogger(name) for name in _TRACKED_ROOTS]
    for tracked in tracked_loggers:
        tracked.setLevel(logging.DEBUG)
        tracked.addHandler(file_handler)
        if not _has_stream_handler(tracked):
            stream_handler = _stream_handler(debug)
            setattr(stream_handler, _HANDLER_TAG, True)
            tracked.addHandler(stream_handler)
        tracked.propagate = False

    for name in _NOISY_LIBS:
        logging.getLogger(name).setLevel(logging.WARNING)

    def _teardown() -> None:
        for tracked in tracked_loggers:
            for handler in list(tracked.handlers):
                if getattr(handler, _HANDLER_TAG, False):
                    tracked.removeHandler(handler)
                    with contextlib.suppress(Exception):
                        handler.flush()
                        handler.close()

    return _teardown
