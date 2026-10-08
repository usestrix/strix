from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from strix.telemetry import logging as tlog


if TYPE_CHECKING:
    from collections.abc import Iterator


def _unraisable(exc: BaseException, obj: object, err_msg: str | None = None) -> object:
    return SimpleNamespace(
        exc_type=type(exc),
        exc_value=exc,
        exc_traceback=None,
        err_msg=err_msg,
        object=obj,
    )


@pytest.fixture
def strix_records() -> Iterator[list[logging.LogRecord]]:
    records: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collect()
    root = logging.getLogger("strix")
    root.addHandler(handler)
    try:
        yield records
    finally:
        root.removeHandler(handler)


@pytest.fixture
def default_hook_calls(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    calls: list[object] = []
    monkeypatch.setattr(sys, "unraisablehook", calls.append)
    tlog.configure_dependency_logging()
    return calls


@pytest.mark.parametrize(
    "args",
    [
        _unraisable(ValueError("I/O operation on closed file."), object()),
        _unraisable(
            ValueError("I/O operation on closed file."),
            None,
            err_msg=(
                "Exception ignored while finalizing file "
                "<urllib3.response.HTTPResponse object at 0x1>"
            ),
        ),
        _unraisable(RuntimeError("boom"), object()),
        _unraisable(KeyError("x"), None, err_msg="Exception ignored in: <function f>"),
    ],
)
def test_every_unraisable_is_logged_not_printed(
    args: object,
    default_hook_calls: list[object],
    strix_records: list[logging.LogRecord],
    capsys: pytest.CaptureFixture[str],
) -> None:
    sys.unraisablehook(args)  # type: ignore[arg-type]

    assert default_hook_calls == []
    assert capsys.readouterr().err == ""
    [record] = strix_records
    assert record.levelno == logging.WARNING
    assert record.name == "strix.telemetry"
    message = logging.Formatter().format(record)
    if args.err_msg:  # type: ignore[attr-defined]
        assert message.startswith(args.err_msg)  # type: ignore[attr-defined]
    else:
        assert message.startswith("Exception ignored in <object object")
    assert str(args.exc_value) in message  # type: ignore[attr-defined]


@pytest.mark.usefixtures("default_hook_calls")
def test_unraisable_is_dropped_when_strix_has_no_handlers(
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = logging.getLogger("strix")
    saved, root.handlers = root.handlers, []
    try:
        sys.unraisablehook(_unraisable(RuntimeError("late"), object()))  # type: ignore[arg-type]
    finally:
        root.handlers = saved
    assert capsys.readouterr().err == ""


_EXIT_SCRIPT = r"""
import io, sys
from strix.telemetry.logging import setup_console_logging
setup_console_logging()

class Leaky:
    def __del__(self):
        raise ValueError("I/O operation on closed file.")

Leaky()
keep = Leaky()

import urllib3.response
resp = urllib3.response.HTTPResponse(body=io.BytesIO(b""), preload_content=False)
resp._fp.close()
del resp
print("done")
"""


def test_process_exit_prints_nothing_to_stderr() -> None:
    env = {
        k: v for k, v in os.environ.items() if k in {"PATH", "HOME", "SYSTEMROOT", "TEMP", "TMP"}
    }
    env |= {"PYTHONPATH": str(Path(__file__).resolve().parents[1]), "STRIX_DEBUG": ""}
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _EXIT_SCRIPT],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "done"
    assert proc.stderr == ""
