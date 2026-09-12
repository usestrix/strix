import sys

import pytest
import urllib3.response

from strix.telemetry import logging as tlog
from strix.telemetry.logging import _is_urllib3_closed_file_noise


class _Args:
    def __init__(self, exc_value: BaseException | None, obj: object) -> None:
        self.exc_type = type(exc_value) if exc_value is not None else None
        self.exc_value = exc_value
        self.exc_traceback = None
        self.err_msg = None
        self.object = obj


def _urllib3_response() -> urllib3.response.HTTPResponse:
    return urllib3.response.HTTPResponse(body=b"")


def test_filters_urllib3_closed_file_noise() -> None:
    args = _Args(ValueError("I/O operation on closed file."), _urllib3_response())
    assert _is_urllib3_closed_file_noise(args)  # type: ignore[arg-type]


def test_passes_through_other_unraisables() -> None:
    assert not _is_urllib3_closed_file_noise(
        _Args(ValueError("I/O operation on closed file."), object())  # type: ignore[arg-type]
    )
    assert not _is_urllib3_closed_file_noise(
        _Args(RuntimeError("boom"), _urllib3_response())  # type: ignore[arg-type]
    )
    assert not _is_urllib3_closed_file_noise(
        _Args(ValueError("something else"), _urllib3_response())  # type: ignore[arg-type]
    )


def test_installed_hook_filters_and_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    monkeypatch.setattr(sys, "unraisablehook", calls.append)
    monkeypatch.setattr(tlog, "_unraisable_hook_installed", False)
    tlog._silence_urllib3_finalizer_noise()
    hook = sys.unraisablehook
    assert hook is not calls.append

    hook(_Args(ValueError("I/O operation on closed file."), _urllib3_response()))  # type: ignore[arg-type]
    assert calls == []

    other = _Args(RuntimeError("boom"), object())
    hook(other)  # type: ignore[arg-type]
    assert calls == [other]
