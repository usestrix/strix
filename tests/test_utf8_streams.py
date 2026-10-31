from __future__ import annotations

import io
import sys

import pytest
from rich.console import Console

from strix.interface.main import _force_utf8_streams
from strix.interface.tui.runtime import _open_output_sink


UNICODE_SAMPLE = "Reflected XSS in / \u2713 \u2192 \U0001f50d \u00b7 done"


def _cp1252_stream() -> tuple[io.TextIOWrapper, io.BytesIO]:
    raw = io.BytesIO()
    return io.TextIOWrapper(raw, encoding="cp1252", line_buffering=True), raw


def test_rich_output_raises_on_a_cp1252_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", _cp1252_stream()[0])
    monkeypatch.setattr(sys, "stderr", _cp1252_stream()[0])

    with pytest.raises(UnicodeEncodeError):
        Console().print(UNICODE_SAMPLE)


def test_force_utf8_streams_lets_rich_print_unicode(monkeypatch: pytest.MonkeyPatch) -> None:
    stdout, stdout_bytes = _cp1252_stream()
    stderr, stderr_bytes = _cp1252_stream()
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)

    _force_utf8_streams()

    assert stdout.encoding == "utf-8"
    assert stderr.encoding == "utf-8"
    Console().print(UNICODE_SAMPLE)
    Console(stderr=True).print(UNICODE_SAMPLE)
    stdout.flush()
    stderr.flush()
    assert UNICODE_SAMPLE in stdout_bytes.getvalue().decode("utf-8")
    assert UNICODE_SAMPLE in stderr_bytes.getvalue().decode("utf-8")


def test_force_utf8_streams_skips_streams_without_reconfigure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", io.StringIO())

    _force_utf8_streams()

    sys.stdout.write(UNICODE_SAMPLE)
    assert stdout.getvalue() == UNICODE_SAMPLE


def test_tui_output_sink_accepts_unicode() -> None:
    with _open_output_sink() as sink:
        assert sink.encoding == "utf-8"
        sink.write(UNICODE_SAMPLE + "\n")
