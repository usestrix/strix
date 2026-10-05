from __future__ import annotations

import io
import os
import sys
from datetime import UTC, datetime, timedelta

import pytest
from rich.console import Console

from strix.interface.resume_picker import (
    KEY_BACKSPACE,
    KEY_DOWN,
    KEY_END,
    KEY_ENTER,
    KEY_ESCAPE,
    KEY_INTERRUPT,
    KEY_UP,
    PickerUnavailableError,
    ResumePicker,
    filter_runs,
    pick_run,
    read_raw_key,
    relative_time,
    translate_key,
)
from strix.report.runs import RunSummary


NOW = datetime(2026, 10, 4, 16, 0, tzinfo=UTC)


def _run(
    name: str,
    target: str,
    *,
    minutes_ago: int,
    status: str = "completed",
    findings: int = 0,
    resumable: bool = True,
) -> RunSummary:
    started = (NOW - timedelta(minutes=minutes_ago)).isoformat()
    return RunSummary(
        run_name=name,
        target=target,
        started_at=started,
        ended_at=started,
        status=status,
        findings=findings,
        resumable=resumable,
    )


RUNS = [
    _run("example-com_e5e6", "https://example.com", minutes_ago=12),
    _run(
        "example-com_223e", "https://example.com", minutes_ago=40, status="interrupted", findings=2
    ),
    _run(
        "juice-shop_8a1f",
        "https://juice-shop.herokuapp.com",
        minutes_ago=60 * 26,
        status="stopped",
        findings=7,
    ),
    _run(
        "strix_41c0",
        "/home/me/code/strix (workspace)",
        minutes_ago=60 * 50,
        status="failed",
        resumable=False,
    ),
]


def _console(width: int = 110, height: int = 30) -> tuple[Console, io.StringIO]:
    buffer = io.StringIO()
    console = Console(
        file=buffer, width=width, height=height, force_terminal=True, color_system="truecolor"
    )
    return console, buffer


def _picker(runs: list[RunSummary] = RUNS) -> ResumePicker:
    console, _ = _console()
    return ResumePicker(runs, console=console, runs_dir="strix_runs", now=NOW)


def _plain(picker: ResumePicker) -> str:
    return "\n".join(line.plain for line in picker.render())


def test_translate_key_maps_control_characters() -> None:
    assert translate_key("\r") == KEY_ENTER
    assert translate_key("\n") == KEY_ENTER
    assert translate_key("\x1b") == KEY_ESCAPE
    assert translate_key("\x7f") == KEY_BACKSPACE
    assert translate_key("\x03") == KEY_INTERRUPT
    assert translate_key("a") == "a"


def test_relative_time_buckets() -> None:
    assert relative_time((NOW - timedelta(seconds=5)).isoformat(), NOW) == "just now"
    assert relative_time((NOW - timedelta(minutes=12)).isoformat(), NOW) == "12 min ago"
    assert relative_time((NOW - timedelta(hours=3, minutes=1)).isoformat(), NOW) == "3 h ago"
    assert relative_time((NOW - timedelta(days=2)).isoformat(), NOW) == "2 d ago"
    assert relative_time("2026-01-02T15:04:00+00:00", NOW).startswith("Jan 2")
    assert relative_time("2025-01-02T15:04:00+00:00", NOW).endswith("2025")
    assert relative_time("not a date", NOW) == "not a date"
    assert relative_time("", NOW) == "unknown"


def test_filter_matches_name_target_and_status() -> None:
    assert [run.run_name for run in filter_runs(RUNS, "juice")] == ["juice-shop_8a1f"]
    assert [run.run_name for run in filter_runs(RUNS, "INTERRUPTED")] == ["example-com_223e"]
    assert [run.run_name for run in filter_runs(RUNS, "example.com")] == [
        "example-com_e5e6",
        "example-com_223e",
    ]
    assert filter_runs(RUNS, "") == RUNS


def test_render_lists_every_run_with_its_metadata() -> None:
    text = _plain(_picker())
    assert "Resume a run" in text
    assert "4 runs in ./strix_runs" in text
    for run in RUNS:
        assert run.run_name in text
    assert "12 min ago" in text
    assert "https://juice-shop.herokuapp.com" in text
    assert "interrupted" in text
    assert "failed · no state" in text
    assert text.splitlines()[3].startswith(" \u276f ")


def test_enter_returns_the_highlighted_run() -> None:
    keys = iter([KEY_DOWN, KEY_ENTER])
    assert _picker().run(lambda: next(keys)) == RUNS[1]


def test_cursor_is_clamped_and_end_jumps_to_the_last_run() -> None:
    picker = _picker()
    picker.handle(KEY_UP)
    assert picker.cursor == 0
    picker.handle(KEY_END)
    assert picker.cursor == len(RUNS) - 1
    for _ in range(10):
        picker.handle(KEY_DOWN)
    assert picker.cursor == len(RUNS) - 1


def test_escape_cancels_and_clears_the_search_first() -> None:
    keys = iter(["j", "u", KEY_ESCAPE, KEY_ESCAPE])
    picker = _picker()
    assert picker.run(lambda: next(keys)) is None
    assert picker.filter == ""


def test_typing_filters_and_backspace_restores() -> None:
    picker = _picker()
    for char in "juice":
        picker.handle(char)
    assert [run.run_name for run in picker.rows] == ["juice-shop_8a1f"]
    assert "search: juice" in _plain(picker)
    for _ in range(5):
        picker.handle(KEY_BACKSPACE)
    assert len(picker.rows) == len(RUNS)


def test_runs_without_agent_state_cannot_be_picked() -> None:
    picker = _picker()
    picker.handle(KEY_END)
    assert picker.handle(KEY_ENTER) == (False, None)
    assert "no saved agent state" in _plain(picker)


def test_no_match_renders_a_hint_and_enter_does_nothing() -> None:
    picker = _picker()
    for char in "zzz":
        picker.handle(char)
    assert "no runs match 'zzz'" in _plain(picker)
    assert picker.handle(KEY_ENTER) == (False, None)


def test_long_lists_scroll_to_keep_the_cursor_visible() -> None:
    runs = [
        _run(f"run_{index:02d}", f"https://host{index}.example", minutes_ago=index)
        for index in range(40)
    ]
    console, _ = _console(height=12)
    picker = ResumePicker(runs, console=console, runs_dir="strix_runs", now=NOW)
    text = _plain(picker)
    assert "run_00" in text
    assert "more above" not in text
    assert "more below" in text
    picker.handle(KEY_END)
    text = _plain(picker)
    assert "run_39" in text
    assert "run_00" not in text
    assert "more above" in text
    assert "more below" not in text


def test_run_redraws_in_place_and_restores_the_cursor() -> None:
    console, buffer = _console()
    picker = ResumePicker(RUNS, console=console, runs_dir="strix_runs", now=NOW)
    keys = iter([KEY_DOWN, KEY_ENTER])
    picker.run(lambda: next(keys))
    output = buffer.getvalue()
    assert output.startswith("\x1b[?25l")
    assert output.endswith("\x1b[?25h")
    assert "\x1b[J" in output
    assert "example-com_223e" in output


def test_ctrl_c_cancels_like_escape() -> None:
    console, _ = _console()
    picker = ResumePicker(RUNS, console=console, runs_dir="strix_runs", now=NOW)
    assert picker.handle(KEY_INTERRUPT) == (True, None)


def test_sigint_while_waiting_for_a_key_cancels_and_restores_the_cursor() -> None:
    console, buffer = _console()
    picker = ResumePicker(RUNS, console=console, runs_dir="strix_runs", now=NOW)

    def interrupted() -> str:
        raise KeyboardInterrupt

    assert picker.run(interrupted) is None
    assert buffer.getvalue().endswith("\x1b[?25h")


def test_sigint_while_drawing_cancels_and_restores_the_cursor() -> None:
    console, buffer = _console()
    picker = ResumePicker(RUNS, console=console, runs_dir="strix_runs", now=NOW)
    draw = picker.draw

    def interrupted_draw() -> None:
        draw()
        raise KeyboardInterrupt

    picker.draw = interrupted_draw  # type: ignore[method-assign]
    assert picker.run(lambda: KEY_DOWN) is None
    assert buffer.getvalue().endswith("\x1b[?25h")


def test_pick_run_needs_a_terminal() -> None:
    console, _ = _console()
    with pytest.raises(PickerUnavailableError):
        pick_run(RUNS, runs_dir="strix_runs", console=console, stdin=io.StringIO())


def test_narrow_terminals_never_wrap_a_row() -> None:
    console, _ = _console(width=48)
    picker = ResumePicker(RUNS, console=console, runs_dir="strix_runs", now=NOW)
    for line in picker.render():
        assert len(line.plain) <= 47, line.plain


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX key reader")
def test_posix_key_reader_handles_multibyte_and_arrows() -> None:
    master, slave = os.openpty()
    try:
        with os.fdopen(slave, "r+b", buffering=0) as stream:
            os.write(master, "\u00e9".encode())
            assert read_raw_key(stream) == "\u00e9"  # type: ignore[arg-type]
            os.write(master, b"\x1b[B")
            assert read_raw_key(stream) == KEY_DOWN  # type: ignore[arg-type]
            os.write(master, b"\x1b[6~")
            assert read_raw_key(stream) == "pagedown"  # type: ignore[arg-type]
            os.write(master, b"\r")
            assert translate_key(read_raw_key(stream)) == KEY_ENTER  # type: ignore[arg-type]
    finally:
        os.close(master)


def test_tall_terminals_still_show_a_short_window() -> None:
    console, _ = _console(height=60)
    runs = [
        _run(f"run_{index:02d}", f"https://host{index}.example", minutes_ago=index)
        for index in range(40)
    ]
    picker = ResumePicker(runs, console=console, runs_dir="strix_runs", now=NOW)
    plain = [line.plain for line in picker.render()]
    assert sum(1 for line in plain if "run_" in line) == 8
    assert any("more below" in line for line in plain)
