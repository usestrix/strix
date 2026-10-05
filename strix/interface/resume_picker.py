"""Inline arrow-key picker for ``strix --resume`` with no run name.

Draws a short list in the normal terminal (no alternate screen), redraws it in
place on every key, and returns the chosen run. Keys: up/down, page up/down,
home/end, enter, esc, typing filters the rows, backspace edits the filter.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime
from typing import TYPE_CHECKING, TextIO

from rich.console import Console
from rich.text import Text


if TYPE_CHECKING:
    from collections.abc import Callable

    from strix.report.runs import RunSummary


KEY_UP = "up"
KEY_DOWN = "down"
KEY_PAGE_UP = "pageup"
KEY_PAGE_DOWN = "pagedown"
KEY_HOME = "home"
KEY_END = "end"
KEY_ENTER = "enter"
KEY_ESCAPE = "escape"
KEY_BACKSPACE = "backspace"
KEY_INTERRUPT = "interrupt"

_CSI_KEYS = {
    "A": KEY_UP,
    "B": KEY_DOWN,
    "H": KEY_HOME,
    "F": KEY_END,
    "1~": KEY_HOME,
    "4~": KEY_END,
    "5~": KEY_PAGE_UP,
    "6~": KEY_PAGE_DOWN,
    "7~": KEY_HOME,
    "8~": KEY_END,
}
_WINDOWS_KEYS = {
    "H": KEY_UP,
    "P": KEY_DOWN,
    "I": KEY_PAGE_UP,
    "Q": KEY_PAGE_DOWN,
    "G": KEY_HOME,
    "O": KEY_END,
}
_CONTROL_KEYS = {
    "\r": KEY_ENTER,
    "\n": KEY_ENTER,
    "\x1b": KEY_ESCAPE,
    "\x7f": KEY_BACKSPACE,
    "\x08": KEY_BACKSPACE,
    "\x03": KEY_INTERRUPT,
}

_CURSOR_HIDE = "\x1b[?25l"
_CURSOR_SHOW = "\x1b[?25h"
_CLEAR_BELOW = "\x1b[J"

_GREEN = "#22c55e"
_AMBER = "#f59e0b"
_STATUS_STYLES = {
    "completed": _GREEN,
    "running": _GREEN,
    "interrupted": _AMBER,
    "stopped": _AMBER,
    "failed": "#ef4444",
}
_NO_STATE = "no state"
_CURSOR = " \u276f "
_STARTED_WIDTH = 14
_FINDINGS_WIDTH = 8
_MIN_TARGET_WIDTH = 12
_MAX_RUN_WIDTH = 40
_CHROME_LINES = 8
_MAX_VISIBLE = 8


def _utf8_length(lead: bytes) -> int:
    byte = lead[0] if lead else 0
    if byte >= 0xF0:
        return 4
    if byte >= 0xE0:
        return 3
    if byte >= 0xC0:
        return 2
    return 1


class PickerUnavailableError(RuntimeError):
    """The picker needs an interactive terminal on stdin and stdout."""


if sys.platform == "win32":
    import msvcrt

    def read_raw_key(_stream: TextIO) -> str:
        char = str(msvcrt.getwch())
        if char in ("\x00", "\xe0"):
            return _WINDOWS_KEYS.get(str(msvcrt.getwch()), "")
        return char

else:
    import select
    import termios
    import tty

    def read_raw_key(stream: TextIO) -> str:
        fd = stream.fileno()
        saved = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd, termios.TCSANOW)
            first = os.read(fd, 1)
            char = (first + os.read(fd, _utf8_length(first) - 1)).decode("utf-8", "replace")
            if char != "\x1b":
                return char
            sequence = ""
            while select.select([fd], [], [], 0.05)[0]:
                sequence += os.read(fd, 1).decode("utf-8", "replace")
                if (sequence.startswith("[") and sequence[-1].isalpha()) or sequence.endswith("~"):
                    break
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        if not sequence:
            return "\x1b"
        return _CSI_KEYS.get(sequence[1:], "") if sequence[0] in "[O" else ""


def read_key(stream: TextIO) -> str:
    return translate_key(read_raw_key(stream))


def translate_key(raw: str) -> str:
    return _CONTROL_KEYS.get(raw, raw)


def relative_time(stamp: str, now: datetime | None = None) -> str:
    try:
        started = datetime.fromisoformat(stamp)
    except ValueError:
        return stamp[:16] if stamp else "unknown"
    if started.tzinfo is None:
        started = started.replace(tzinfo=UTC)
    now = now or datetime.now(UTC)
    seconds = (now - started).total_seconds()
    for limit, unit, label in (
        (60, 1, ""),
        (3600, 60, "min"),
        (86400, 3600, "h"),
        (7 * 86400, 86400, "d"),
    ):
        if seconds < limit:
            return "just now" if not label else f"{int(seconds // unit)} {label} ago"
    local = started.astimezone()
    if local.year == now.astimezone().year:
        return f"{local:%b} {local.day}, {local:%H:%M}"
    return f"{local:%b} {local.day}, {local.year}"


def filter_runs(runs: list[RunSummary], needle: str) -> list[RunSummary]:
    needle = needle.strip().lower()
    if not needle:
        return list(runs)
    return [
        run
        for run in runs
        if needle in run.run_name.lower()
        or needle in run.target.lower()
        or needle in run.status.lower()
    ]


def _fit(text: str, width: int) -> str:
    if len(text) <= width:
        return text.ljust(width)
    return text[: width - 1] + "\u2026"


def _status_text(run: RunSummary) -> str:
    return run.status if run.resumable else f"{run.status} \u00b7 {_NO_STATE}"


class ResumePicker:
    def __init__(
        self,
        runs: list[RunSummary],
        *,
        console: Console,
        runs_dir: str,
        now: datetime | None = None,
    ) -> None:
        self.runs = runs
        self.console = console
        self.runs_dir = runs_dir
        self.now = now
        self.filter = ""
        self.cursor = 0
        self.offset = 0
        self.notice = ""
        self._drawn = 0

    @property
    def rows(self) -> list[RunSummary]:
        return filter_runs(self.runs, self.filter)

    def _visible(self) -> int:
        return max(3, min(len(self.rows), _MAX_VISIBLE, self.console.height - _CHROME_LINES))

    def _columns(self) -> tuple[int, int, int]:
        width = max(40, self.console.width - 1)
        status_width = max(len("status"), *(len(_status_text(run)) for run in self.runs))
        run_width = min(_MAX_RUN_WIDTH, max(len("run"), *(len(run.run_name) for run in self.runs)))
        fixed = len(_CURSOR) + _STARTED_WIDTH + _FINDINGS_WIDTH + status_width + 4 * 2
        target_width = width - fixed - run_width
        if target_width < _MIN_TARGET_WIDTH:
            run_width = max(8, run_width + target_width - _MIN_TARGET_WIDTH)
            target_width = width - fixed - run_width
        return max(_MIN_TARGET_WIDTH, target_width), status_width, run_width

    def _scroll(self) -> range:
        rows = self.rows
        visible = self._visible()
        self.cursor = max(0, min(self.cursor, len(rows) - 1))
        if self.cursor < self.offset:
            self.offset = self.cursor
        elif self.cursor >= self.offset + visible:
            self.offset = self.cursor - visible + 1
        self.offset = max(0, min(self.offset, max(0, len(rows) - visible)))
        return range(self.offset, min(len(rows), self.offset + visible))

    def render(self) -> list[Text]:
        rows = self.rows
        widths = self._columns()
        window = self._scroll()

        title = Text()
        title.append(" Resume a run", style="bold")
        title.append(f"   {len(self.runs)} runs in ./{self.runs_dir}", style="dim")
        if self.filter:
            title.append("   search: ", style="dim")
            title.append(self.filter)
        header = Text(
            " " * len(_CURSOR)
            + self._cells("started", "target", "status", "findings", "run", widths),
            style="dim",
        )
        lines = [title, Text(), header]
        if not rows:
            lines.append(Text(f"   no runs match {self.filter!r}", style="dim"))
        if window.start:
            lines.append(Text(f"   \u2026 {window.start} more above", style="dim"))
        lines.extend(self._row(rows[index], index == self.cursor, widths) for index in window)
        if window.stop < len(rows):
            lines.append(Text(f"   \u2026 {len(rows) - window.stop} more below", style="dim"))
        footer = Text(" ")
        if self.notice:
            footer.append(self.notice, style=_AMBER)
        else:
            footer.append(
                "\u2191\u2193 move   enter resume   type to search   esc cancel", style="dim"
            )
        lines.extend([Text(), footer])
        for line in lines:
            line.truncate(self.console.width - 1)
        return lines

    @staticmethod
    def _cells(
        started: str,
        target: str,
        status: str,
        findings: str,
        run: str,
        widths: tuple[int, int, int],
    ) -> str:
        target_width, status_width, run_width = widths
        return "  ".join(
            [
                _fit(started, _STARTED_WIDTH),
                _fit(target, target_width),
                _fit(status, status_width),
                _fit(findings, _FINDINGS_WIDTH),
                _fit(run, run_width),
            ]
        )

    def _row(self, run: RunSummary, selected: bool, widths: tuple[int, int, int]) -> Text:
        target_width, status_width, run_width = widths
        primary = "bold" if selected else ""
        muted = "" if selected else "dim"
        status_style = _STATUS_STYLES.get(run.status, "")
        if not run.resumable:
            primary = muted = status_style = "dim"
        line = Text()
        line.append(_CURSOR if selected else " " * len(_CURSOR), style=_GREEN)
        line.append(_fit(relative_time(run.started_at, self.now), _STARTED_WIDTH), style=muted)
        line.append("  ")
        line.append(_fit(run.target, target_width), style=primary)
        line.append("  ")
        line.append(_fit(_status_text(run), status_width), style=status_style)
        line.append("  ")
        line.append(_fit(str(run.findings), _FINDINGS_WIDTH), style=muted)
        line.append("  ")
        line.append(_fit(run.run_name, run_width), style=muted)
        return line

    def draw(self) -> None:
        self.clear()
        lines = self.render()
        for line in lines:
            self.console.print(line, soft_wrap=True, overflow="crop", end="\n")
        self.console.file.flush()
        self._drawn = len(lines)

    def clear(self) -> None:
        if self._drawn:
            self.console.file.write(f"\x1b[{self._drawn}A\r{_CLEAR_BELOW}")
            self.console.file.flush()
            self._drawn = 0

    def handle(self, key: str) -> tuple[bool, RunSummary | None]:
        """Apply one key: (done, run), where done with no run means cancelled."""
        self.notice = ""
        if key == KEY_INTERRUPT:
            return True, None
        if key == KEY_ESCAPE:
            if not self.filter:
                return True, None
            self.filter = ""
            self.cursor = 0
            return False, None
        if key == KEY_ENTER:
            return self._choose()
        if key == KEY_BACKSPACE:
            self.filter = self.filter[:-1]
            self.cursor = 0
        elif len(key) == 1 and key.isprintable():
            self.filter += key
            self.cursor = 0
        else:
            self._move(key)
        self.cursor = max(0, min(self.cursor, max(0, len(self.rows) - 1)))
        return False, None

    def _choose(self) -> tuple[bool, RunSummary | None]:
        rows = self.rows
        if not rows:
            return False, None
        run = rows[self.cursor]
        if not run.resumable:
            self.notice = f"{run.run_name} has no saved agent state to resume from"
            return False, None
        return True, run

    def _move(self, key: str) -> None:
        steps = {
            KEY_UP: -1,
            KEY_DOWN: 1,
            KEY_PAGE_UP: -self._visible(),
            KEY_PAGE_DOWN: self._visible(),
        }
        if key in steps:
            self.cursor += steps[key]
        elif key == KEY_HOME:
            self.cursor = 0
        elif key == KEY_END:
            self.cursor = len(self.rows) - 1

    def run(self, next_key: Callable[[], str]) -> RunSummary | None:
        self.console.file.write(_CURSOR_HIDE)
        try:
            self.draw()
            while True:
                done, chosen = self.handle(next_key())
                if done:
                    return chosen
                self.draw()
        except KeyboardInterrupt:
            return None
        finally:
            self.clear()
            self.console.file.write(_CURSOR_SHOW)
            self.console.file.flush()


def pick_run(
    runs: list[RunSummary],
    *,
    runs_dir: str,
    console: Console | None = None,
    stdin: TextIO | None = None,
) -> RunSummary | None:
    stdin = stdin or sys.stdin
    console = console or Console()
    if not (hasattr(stdin, "isatty") and stdin.isatty() and console.is_terminal):
        raise PickerUnavailableError(
            "--resume needs a run name when there is no interactive terminal"
        )
    picker = ResumePicker(runs, console=console, runs_dir=runs_dir)
    return picker.run(lambda: read_key(stdin))
