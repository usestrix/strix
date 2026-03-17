import sys
import threading


_pretty = "--pretty" in sys.argv
_lock = threading.Lock()

_failures: list[dict[str, str | dict[str, object] | None]] = []
_passed = 0
_failed = 0

_live = None
_spinner = None
_console = None

if _pretty:
    from rich.console import Console
    from rich.live import Live
    from rich.markup import escape as rich_escape
    from rich.spinner import Spinner

    _console = Console(stderr=True, force_terminal=True)


def is_pretty():
    return _pretty


def start():
    global _live, _spinner
    if not _pretty:
        return
    _spinner = Spinner("dots", text="Starting…")
    _live = Live(
        _spinner,
        console=_console,
        refresh_per_second=12,
    )
    _live.start()


def stop():
    global _live
    if _live is not None:
        _live.stop()
        _live = None
    if _pretty and (_passed or _failed):
        _print_summary()


def status(msg):
    if not _pretty:
        return
    with _lock:
        if _spinner is not None:
            _spinner.update(text=f"  {msg}")


def _print_line(text, **kwargs):
    with _lock:
        if _live is not None:
            _live.console.print(text, **kwargs)
        elif _console is not None:
            _console.print(text, **kwargs)


def test_start(name):
    if not _pretty:
        return
    _print_line(f"  [bold]●[/] [bold]{name}[/]")


def log(msg, style="dim"):
    if not _pretty:
        return
    _print_line(f"      [dim]│[/] {msg}", style=style, highlight=False)


def log_error(msg):
    if not _pretty:
        return
    _print_line(f"      [red]│[/] {msg}", style="bold red", highlight=False)


def log_warn(msg):
    if not _pretty:
        return
    _print_line(f"      [yellow]│[/] {msg}", style="yellow", highlight=False)


def test_passed(name):
    global _passed
    _passed += 1
    if not _pretty:
        return
    _print_line("      [bold green]╰─ ✓ pass[/]")


def test_failed(name, details=""):
    global _failed
    _failed += 1
    if details:
        _failures.append({"name": name, "details": details})
    if not _pretty:
        return
    _print_line("      [bold red]╰─ ✗ fail[/]")


def record_failure(
    test_name,
    label,
    reason,
    result=None,
):
    _failures.append(
        {
            "name": test_name,
            "label": label,
            "reason": reason,
            "result": result,
        }
    )


def _print_summary():
    if _console is None:
        return
    _console.print()
    _console.rule(style="dim")
    _console.print()

    if _failures:
        _console.print("  [bold red]failures[/]")
        _console.print()
        for f in _failures:
            name = f.get("name", "?")
            reason = str(f.get("reason", f.get("details", "")))
            result = f.get("result")

            _console.print(f"  [bold red]── {name} ──[/]")

            if reason:
                for line in reason.split("\n"):
                    _console.print(f"     [red]│[/] {rich_escape(line)}")

            if result and isinstance(result, dict):
                _console.print("     [red]│[/]")
                _console.print("     [red]╰─▶[/] [dim]result:[/]")
                for k, v in result.items():
                    v_str = str(v)
                    if len(v_str) > 120:
                        v_str = v_str[:120] + "…"
                    _console.print(f"          [dim]{k}:[/] {rich_escape(v_str)}")

            _console.print()

    total = _passed + _failed
    if _failed:
        _console.print(
            f"  [bold]result:[/] [bold red]FAILED[/]  "
            f"{_passed} passed, {_failed} failed  "
            f"({total} total)",
        )
    else:
        _console.print(
            f"  [bold]result:[/] [bold green]ok[/]  {_passed} passed  ({total} total)",
        )
    _console.print()
