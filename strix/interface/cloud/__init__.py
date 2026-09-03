"""`strix cloud` — the managed Strix platform (app.strix.ai) from the terminal.

Every command maps to one operation of the public REST API. Output is JSON
when stdout is not a terminal, so agents can parse every result. Exit codes:
0 success, 1 error, 2 invalid usage, 4 authentication required, 5 payment
required.
"""

from __future__ import annotations

import json
import sys

from rich.console import Console
from rich.markup import escape

from strix.interface.cloud import http
from strix.interface.cloud.render import json_mode
from strix.interface.cloud.runner import resolve, run
from strix.interface.cloud.session import run_session
from strix.interface.cloud.spec import DEFAULT_VERBS, GROUP_HELP, SPEC
from strix.interface.cloud.workspaces import run_workspace_use
from strix.interface.platform_cli import run_login
from strix.interface.terminal_text import sanitize_terminal_text


_USAGE_HEADER = """[bold]Usage:[/] strix cloud <command> [arguments]

[bold]Session commands:[/]
  login       Sign in to the managed platform and store an API token
  logout      Remove the stored API token
  whoami      Show the stored account, workspace, and token state
  session     Inspect or narrow the remote CLI session
  credits     Show the credit balance of the workspace

[bold]Resource commands:[/]"""

_USAGE_FOOTER = """
Run [bold]strix cloud <command> help[/] to list its verbs. Common read-only
commands may also run their default verb when no verb is given.
Every REST resource command accepts [bold]--json[/] and [bold]--token[/]. Write
commands accept [bold]--data[/] with a JSON object of extra request fields.
Login is an interactive device flow; [bold]whoami[/] and [bold]logout[/] also
produce JSON automatically when output is redirected.
API reference: https://docs.app.strix.ai"""

_HELP_TOKENS = frozenset({"-h", "--help", "help"})


def _is_help_request(argv: list[str]) -> bool:
    """Recognize a help token with an optional JSON-output flag in either order."""
    return sum(argument in _HELP_TOKENS for argument in argv) == 1 and all(
        argument in _HELP_TOKENS or argument == "--json" for argument in argv
    )


def run_cloud(argv: list[str]) -> int:
    """Run a managed-cloud command without ever leaking a Ctrl-C traceback."""
    try:
        return _run_cloud(argv)
    except KeyboardInterrupt:
        if json_mode(flag="--json" in argv):
            sys.stdout.write(json.dumps({"error": "Interrupted.", "interrupted": True}) + "\n")
        else:
            Console(stderr=True).print("[yellow]Interrupted.[/]")
        return 130


def _run_cloud(argv: list[str]) -> int:  # noqa: PLR0911, PLR0912
    """Entry point for ``strix cloud …``. Returns a process exit code."""
    console = Console()
    as_json = json_mode(flag="--json" in argv)
    if not argv or _is_help_request(argv):
        if as_json:
            _print_usage_json()
        else:
            _print_usage(console)
        return 0
    if argv == ["--json"]:
        _print_usage_json()
        return 0

    group, rest = argv[0], argv[1:]
    if group == "workspace":
        group = "workspaces"
    if group in ("login", "logout", "whoami"):
        return _run_session(console, group, rest)
    if group == "session":
        return run_session(rest)
    if group == "credits":
        group, rest = "billing", ["credits", *rest]
    if group == "workspaces" and rest and rest[0] == "use":
        try:
            return run_workspace_use(rest[1:])
        except http.CloudError as exc:
            if "--json" in rest:
                sys.stdout.write(json.dumps({"error": str(exc)}) + "\n")
            else:
                console.print(f"[red]Error:[/] {escape(sanitize_terminal_text(exc))}")
            return exc.exit_code

    if group not in SPEC:
        if as_json:
            sys.stdout.write(json.dumps({"error": f"unknown command: {group}"}) + "\n")
            return 2
        console.print(f"[red]Unknown command:[/] {escape(sanitize_terminal_text(group))}")
        _print_usage(console)
        return 2
    group_help = _is_help_request(rest)
    resolved = None if group_help else resolve(group, rest)
    if resolved is None:
        help_tokens: set[str] = set(_HELP_TOKENS) if group_help else set()
        invalid = [arg for arg in rest if arg != "--json" and arg not in help_tokens]
        _print_verbs(console, group, as_json=as_json, error="unknown verb" if invalid else None)
        return 2 if invalid else 0
    cmd, remaining = resolved
    verb_label = " ".join(rest[: len(rest) - len(remaining)]) or DEFAULT_VERBS.get(group, "")
    return run(group, verb_label, cmd, remaining)


def _run_session(_console: Console, group: str, rest: list[str]) -> int:
    if rest and rest[0] == "help":
        rest = ["--help", *rest[1:]]
    session_argv = {
        "login": rest,
        "logout": ["logout", *rest],
        "whoami": ["status", *rest],
    }
    return run_login(session_argv[group])


def _print_usage(console: Console) -> None:
    console.print(_USAGE_HEADER)
    for group in SPEC:
        console.print(f"  {group:<14}{GROUP_HELP.get(group, '')}")
    console.print(_USAGE_FOOTER)


def _print_verbs(
    console: Console, group: str, *, as_json: bool = False, error: str | None = None
) -> None:
    if as_json:
        verbs: list[dict[str, str]] = [
            {"name": verb, "help": command.help} for verb, command in SPEC[group].items()
        ]
        if group == "workspaces":
            verbs.append({"name": "use", "help": "Switch the stored token to another workspace."})
        payload: dict[str, object] = {
            "command": f"strix cloud {group}",
            "verbs": verbs,
        }
        if error:
            payload["error"] = error
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return
    console.print(f"[bold]strix cloud {group}[/] verbs:")
    for verb, cmd in SPEC[group].items():
        console.print(f"  {verb:<28}{cmd.help}")
    if group == "workspaces":
        console.print(f"  {'use':<28}Switch the stored token to another workspace.")


def _print_usage_json() -> None:
    payload = {
        "command": "strix cloud",
        "session_commands": ["login", "logout", "whoami", "session", "credits"],
        "resource_commands": [{"name": group, "help": GROUP_HELP.get(group, "")} for group in SPEC],
    }
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
