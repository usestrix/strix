"""Inspect and safely narrow a managed Strix CLI session."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, cast

from rich.console import Console
from rich.markup import escape

import strix.interface.cloud.http as http  # noqa: PLR0402
from strix.interface.cloud.arguments import CloudArgumentParser
from strix.interface.cloud.render import emit, json_mode
from strix.interface.platform_cli import read_record, save_record
from strix.interface.terminal_text import sanitize_terminal_text


if TYPE_CHECKING:
    import argparse


def run_session(argv: list[str]) -> int:
    console = Console()
    normalized = ["show", *argv] if not argv or argv[0].startswith("-") else list(argv)
    if normalized[0] == "help":
        normalized = ["--help", *normalized[1:]]
    if normalized[0] in {"-h", "--help"}:
        _print_help(console)
        return 0
    verb = normalized.pop(0)
    if verb == "scopes" and normalized and normalized[0] == "set":
        normalized.pop(0)
        return _run_scopes_set(console, normalized)
    if verb not in {"show", "scopes"}:
        console.print(f"[red]Unknown session command:[/] {escape(sanitize_terminal_text(verb))}")
        _print_help(console)
        return http.EXIT_USAGE
    return _run_show(console, normalized, scopes_only=verb == "scopes")


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Print the raw JSON response.")
    parser.add_argument("--show-scopes", action="store_true", help="Print every granted scope.")
    parser.add_argument("--token", default=None, help="API token override.")
    parser.add_argument("--workspace-id", default=None, metavar="ORG_ID")
    parser.add_argument("--app-url", default=None, metavar="URL")
    parser.add_argument("--timeout", default=None, type=float, metavar="SECONDS")


def _configure(args: argparse.Namespace) -> bool:
    external = args.token is not None or bool(os.environ.get("STRIX_API_TOKEN", "").strip())
    http.configure(
        base_url=args.app_url,
        timeout=args.timeout,
        token_override=bool(args.token),
        workspace_id=args.workspace_id,
    )
    return external


def _run_show(console: Console, argv: list[str], *, scopes_only: bool) -> int:
    parser = CloudArgumentParser(prog=f"strix cloud session {'scopes' if scopes_only else 'show'}")
    _common(parser)
    as_json = json_mode(flag="--json" in argv)
    try:
        args = parser.parse_args(argv)
        _configure(args)
        payload = http.check(http.request("GET", "/cli/session", token=args.token))
    except SystemExit as exc:
        return int(exc.code or 0)
    except http.CloudError as exc:
        return _error(console, exc, as_json=as_json)
    if not isinstance(payload, dict):
        return _error(console, http.CloudError("invalid CLI session response"), as_json=as_json)
    record = cast("dict[str, Any]", payload)
    if as_json:
        emit(console, record, as_json=True)
        return http.EXIT_OK
    scopes = _string_list(record.get("scopes"))
    ceiling = _string_list(record.get("scope_ceiling"))
    profile = str(record.get("scope_profile") or "custom").title()
    if not scopes_only:
        device_name = escape(str(record.get("device_name") or "this device"))
        console.print(f"[green]Active CLI session[/] on [bold]{device_name}[/]")
        console.print(f"  Workspace: {escape(str(record.get('organization_id') or 'unknown'))}")
    console.print(f"  Access: {profile} · {len(scopes)} scopes granted · {len(ceiling)} maximum")
    if args.show_scopes or scopes_only:
        console.print(f"  Granted: [dim]{escape(' '.join(scopes))}[/]")
        console.print(f"  Ceiling: [dim]{escape(' '.join(ceiling))}[/]")
    return http.EXIT_OK


def _run_scopes_set(console: Console, argv: list[str]) -> int:
    parser = CloudArgumentParser(
        prog="strix cloud session scopes set",
        description="Change scopes within the access approved at browser sign-in.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("profile", nargs="?", choices=("minimal", "recommended", "full"))
    mode.add_argument("--scopes", nargs="+", metavar="SCOPE")
    _common(parser)
    as_json = json_mode(flag="--json" in argv)
    try:
        args = parser.parse_args(argv)
        external = _configure(args)
        body = (
            {"scope_profile": args.profile}
            if args.profile
            else {"scope_profile": "custom", "scopes": args.scopes}
        )
        payload = http.check(http.request("PATCH", "/cli/session", token=args.token, body=body))
    except SystemExit as exc:
        return int(exc.code or 0)
    except http.CloudError as exc:
        return _error(console, exc, as_json=as_json)
    if not isinstance(payload, dict):
        return _error(console, http.CloudError("invalid CLI session response"), as_json=as_json)
    result = cast("dict[str, Any]", payload)
    if not external:
        stored = read_record()
        if stored is not None:
            stored.update(
                {
                    key: result[key]
                    for key in ("scopes", "requested_scopes", "scope_ceiling", "scope_profile")
                    if key in result
                }
            )
            save_record(stored)
    if as_json:
        emit(console, result, as_json=True)
    else:
        scopes = _string_list(result.get("scopes"))
        profile = str(result.get("scope_profile") or "custom").title()
        console.print(f"[green]✓ CLI access updated.[/] {profile} · {len(scopes)} scopes granted")
        if args.show_scopes:
            console.print(f"  Scopes: [dim]{escape(' '.join(scopes))}[/]")
    return http.EXIT_OK


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items = cast("list[Any]", cast("Any", value))
    return [str(item) for item in items]


def _error(console: Console, error: http.CloudError, *, as_json: bool) -> int:
    if as_json:
        raw_payload: Any = error.payload
        error_payload = cast("dict[str, Any]", raw_payload)
        payload = dict(error_payload) if isinstance(raw_payload, dict) else {}
        payload["error"] = str(error)
        if payload.get("detail") == payload.get("error"):
            payload.pop("detail", None)
        emit(console, payload, as_json=True)
    else:
        console.print(f"[red]Error:[/] {escape(sanitize_terminal_text(error))}")
    return error.exit_code


def _print_help(console: Console) -> None:
    console.print("[bold]strix cloud session[/] commands:")
    console.print("  show                         Show the remote CLI session (default).")
    console.print("  scopes                       Show granted scopes and consent ceiling.")
    console.print("  scopes set PROFILE           Use minimal, recommended, or full.")
    console.print("  scopes set --scopes SCOPE…   Use a custom set within the ceiling.")
