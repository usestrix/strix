"""`strix cloud login` — managed platform sign-in (app.strix.ai).

Signing in runs an OAuth 2.0 device authorization flow in the browser, creates
the Strix account and workspace when they do not exist yet, and stores a
personal API token in ``~/.strix/platform-auth.json``. The token drives the
managed REST API (scans, credits, top-ups) without a dashboard visit.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any, NoReturn, cast
from urllib.parse import urlparse, urlsplit, urlunsplit

import requests
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.text import Text

from strix.config import load_settings
from strix.interface.platform_identity import read_or_create_identity
from strix.interface.terminal_text import sanitize_terminal_text
from strix.interface.url_safety import is_safe_web_url
from strix.utils.secret_files import write_secret_text


AUTH_PATH = Path.home() / ".strix" / "platform-auth.json"

_HTTP_TIMEOUT_S = 30
_DEFAULT_POLL_INTERVAL_S = 5
_MAX_POLL_INTERVAL_S = 60
_MAX_EXPIRES_IN_S = 30 * 60

_ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}


class PlatformAuthError(Exception):
    """Raised when the device authorization flow fails."""


class _SessionUsageError(Exception):
    """A session subcommand received invalid arguments."""


class _SessionArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _SessionUsageError(f"invalid arguments for {self.prog}: {message}")


def _terminal_markup(value: object) -> str:
    return escape(sanitize_terminal_text(value))


def _app_url() -> str:
    return load_settings().viewer.app_url.rstrip("/")


def read_record() -> dict[str, Any] | None:
    try:
        data = json.loads(AUTH_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    record = cast("dict[str, Any]", data)
    if not record.get("api_token"):
        return None
    return record


def save_record(record: dict[str, Any]) -> None:
    write_secret_text(AUTH_PATH, json.dumps(record, indent=2))


def logout() -> bool:
    try:
        AUTH_PATH.unlink()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True


def run_login(argv: list[str]) -> int:
    """Entry point for ``strix cloud login``. Returns a process exit code."""
    console = Console()
    subcommand = argv[0] if argv else None

    if subcommand == "status":
        return _status(console, argv[1:])
    if subcommand == "logout":
        return _logout(console, argv[1:])
    return _login(console, argv)


def _login(console: Console, argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="strix cloud login", add_help=True)
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open the browser. Print the verification URL instead.",
    )
    scope_mode = parser.add_mutually_exclusive_group()
    scope_mode.add_argument(
        "--scopes",
        nargs="+",
        metavar="SCOPE",
        default=None,
        help=(
            "API scopes for the token, for example scans:read billing:write. "
            "The server always includes a minimum scope set. "
            "Without this option, an interactive picker opens after the browser step."
        ),
    )
    scope_mode.add_argument(
        "--scope-profile",
        choices=("minimal", "recommended", "full"),
        default=None,
        help="Scope profile to approve. Defaults to an interactive choice in a TTY.",
    )
    parser.add_argument(
        "--device-name",
        default=None,
        metavar="NAME",
        help="Privacy-safe label shown for this CLI session in the dashboard.",
    )
    parser.add_argument(
        "--workspace",
        metavar="WORKSPACE",
        default=None,
        help=(
            "Workspace that receives the token, by ID or by exact name. "
            "Without this option, an interactive picker opens when you have "
            "more than one workspace."
        ),
    )
    previous_record = read_record()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse already printed the message
        return exc.code if isinstance(exc.code, int) else 2

    console.print()
    host = urlparse(_app_url()).netloc or _app_url()
    console.print(f"[bold]Signing in to the Strix platform[/] [dim]({_terminal_markup(host)})[/]")
    console.print(
        "[dim]This creates your account and workspace when needed, and stores an API token.[/]"
    )
    console.print()

    try:
        record = _run_device_flow(
            console,
            open_browser=not args.no_browser,
            scopes=args.scopes,
            scope_profile=args.scope_profile,
            workspace=args.workspace,
            device_name=args.device_name,
        )
    except PlatformAuthError as exc:
        console.print(f"[red]Sign-in failed:[/] {_terminal_markup(exc)}")
        return 1
    except KeyboardInterrupt:
        console.print("\n[yellow]Sign-in cancelled.[/]")
        return 130

    try:
        save_record(record)
    except OSError as exc:
        console.print(
            f"[red]Sign-in succeeded, but the token could not be stored:[/] {_terminal_markup(exc)}"
        )
        console.print(
            f"[dim]Check that {_terminal_markup(AUTH_PATH.parent)} is writable, "
            "then run `strix cloud login` again.[/]"
        )
        return 1
    _revoke_replaced_legacy_session(previous_record, record)
    _print_success(console, record)
    return 0


def _run_device_flow(  # noqa: PLR0912, PLR0915
    console: Console,
    *,
    open_browser: bool,
    scopes: list[str] | None = None,
    scope_profile: str | None = None,
    workspace: str | None = None,
    device_name: str | None = None,
) -> dict[str, Any]:
    app_url = _app_url()
    interactive = workspace is not None or (
        sys.stdin.isatty() and scopes is None and scope_profile is None
    )
    try:
        identity = read_or_create_identity(device_name=device_name)
    except (OSError, ValueError) as exc:
        raise PlatformAuthError(f"could not prepare the CLI device identity: {exc}") from exc

    try:
        response = requests.post(
            f"{app_url}/api/v1/cli/login",
            timeout=_HTTP_TIMEOUT_S,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise PlatformAuthError(f"could not reach {app_url}: {exc}") from exc
    if not 200 <= response.status_code < 300:
        raise PlatformAuthError(_error_detail(response))
    authorization = _json_object(response)

    user_code = str(authorization.get("user_code") or "")
    verification_uri = str(
        authorization.get("verification_uri_complete")
        or authorization.get("verification_uri")
        or ""
    )
    device_code = str(authorization.get("device_code") or "")
    expires_in = _as_positive_int(
        authorization.get("expires_in"), default=300, maximum=_MAX_EXPIRES_IN_S
    )
    interval = _as_positive_int(
        authorization.get("interval"),
        default=_DEFAULT_POLL_INTERVAL_S,
        maximum=_MAX_POLL_INTERVAL_S,
    )
    if not device_code or not verification_uri:
        raise PlatformAuthError("the server returned an incomplete device authorization")
    if not is_safe_web_url(verification_uri, trusted_origin=app_url):
        raise PlatformAuthError("the server returned an invalid verification URL")

    console.print(
        Panel.fit(
            Text.assemble(
                ("Confirmation code: ", "dim"),
                (sanitize_terminal_text(user_code), "bold cyan"),
            ),
            title="Verify this device",
        )
    )
    console.print("Open this URL in your browser and confirm the code:")
    console.print(sanitize_terminal_text(verification_uri), markup=False, soft_wrap=True)

    if open_browser:
        with contextlib.suppress(Exception):
            webbrowser.open(verification_uri)

    console.print("[dim]Waiting for browser confirmation…[/]")

    poll_body: dict[str, Any] = {"device_code": device_code, **identity}
    if interactive:
        poll_body["interactive"] = True
    elif scopes:
        poll_body["scopes"] = scopes
    elif scope_profile:
        poll_body["scope_profile"] = scope_profile

    deadline = time.monotonic() + expires_in
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))
        try:
            poll = requests.post(
                f"{app_url}/api/v1/cli/login/poll",
                json=poll_body,
                timeout=_HTTP_TIMEOUT_S,
                allow_redirects=False,
            )
        except requests.RequestException:
            continue
        if 200 <= poll.status_code < 300:
            return _finish_login(
                console,
                app_url,
                poll,
                scopes=scopes,
                scope_profile=scope_profile,
                workspace=workspace,
            )
        delta = _handle_poll_error(poll)
        if delta is None:
            break
        interval = min(interval + delta, _MAX_POLL_INTERVAL_S)

    raise PlatformAuthError("the sign-in request expired. Run `strix cloud login` again.")


def _handle_poll_error(poll: requests.Response) -> int | None:
    """Return the interval increase, or None when the device code expired."""
    error = ""
    with contextlib.suppress(ValueError, AttributeError):
        error = str(poll.json().get("error", ""))
    if error == "authorization_pending":
        return 0
    if error == "slow_down":
        return 5
    if error == "access_denied":
        raise PlatformAuthError("the sign-in request was denied in the browser")
    if error == "expired_token":
        return None
    raise PlatformAuthError(_error_detail(poll))


def _finish_login(
    console: Console,
    app_url: str,
    poll: requests.Response,
    *,
    scopes: list[str] | None,
    scope_profile: str | None,
    workspace: str | None,
) -> dict[str, Any]:
    result = _json_object(poll)
    if result.get("selection_required"):
        return _complete_selection(
            console,
            app_url,
            result,
            scopes=scopes,
            scope_profile=scope_profile,
            workspace=workspace,
        )
    return _bind_login_record(_require_api_token(result), app_url)


def _signed_in_record(
    response: requests.Response,
    *,
    app_url: str,
) -> dict[str, Any]:
    return _bind_login_record(
        _require_api_token(_json_object(response)),
        app_url,
    )


def _require_api_token(record: dict[str, Any]) -> dict[str, Any]:
    api_token = record.get("api_token")
    if not isinstance(api_token, str) or not api_token.strip():
        raise PlatformAuthError("the server returned a sign-in response without an API token")
    return record


def _bind_login_record(record: dict[str, Any], app_url: str) -> dict[str, Any]:
    """Bind a stored credential to its issuer and preserve its scope preference."""
    parsed = urlsplit(app_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\\" in app_url
        or any(character.isspace() for character in app_url)
        or "%" in parsed.netloc
    ):
        raise PlatformAuthError("the configured platform URL is invalid")
    bound = dict(record)
    bound["app_url"] = urlunsplit(
        (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/"), "", "")
    )
    preference: Any = record.get("requested_scopes", record.get("scopes"))
    preference_items = cast("list[Any]", preference)
    if isinstance(preference, list) and all(isinstance(scope, str) for scope in preference_items):
        bound["requested_scopes"] = list(dict.fromkeys(cast("list[str]", preference_items)))
    return bound


def _complete_selection(
    console: Console,
    app_url: str,
    selection: dict[str, Any],
    *,
    scopes: list[str] | None,
    scope_profile: str | None,
    workspace: str | None,
) -> dict[str, Any]:
    organizations = _dict_items(selection.get("organizations"))
    catalog = _dict_items(selection.get("scopes"))
    selection_token = str(selection.get("selection_token") or "")
    if not selection_token or not organizations:
        raise PlatformAuthError("the server returned an incomplete selection response")

    chosen_org = _choose_workspace(console, organizations, workspace)
    role = str(chosen_org.get("role") or "admin")
    chosen_scopes = scopes
    chosen_profile = scope_profile
    if chosen_scopes is None and chosen_profile is None and sys.stdin.isatty():
        chosen_profile, chosen_scopes = _choose_scopes(console, catalog, role)

    body: dict[str, Any] = {
        "selection_token": selection_token,
        "organization_id": chosen_org.get("id"),
    }
    if chosen_scopes is not None:
        body["scopes"] = chosen_scopes
        body["scope_profile"] = "custom"
    elif chosen_profile is not None:
        body["scope_profile"] = chosen_profile
    try:
        response = requests.post(
            f"{app_url}/api/v1/cli/login/complete",
            json=body,
            timeout=_HTTP_TIMEOUT_S,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise PlatformAuthError(f"could not reach {app_url}: {exc}") from exc
    if not 200 <= response.status_code < 300:
        raise PlatformAuthError(_error_detail(response))
    return _signed_in_record(
        response,
        app_url=app_url,
    )


def _dict_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items = cast("list[Any]", cast("Any", value))
    return [cast("dict[str, Any]", cast("Any", item)) for item in items if isinstance(item, dict)]


def _choose_workspace(
    console: Console, organizations: list[dict[str, Any]], workspace: str | None
) -> dict[str, Any]:
    if workspace is not None:
        wanted = workspace.strip().casefold()
        by_id = [org for org in organizations if str(org.get("id", "")).casefold() == wanted]
        if by_id:
            return by_id[0]
        by_name = [
            org for org in organizations if str(org.get("name", "")).strip().casefold() == wanted
        ]
        if len(by_name) == 1:
            return by_name[0]
        if len(by_name) > 1:
            matching_ids = ", ".join(str(org.get("id", "")) for org in by_name)
            raise PlatformAuthError(
                f"multiple workspaces are named {workspace!r}; use an exact workspace ID: "
                f"{matching_ids}"
            )
        names = ", ".join(str(org.get("name", "")) for org in organizations)
        raise PlatformAuthError(f"no workspace matches {workspace!r}. Your workspaces: {names}")
    if len(organizations) == 1:
        return organizations[0]
    if not sys.stdin.isatty():
        choices = ", ".join(f"{org.get('name', '')} ({org.get('id', '')})" for org in organizations)
        raise PlatformAuthError(
            "more than one workspace is available; rerun with --workspace NAME_OR_ID. "
            f"Available workspaces: {choices}"
        )

    console.print()
    console.print("[bold]Select a workspace for the API token:[/]")
    for index, org in enumerate(organizations, start=1):
        name = _terminal_markup(org.get("name", ""))
        org_role = _terminal_markup(org.get("role", ""))
        console.print(f"  [cyan]{index}[/]. {name} [dim]({org_role})[/]")
    while True:
        answer = console.input(f"Workspace [1-{len(organizations)}] (1): ").strip() or "1"
        if answer.isdigit() and 1 <= int(answer) <= len(organizations):
            return organizations[int(answer) - 1]
        console.print("[yellow]Enter a number from the list.[/]")


def _choose_scopes(
    console: Console, catalog: list[dict[str, Any]], role: str
) -> tuple[str, list[str] | None]:
    """Prompt for a named scope profile or a custom scope list."""
    rank = _ROLE_RANK.get(role, 2)
    allowed = [
        item for item in catalog if _ROLE_RANK.get(str(item.get("min_role", "viewer")), 0) <= rank
    ]
    if not allowed:
        return "recommended", None

    console.print()
    console.print("[bold]Select token scopes:[/]")
    console.print(
        "  [cyan]1[/]. Recommended [dim](scans, findings, schedules, assets, uploads, "
        "workspace switching, billing/top-ups; no token creation)[/]"
    )
    console.print("  [cyan]2[/]. Full access [dim](every scope your role allows)[/]")
    console.print("  [cyan]3[/]. Minimal [dim](scan read/write and billing read)[/]")
    console.print("  [cyan]4[/]. Custom [dim](pick individual scopes)[/]")
    while True:
        answer = console.input("Scopes [1-4] (1): ").strip() or "1"
        if answer == "1":
            return "recommended", None
        if answer == "2":
            return "full", None
        if answer == "3":
            return "minimal", None
        if answer == "4":
            return "custom", _choose_custom_scopes(console, allowed)
        console.print("[yellow]Enter a number from 1 to 4.[/]")


def _choose_custom_scopes(console: Console, allowed: list[dict[str, Any]]) -> list[str]:
    selected = {
        str(item["scope"])
        for item in allowed
        if item.get("scope") and (item.get("default") or item.get("minimum"))
    }
    while True:
        console.print()
        for index, item in enumerate(allowed, start=1):
            scope = str(item.get("scope", ""))
            mark = "[green]x[/]" if scope in selected else " "
            required = " [dim](always included)[/]" if item.get("minimum") else ""
            rendered_scope = _terminal_markup(scope)
            description = _terminal_markup(item.get("description", ""))
            console.print(
                f"  [{mark}] [cyan]{index:>2}[/]. {rendered_scope}{required}"
                f"\n         [dim]{description}[/]"
            )
        answer = console.input(
            "Toggle scopes by number (comma separated), or press Enter to confirm: "
        ).strip()
        if not answer:
            return sorted(selected)
        for part in answer.replace(",", " ").split():
            if not part.isdigit() or not 1 <= int(part) <= len(allowed):
                console.print(
                    f"[yellow]Ignored {_terminal_markup(part)!r}: not a number from the list.[/]"
                )
                continue
            item = allowed[int(part) - 1]
            scope = str(item.get("scope", ""))
            if item.get("minimum"):
                console.print(f"[yellow]{_terminal_markup(scope)} is always included.[/]")
                continue
            if scope in selected:
                selected.discard(scope)
            else:
                selected.add(scope)


def _json_object(response: requests.Response) -> dict[str, Any]:
    try:
        data = response.json()
    except ValueError as exc:
        raise PlatformAuthError("the server returned a response that is not JSON") from exc
    if not isinstance(data, dict):
        raise PlatformAuthError("the server returned an unexpected response shape")
    return cast("dict[str, Any]", data)


def _as_positive_int(value: Any, *, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if parsed <= 0:
        return default
    return min(parsed, maximum)


def _error_detail(response: requests.Response) -> str:
    with contextlib.suppress(ValueError, AttributeError):
        detail = response.json().get("detail")
        if detail:
            return str(detail)
    return f"HTTP {response.status_code}"


def _session_headers(record: dict[str, Any]) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {record['api_token']}"}
    workspace_id = record.get("organization_id")
    if isinstance(workspace_id, str) and workspace_id:
        headers["X-Strix-Workspace"] = workspace_id
    return headers


def _revoke_stored_session(record: dict[str, Any]) -> tuple[bool, str | None]:
    """Revoke one server session; return (definitively_inactive, error)."""
    app_url = record.get("app_url")
    if not isinstance(app_url, str) or not app_url:
        return False, (
            "the stored sign-in has no trusted platform URL; use --local-only to remove it"
        )
    try:
        response = requests.delete(
            f"{app_url.rstrip('/')}/api/v1/cli/session",
            headers=_session_headers(record),
            timeout=_HTTP_TIMEOUT_S,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        return False, f"could not revoke the remote CLI session: {exc}"
    if response.status_code in {200, 204, 401}:
        return True, None
    return False, f"could not revoke the remote CLI session: {_error_detail(response)}"


def _print_logout_failure(console: Console, message: str, *, as_json: bool) -> int:
    if as_json:
        sys.stdout.write(json.dumps({"error": message, "removed": False}) + "\n")
    else:
        console.print(f"[red]Sign-out failed:[/] {_terminal_markup(message)}")
        console.print("[dim]The local token was kept so you can safely retry.[/]")
    return 1


def _revoke_replaced_legacy_session(
    previous: dict[str, Any] | None, current: dict[str, Any]
) -> None:
    """Best-effort cleanup when the first device-aware login replaces a legacy token."""
    if not previous or previous.get("api_token") == current.get("api_token"):
        return
    if previous.get("app_url") != current.get("app_url"):
        return
    with contextlib.suppress(KeyError, requests.RequestException):
        requests.delete(
            f"{previous['app_url']}/api/v1/cli/session",
            headers=_session_headers(previous),
            timeout=_HTTP_TIMEOUT_S,
            allow_redirects=False,
        )


def _print_success(console: Console, record: dict[str, Any]) -> None:
    email = record.get("email", "")
    organization = record.get("organization_name") or record.get("organization_id", "")
    console.print()
    console.print("[green]✓ Signed in to the Strix platform.[/]")
    if email:
        console.print(f"  Account:   [bold]{_terminal_markup(email)}[/]")
    if organization:
        console.print(f"  Workspace: [bold]{_terminal_markup(organization)}[/]")
    scopes = record.get("scopes")
    if isinstance(scopes, list) and scopes:
        console.print(f"  Access:    [dim]{_terminal_markup(_scope_summary(record))}[/]")
    console.print(f"  Token:     stored in [dim]{_terminal_markup(AUTH_PATH)}[/]")
    console.print()
    console.print(
        "[dim]The managed platform is ready. Run `strix cloud` to list the commands. "
        "See https://docs.app.strix.ai for the API reference.[/]"
    )


def _status(console: Console, argv: list[str]) -> int:  # noqa: PLR0912
    parser = _SessionArgumentParser(
        prog="strix cloud whoami",
        description="Show the stored managed-platform account, workspace, scopes, and expiry.",
    )
    parser.add_argument("--json", action="store_true", help="Print the session as JSON.")
    parser.add_argument("--show-scopes", action="store_true", help="Print every granted scope.")
    as_json = "--json" in argv or not sys.stdout.isatty()
    try:
        args = parser.parse_args(argv)
    except _SessionUsageError as exc:
        if as_json:
            sys.stdout.write(json.dumps({"error": str(exc)}) + "\n")
        else:
            console.print(f"[red]Error:[/] {_terminal_markup(exc)}")
        return 2
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    as_json = bool(args.json) or not sys.stdout.isatty()
    record = read_record()
    if record is None:
        if as_json:
            sys.stdout.write(json.dumps({"signed_in": False, "error": "Not signed in"}) + "\n")
            return 1
        console.print("[yellow]Not signed in.[/] Run [bold]strix cloud login[/] to sign in.")
        return 1
    email = record.get("email", "unknown")
    organization = record.get("organization_name") or record.get("organization_id", "")
    expires_at = record.get("expires_at", "")
    if as_json:
        payload = {
            "signed_in": True,
            "email": email,
            "organization_id": record.get("organization_id"),
            "organization_name": record.get("organization_name"),
            "scopes": record.get("scopes", []),
            "expires_at": expires_at or None,
            **({"app_url": record["app_url"]} if record.get("app_url") else {}),
        }
        sys.stdout.write(json.dumps(payload, indent=2, default=str) + "\n")
        return 0
    console.print(f"[green]Signed in[/] as [bold]{_terminal_markup(email)}[/]")
    if organization:
        console.print(f"  Workspace: {_terminal_markup(organization)}")
    if expires_at:
        console.print(f"  Token expires: {_terminal_markup(expires_at)}")
    if record.get("app_url"):
        console.print(f"  Platform: {_terminal_markup(record['app_url'])}")
    scopes = record.get("scopes")
    if isinstance(scopes, list) and scopes:
        scope_items = cast("list[Any]", cast("Any", scopes))
        if args.show_scopes:
            console.print(
                f"  Scopes: {_terminal_markup(' '.join(str(scope) for scope in scope_items))}"
            )
        else:
            console.print(f"  Access: {_terminal_markup(_scope_summary(record))}")
    return 0


def _scope_summary(record: dict[str, Any]) -> str:
    scopes = record.get("scopes")
    scope_items = cast("list[Any]", cast("Any", scopes)) if isinstance(scopes, list) else []
    count = len(scope_items)
    profile = str(record.get("scope_profile") or "custom").replace("_", " ").title()
    return f"{profile} · {count} scope{'s' if count != 1 else ''} granted"


def _logout(console: Console, argv: list[str]) -> int:  # noqa: PLR0911, PLR0912
    parser = _SessionArgumentParser(
        prog="strix cloud logout",
        description="Revoke this CLI session and remove its token from this machine.",
    )
    parser.add_argument("--json", action="store_true", help="Print the result as JSON.")
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="Remove only the local token, leaving the remote session active.",
    )
    as_json = "--json" in argv or not sys.stdout.isatty()
    try:
        args = parser.parse_args(argv)
    except _SessionUsageError as exc:
        if as_json:
            sys.stdout.write(json.dumps({"error": str(exc)}) + "\n")
        else:
            console.print(f"[red]Error:[/] {_terminal_markup(exc)}")
        return 2
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    as_json = bool(args.json) or not sys.stdout.isatty()
    if read_record() is None and not AUTH_PATH.exists():
        if as_json:
            sys.stdout.write(json.dumps({"signed_in": False, "removed": False}) + "\n")
            return 0
        console.print("[yellow]Not signed in.[/]")
        return 0
    record = read_record()
    remotely_revoked = False
    if record is not None and not args.local_only:
        remotely_revoked, revoke_error = _revoke_stored_session(record)
        if revoke_error:
            return _print_logout_failure(console, revoke_error, as_json=as_json)

    if not logout():
        if as_json:
            sys.stdout.write(
                json.dumps(
                    {
                        "error": "Could not remove the stored API token",
                        "signed_in": True,
                        "removed": False,
                    }
                )
                + "\n"
            )
            return 1
        console.print(
            f"[red]Could not remove the stored API token.[/] Delete "
            f"{_terminal_markup(AUTH_PATH)} manually."
        )
        return 1
    if as_json:
        sys.stdout.write(
            json.dumps(
                {
                    "signed_in": False,
                    "removed": True,
                    "remotely_revoked": remotely_revoked,
                    "local_only": bool(args.local_only),
                }
            )
            + "\n"
        )
        return 0
    if args.local_only:
        console.print(
            "[yellow]Local sign-out only.[/] The remote CLI session is still active; "
            "revoke it from API Access if needed."
        )
    else:
        console.print("[green]Signed out.[/] The CLI session was revoked and removed locally.")
    return 0
