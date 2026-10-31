"""`strix cloud workspaces use` — switch the stored token to another workspace.

The command lists the workspaces of the account, finds the requested one by
ID or by exact name, asks the platform to rotate that token in place, and
stores the returned workspace metadata. The bearer secret and expiry stay the
same; the account's role in the target workspace limits the granted scopes.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, cast

from rich.console import Console
from rich.markup import escape

import strix.interface.cloud.http as http  # noqa: PLR0402
from strix.interface.cloud.arguments import CloudArgumentParser
from strix.interface.cloud.render import emit, json_mode
from strix.interface.platform_cli import AUTH_PATH, read_record, save_record
from strix.interface.platform_identity import read_or_create_identity
from strix.interface.terminal_text import sanitize_terminal_text


if TYPE_CHECKING:
    import argparse


def run_workspace_use(argv: list[str]) -> int:
    """Entry point for ``strix cloud workspaces use``. Returns an exit code."""
    console = Console()
    parser = CloudArgumentParser(
        prog="strix cloud workspaces use",
        description="Switch the stored API token to another workspace.",
    )
    parser.add_argument(
        "workspace",
        metavar="WORKSPACE",
        help="Workspace number from `workspaces list`, ID, or exact name.",
    )
    scope_mode = parser.add_mutually_exclusive_group()
    scope_mode.add_argument(
        "--scopes",
        nargs="+",
        metavar="SCOPE",
        default=None,
        help=(
            "Use a custom scope set within the login-approved ceiling. "
            "Without this option, preserve the server-side scope preference."
        ),
    )
    scope_mode.add_argument(
        "--scope-profile",
        choices=("minimal", "recommended", "full"),
        default=None,
        help="Change to a profile within the authority approved at login.",
    )
    parser.add_argument("--show-scopes", action="store_true", help="Print every granted scope.")
    parser.add_argument("--json", action="store_true", help="Print the raw JSON response.")
    parser.add_argument("--token", default=None, help="API token override.")
    parser.add_argument(
        "--workspace-id",
        default=None,
        metavar="ORG_ID",
        help="Expected workspace for an override CLI token.",
    )
    parser.add_argument("--app-url", default=None, metavar="URL", help="Platform URL override.")
    parser.add_argument(
        "--timeout", default=None, type=float, metavar="SECONDS", help="Request timeout in seconds."
    )
    as_json = json_mode(flag="--json" in argv)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except http.CloudError as exc:
        _emit_cloud_error(console, exc, as_json=as_json)
        return exc.exit_code

    as_json = json_mode(flag=bool(args.json))
    try:
        http.configure(
            base_url=args.app_url,
            timeout=args.timeout,
            token_override=bool(args.token),
            workspace_id=args.workspace_id,
        )
        return _use(console, args, as_json=as_json)
    except http.CloudError as exc:
        _emit_cloud_error(console, exc, as_json=as_json)
        return exc.exit_code


def _use(  # noqa: PLR0912, PLR0915
    console: Console, args: argparse.Namespace, *, as_json: bool
) -> int:
    workspace = _find_workspace(args.workspace, token=args.token)
    stored_record: dict[str, Any] = read_record() or {}
    # An override token may belong to a different account. Never mix its new
    # workspace state with identity or scope preferences from the stored sign-in.
    external_token = args.token is not None or bool(os.environ.get("STRIX_API_TOKEN", "").strip())
    record: dict[str, Any] = {} if external_token else dict(stored_record)
    body: dict[str, Any] = {}
    if args.scopes:
        body["scopes"] = args.scopes
        body["scope_profile"] = "custom"
    elif args.scope_profile:
        body["scope_profile"] = args.scope_profile
    if not external_token:
        try:
            body.update(read_or_create_identity())
        except (OSError, ValueError) as exc:
            raise http.CloudError(f"could not load the CLI device identity: {exc}") from exc
    switched = _switch_workspace_token(
        str(workspace["id"]),
        token=args.token,
        body=body or None,
    )
    if not isinstance(switched, dict):
        raise _workspace_switch_unknown("the platform returned an invalid response")
    switched_record = cast("dict[str, Any]", switched)
    switched_token = switched_record.get("api_token")
    if not isinstance(switched_token, str) or not switched_token.strip():
        raise _workspace_switch_unknown("the platform response omitted the token")
    switched_scopes = switched_record.get("scopes")
    switched_scope_items = cast("list[Any]", cast("Any", switched_scopes))
    if not isinstance(switched_scopes, list) or not all(
        isinstance(scope, str) for scope in switched_scope_items
    ):
        raise _workspace_switch_unknown("the platform response contained invalid scopes")
    validated_scopes = cast("list[str]", switched_scope_items)

    record.update(
        {
            "api_token": switched_token,
            "organization_id": switched_record.get("organization_id", workspace["id"]),
            "organization_name": switched_record.get(
                "organization_name", workspace.get("name", "")
            ),
            "expires_at": switched_record.get("expires_at") or stored_record.get("expires_at"),
            "scopes": validated_scopes,
            "requested_scopes": switched_record.get("requested_scopes", validated_scopes),
            "scope_ceiling": switched_record.get("scope_ceiling", []),
            "scope_profile": switched_record.get("scope_profile", "custom"),
            "token_id": switched_record.get("token_id"),
            "credential_source": switched_record.get("credential_source", "api"),
            "device_name": switched_record.get("device_name"),
            "app_url": http.app_url(),
        }
    )
    if switched_record.get("email"):
        record["email"] = switched_record["email"]
    if not external_token:
        try:
            save_record(record)
        except OSError as exc:
            raise http.CloudError(
                "the platform switched the token, but the local workspace metadata could not be "
                f"stored in {AUTH_PATH}: {exc}. The bearer is still valid; fix the file and safely "
                "rerun the same workspace use command.",
                payload={
                    "workspace_switched": True,
                    "local_record_updated": False,
                    "retry_safe": True,
                },
            ) from exc

    result = {
        "workspace_id": record["organization_id"],
        "workspace_name": record["organization_name"],
        "scopes": record["scopes"],
        "requested_scopes": record.get("requested_scopes", record["scopes"]),
        "scope_ceiling": record.get("scope_ceiling", []),
        "scope_profile": record.get("scope_profile", "custom"),
        "expires_at": record.get("expires_at"),
        "token_id": record.get("token_id"),
        "credential_source": record.get("credential_source", "api"),
        "device_name": record.get("device_name"),
        "stored": not external_token,
    }
    if as_json:
        emit(console, result, as_json=True)
        return http.EXIT_OK
    workspace_name = escape(sanitize_terminal_text(record["organization_name"]))
    console.print(f"[green]✓ Switched to workspace [bold]{workspace_name}[/].[/]")
    scopes = record.get("scopes")
    if isinstance(scopes, list) and scopes:
        scope_items = cast("list[Any]", cast("Any", scopes))
        scope_names = [scope for scope in scope_items if isinstance(scope, str)]
        if scope_names and args.show_scopes:
            rendered_scopes = escape(sanitize_terminal_text(" ".join(scope_names)))
            console.print(f"  Scopes: [dim]{rendered_scopes}[/]")
        elif scope_names:
            profile = str(record.get("scope_profile") or "custom").title()
            console.print(f"  Access: [dim]{profile} · {len(scope_names)} scopes granted[/]")
    if external_token:
        console.print("  Token:  [dim]override used for this command only; not stored[/]")
    else:
        console.print(f"  Token:  stored in [dim]{escape(sanitize_terminal_text(AUTH_PATH))}[/]")
    return http.EXIT_OK


def _switch_workspace_token(
    workspace_id: str,
    *,
    token: str | None,
    body: dict[str, Any] | None,
) -> Any:
    """Switch in place, distinguishing definitive rejections from lost outcomes."""
    try:
        response = http.request(
            "POST",
            f"/workspaces/{workspace_id}/token",
            token=token,
            body=body,
        )
    except http.CloudError as exc:
        raise _workspace_switch_unknown(str(exc)) from exc

    # Client/auth/conflict responses prove the rotation did not return success.
    # A 5xx or malformed success may arrive after the database commit, but the
    # server preserves the bearer so replaying this exact command is safe.
    if response.status_code in {400, 401, 403, 404, 409, 422}:
        return http.check(response)
    try:
        return http.check(response)
    except http.CloudError as exc:
        raise _workspace_switch_unknown(str(exc)) from exc


def _workspace_switch_unknown(detail: str) -> http.CloudError:
    return http.CloudError(
        "workspace switch outcome is unknown: "
        f"{sanitize_terminal_text(detail)}. The bearer secret is unchanged; safely rerun the "
        "same workspace use command, or list workspaces to check the current one.",
        payload={
            "switch_outcome_unknown": True,
            "retry_safe": True,
        },
    )


def _emit_cloud_error(console: Console, error: http.CloudError, *, as_json: bool) -> None:
    if as_json:
        raw_payload: Any = error.payload
        error_payload = cast("dict[str, Any]", raw_payload)
        payload = dict(error_payload) if isinstance(raw_payload, dict) else {}
        payload["error"] = str(error)
        emit(console, payload, as_json=True)
        return
    console.print(f"[red]Error:[/] {escape(sanitize_terminal_text(error))}")


def _find_workspace(selector: str, *, token: str | None) -> dict[str, Any]:
    listed = http.check(http.request("GET", "/workspaces", token=token))
    listed_record = cast("dict[str, Any]", listed) if isinstance(listed, dict) else {}
    items = listed_record.get("workspaces")
    item_values = cast("list[Any]", cast("Any", items)) if isinstance(items, list) else []
    workspaces = [
        cast("dict[str, Any]", cast("Any", item)) for item in item_values if isinstance(item, dict)
    ]
    if not workspaces:
        raise http.CloudError("no workspaces found for this account.")
    wanted = selector.strip()
    if wanted.isdigit():
        index = int(wanted)
        if 1 <= index <= len(workspaces):
            return workspaces[index - 1]
        raise http.CloudError(
            f"workspace number must be between 1 and {len(workspaces)}. "
            "Run `strix cloud workspaces` to see the numbered list."
        )
    by_id = [w for w in workspaces if w.get("id") == wanted]
    if by_id:
        return by_id[0]
    by_name = [w for w in workspaces if str(w.get("name", "")).casefold() == wanted.casefold()]
    if len(by_name) == 1:
        return by_name[0]
    if len(by_name) > 1:
        numbers = ", ".join(
            str(index)
            for index, workspace in enumerate(workspaces, start=1)
            if workspace in by_name
        )
        raise http.CloudError(
            f"multiple workspaces are named {wanted!r}. Use its list number: {numbers}"
        )
    names = ", ".join(
        f"{index}: {workspace.get('name')}" for index, workspace in enumerate(workspaces, start=1)
    )
    raise http.CloudError(f"no workspace matches {wanted!r}. Your workspaces: {names}")
