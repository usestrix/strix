"""Generic command runner for `strix cloud`.

The runner turns one entry of the command table into an argument parser,
sends the HTTP request, renders the result, and returns the exit code.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import tempfile
import time
import webbrowser
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import quote
from uuid import uuid4

import requests
from rich.console import Console
from rich.markup import escape

import strix.interface.cloud.http as http  # noqa: PLR0402
from strix.interface.cloud.arguments import CloudArgumentParser
from strix.interface.cloud.billing import run_topup
from strix.interface.cloud.render import emit, json_mode
from strix.interface.cloud.source_scan import LocalSourceScan
from strix.interface.cloud.spec import DEFAULT_VERBS, SPEC, Cmd, P
from strix.interface.terminal_text import sanitize_terminal_text
from strix.interface.url_safety import is_safe_web_url


if TYPE_CHECKING:
    from collections.abc import Iterator


_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_WAIT_POLL_S = 15
_DEFAULT_WAIT_TIMEOUT_S = 4 * 60 * 60
_TERMINAL_STATUSES = frozenset(
    {
        "completed",
        "failed",
        "cancelled",
        "canceled",
        "stopped",
        "error",
        "expired",
        "succeeded",
    }
)
_DEFINITIVE_SCAN_REJECTION_STATUSES = frozenset({400, 401, 402, 403, 404, 409, 413, 415, 422})
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/=-]{0,199}$")
_IDEMPOTENCY_RETRY_DELAYS_S = (0.25, 1.0)
_RETRYABLE_IDEMPOTENCY_CODES = frozenset(
    {"idempotency_request_in_progress", "idempotency_outcome_unknown"}
)


def _dest(name: str) -> str:
    return _CAMEL_BOUNDARY.sub("_", name).lower()


def _metavar(name: str) -> str:
    return _CAMEL_BOUNDARY.sub("_", name).upper()


def _positive_seconds(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number greater than 0") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than 0")
    return parsed


def _resolve_idempotency_key(cmd: Cmd, args: argparse.Namespace) -> str | None:
    if not cmd.idempotent:
        return None
    supplied = getattr(args, "idempotency_key", None)
    key = supplied if isinstance(supplied, str) else str(uuid4())
    if not _IDEMPOTENCY_KEY.fullmatch(key):
        raise http.CloudError(
            "--idempotency-key must be 1-200 characters, start with a letter or digit, and "
            "contain only letters, digits, '.', '_', ':', '/', '=', or '-'.",
            exit_code=http.EXIT_USAGE,
        )
    return key


def _audit_export_format(cmd: Cmd, query: dict[str, Any]) -> str | None:
    if cmd.method != "GET" or cmd.path != "/audit":
        return None
    value = query.get("format")
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if normalized in {"csv", "ndjson", "jsonl", "snowflake", "splunk"} else None


def _contains_response_key(value: Any, keys: frozenset[str], *, depth: int = 0) -> bool:
    if depth > 2:
        return False
    if isinstance(value, dict):
        fields = cast("dict[str, Any]", value)
        if any(key in fields and fields[key] not in (None, "") for key in keys):
            return True
        return any(_contains_response_key(item, keys, depth=depth + 1) for item in fields.values())
    return False


def _one_time_secret_warning(cmd: Cmd, args: argparse.Namespace, result: Any) -> str | None:
    if (
        cmd.method == "POST"
        and cmd.path == "/tokens"
        and _contains_response_key(result, frozenset({"token", "api_token", "secret"}))
    ):
        return "This API token is shown only once. Store it securely before leaving this output."
    if cmd.path.startswith("/webhooks") and _contains_response_key(
        result, frozenset({"secret", "signing_secret", "webhook_secret"})
    ):
        return (
            "This webhook signing secret is shown only once. Store it securely before leaving "
            "this output."
        )
    connector_command_requested = cmd.method == "POST" or bool(
        getattr(args, "include_command", False)
    )
    if (
        cmd.path.startswith("/connectors")
        and connector_command_requested
        and _contains_response_key(
            result, frozenset({"command", "enrollment_command", "docker_command", "token"})
        )
    ):
        return (
            "This connector enrollment command contains one-time credentials. Store it securely "
            "and do not share it."
        )
    return None


def resolve(group: str, tokens: list[str]) -> tuple[Cmd, list[str]] | None:
    """Find the command for a verb. Two-word verbs match before one-word verbs."""
    commands = SPEC.get(group)
    if commands is None:
        return None
    if len(tokens) >= 2:
        two = f"{tokens[0]} {tokens[1]}"
        if two in commands:
            return commands[two], tokens[2:]
    if tokens and tokens[0] in commands:
        return commands[tokens[0]], tokens[1:]
    default = DEFAULT_VERBS.get(group)
    if default is not None and (not tokens or tokens[0].startswith("-")):
        return commands[default], tokens
    return None


def run(group: str, verb_label: str, cmd: Cmd, argv: list[str]) -> int:
    console = Console()
    parser = _build_parser(group, verb_label, cmd)
    as_json = json_mode(flag="--json" in argv)
    raw_binary_stdout = _argv_uses_raw_binary_stdout(cmd, argv)
    try:
        args = parser.parse_args(argv)
    except KeyboardInterrupt:
        _emit_interrupted(console, as_json=as_json, to_stderr=raw_binary_stdout)
        return 130
    except http.CloudError as exc:
        _emit_error(
            console,
            exc,
            as_json=as_json and not raw_binary_stdout,
            to_stderr=raw_binary_stdout,
        )
        return exc.exit_code
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    path = cmd.path
    for name in _PLACEHOLDER.findall(cmd.path):
        value = quote(str(getattr(args, _dest(name))), safe="")
        path = path.replace("{" + name + "}", value)

    as_json = json_mode(flag=bool(getattr(args, "json", False)))
    raw_binary_stdout = _uses_raw_binary_stdout(cmd, args)
    token = getattr(args, "token", None)
    try:
        http.configure(
            base_url=getattr(args, "app_url", None),
            timeout=getattr(args, "timeout", None),
            token_override=bool(token),
            workspace_id=getattr(args, "workspace_id", None),
        )
        query = _collect(args, cmd.query)
        body = _collect(args, cmd.body)
        data = getattr(args, "data", None)
        if data:
            _merge_extra_body(body, _load_data(data))
        _validate_body(cmd, body)
        if getattr(args, "no_monthly_cap", False):
            body["monthly_cap_credits"] = None
        return _execute(console, cmd, args, path, query, body, as_json=as_json, token=token)
    except KeyboardInterrupt:
        _emit_interrupted(console, as_json=as_json, to_stderr=raw_binary_stdout)
        return 130
    except http.CloudError as exc:
        _emit_error(
            console,
            exc,
            as_json=as_json and not raw_binary_stdout,
            to_stderr=raw_binary_stdout,
        )
        return exc.exit_code


def _uses_raw_binary_stdout(cmd: Cmd, args: argparse.Namespace) -> bool:
    if bool(getattr(args, "json", False)) or getattr(args, "output", None):
        return False
    format_value = str(getattr(args, "format", "") or "").strip().lower()
    audit_export = (
        cmd.method == "GET"
        and cmd.path == "/audit"
        and format_value
        in {
            "csv",
            "ndjson",
            "jsonl",
            "snowflake",
            "splunk",
        }
    )
    return not sys.stdout.isatty() and bool(cmd.binary or audit_export)


def _argv_uses_raw_binary_stdout(cmd: Cmd, argv: list[str]) -> bool:
    """Choose the error channel before argparse can reject a binary command."""
    if "--json" in argv or any(arg.startswith("--json=") for arg in argv):
        return False
    has_output = any(
        (arg.startswith("--output=") and bool(arg.partition("=")[2]))
        or (arg == "--output" and index + 1 < len(argv) and not argv[index + 1].startswith("-"))
        for index, arg in enumerate(argv)
    )
    if has_output:
        return False
    format_value = ""
    for index, arg in enumerate(argv):
        if arg.startswith("--format="):
            format_value = arg.partition("=")[2]
        elif arg == "--format" and index + 1 < len(argv):
            format_value = argv[index + 1]
    audit_export = (
        cmd.method == "GET"
        and cmd.path == "/audit"
        and format_value.lower()
        in {
            "csv",
            "ndjson",
            "jsonl",
            "snowflake",
            "splunk",
        }
    )
    return not sys.stdout.isatty() and bool(cmd.binary or audit_export)


def _request_with_idempotency(
    cmd: Cmd,
    path: str,
    *,
    token: str | None,
    query: dict[str, Any],
    body: dict[str, Any],
    stream: bool,
    idempotency_key: str | None,
) -> requests.Response:
    """Retry only exact, caller-keyed mutations whose outcome may be ambiguous."""
    attempts = 1 + (len(_IDEMPOTENCY_RETRY_DELAYS_S) if idempotency_key else 0)
    for attempt in range(attempts):
        try:
            response = http.request(
                cmd.method,
                path,
                token=token,
                query=query or None,
                body=body if cmd.method in ("POST", "PUT", "PATCH") else None,
                stream=stream,
                idempotency_key=idempotency_key,
            )
        except http.CloudTransportError:
            if attempt + 1 >= attempts:
                raise
        else:
            if attempt + 1 >= attempts or not _idempotency_response_is_retryable(response):
                return response
            response.close()
        time.sleep(_IDEMPOTENCY_RETRY_DELAYS_S[attempt])
    raise AssertionError("idempotent request retry loop exhausted without returning")


def _idempotency_response_is_retryable(response: requests.Response) -> bool:
    if 500 <= response.status_code < 600 or response.status_code == 429:
        return True
    if response.status_code != 409:
        return False
    payload = http.parsed(response)
    if not isinstance(payload, dict):
        return False
    fields = cast("dict[str, Any]", payload)
    return fields.get("retry_safe") is True or fields.get("code") in _RETRYABLE_IDEMPOTENCY_CODES


def _scan_rejection_is_definitive(response: requests.Response) -> bool:
    payload = http.parsed(response)
    if isinstance(payload, dict):
        fields = cast("dict[str, Any]", payload)
        if fields.get("retry_safe") is True:
            return False
        if fields.get("terminal") is True:
            return True
    return response.status_code in _DEFINITIVE_SCAN_REJECTION_STATUSES


def _execute(  # noqa: PLR0912, PLR0915
    console: Console,
    cmd: Cmd,
    args: argparse.Namespace,
    path: str,
    query: dict[str, Any],
    body: dict[str, Any],
    *,
    as_json: bool,
    token: str | None,
) -> int:
    if cmd.path == "/billing/topup":
        return run_topup(console, args, body, as_json=as_json, token=token)
    audit_export = _audit_export_format(cmd, query)
    output_path = getattr(args, "output", None)
    explicit_json = bool(getattr(args, "json", False))
    binary_response = bool(cmd.binary or audit_export)
    if binary_response and explicit_json and not output_path:
        raise http.CloudError(
            "--json for a binary response requires --output FILE; omit --json only when "
            "intentionally redirecting the raw bytes.",
            exit_code=http.EXIT_USAGE,
        )
    binary_json_metadata = explicit_json or bool(output_path and not sys.stdout.isatty())
    if cmd.path == "/audit" and getattr(args, "output", None) and not audit_export:
        raise http.CloudError(
            "--output requires --format csv, ndjson, jsonl, snowflake, or splunk.",
            exit_code=http.EXIT_USAGE,
        )
    idempotency_key = _resolve_idempotency_key(cmd, args)
    source_workflow = LocalSourceScan(idempotency_key=idempotency_key)
    scan_request_started = False
    try:
        if cmd.path == "/scans" and cmd.method == "POST":
            _set_default_scan_engagement(
                body,
                has_local_source=getattr(args, "source", None) is not None,
            )
            if source_workflow.prepare_and_attach(
                console,
                args,
                body,
                as_json=as_json,
                token=token,
            ):
                return http.EXIT_OK

        source_workflow.mark_launch_started()
        # Every wait-path mutation creates a scan, even when the endpoint has
        # not yet adopted idempotency keys (for example vulnerability retests).
        # Once sent, transport and malformed-success failures are ambiguous.
        scan_request_started = cmd.idempotent or cmd.wait_path is not None
        response = _request_with_idempotency(
            cmd,
            path,
            token=token,
            query=query,
            body=body,
            stream=bool(cmd.binary or audit_export),
            idempotency_key=idempotency_key,
        )
    except BaseException as exc:
        source_workflow.handle_request_failure(exc, token=token)
        if scan_request_started:
            if isinstance(exc, KeyboardInterrupt):
                raise _interrupted_scan_launch_error(idempotency_key) from None
            if isinstance(exc, Exception):
                raise _ambiguous_scan_launch_error(exc, idempotency_key) from exc
        raise
    finally:
        source_workflow.close()
    if audit_export:
        return _emit_binary(
            console,
            response,
            output_path,
            force=bool(getattr(args, "force", False)),
            json_metadata=binary_json_metadata,
        )
    if cmd.binary:
        return _emit_binary(
            console,
            response,
            output_path,
            force=bool(getattr(args, "force", False)),
            json_metadata=binary_json_metadata,
        )
    try:
        result = _validated_operation_result(http.check(response), cmd)
    except BaseException as exc:
        source_workflow.handle_response_failure(
            exc,
            definitive=_scan_rejection_is_definitive(response),
            token=token,
        )
        if (
            source_workflow.upload_id is None
            and scan_request_started
            and not _scan_rejection_is_definitive(response)
            and isinstance(exc, Exception)
        ):
            raise _ambiguous_scan_launch_error(exc, idempotency_key) from exc
        raise
    if getattr(args, "wait", False):
        wait_timeout = cast("float", getattr(args, "wait_timeout", _DEFAULT_WAIT_TIMEOUT_S))
        try:
            if cmd.wait_self:
                result = _poll(
                    console,
                    path,
                    token=token,
                    as_json=as_json,
                    wait_timeout=wait_timeout,
                )
            elif cmd.wait_path:
                result = _wait(
                    console,
                    cmd,
                    result,
                    token=token,
                    as_json=as_json,
                    wait_timeout=wait_timeout,
                )
        except KeyboardInterrupt:
            raise _wait_status_error(result, interrupted=True) from None
        except http.CloudError as exc:
            raise _wait_status_error(result, error=exc) from exc
    result = source_workflow.wrap_result(result, args)
    if cmd.link:
        return _handoff_link(console, cmd, args, result, as_json=as_json)
    workspace_list = cmd.method == "GET" and cmd.path == "/workspaces"
    integration_list = cmd.method == "GET" and cmd.path == "/integrations"
    emit(
        console,
        result,
        as_json=as_json,
        row_numbers=workspace_list or integration_list,
        omit_columns=frozenset({"id"}) if workspace_list else frozenset(),
        hint=(
            "Switch with `strix cloud workspaces use NUMBER`."
            if workspace_list
            else (
                "For Git providers, disconnect with `strix cloud integrations disconnect "
                "PROVIDER --installation-id INSTALLATION_ID`; omit the ID for Slack."
                if integration_list
                else None
            )
        ),
        view=f"{cmd.method} {cmd.path}",
        warning=_one_time_secret_warning(cmd, args, result),
    )
    return http.EXIT_OK


def _set_default_scan_engagement(body: dict[str, Any], *, has_local_source: bool = False) -> None:
    """Infer the scan type from its targets when the caller did not choose one."""
    if body.get("engagement_type"):
        return
    if body.get("internal_targets"):
        body["engagement_type"] = "internal_infra"
    elif body.get("domain_ids"):
        body["engagement_type"] = "live_test"
    elif has_local_source or body.get("repository_ids") or body.get("upload_ids"):
        body["engagement_type"] = "code_review"


def _validate_body(cmd: Cmd, body: dict[str, Any]) -> None:
    missing = [
        "--" + (param.flag or param.name.replace("_", "-"))
        for param in cmd.body
        if param.required and body.get(param.name) is None
    ]
    if missing:
        raise http.CloudError(
            "missing required request field(s): "
            + ", ".join(missing)
            + ". Supply them as options or with --data @file/-.",
            exit_code=http.EXIT_USAGE,
        )
    if (
        cmd.method == "POST"
        and cmd.path == "/tokens"
        and body.get("expires_at") is not None
        and body.get("expires_in_days") is not None
    ):
        raise http.CloudError(
            "--expires-at and --expires-in-days are mutually exclusive.",
            exit_code=http.EXIT_USAGE,
        )


def _handoff_link(
    console: Console, cmd: Cmd, args: argparse.Namespace, result: Any, *, as_json: bool
) -> int:
    """Print a hosted URL a person must open, and open the browser when interactive."""
    fields = cast("dict[str, Any]", result) if isinstance(result, dict) else {}
    url = fields.get(cmd.link) if cmd.link else None
    if not isinstance(url, str) or not url:
        raise http.CloudError(
            f"the platform response did not include the expected {cmd.link or 'continuation'} URL."
        )
    if not is_safe_web_url(url, trusted_origin=http.app_url()):
        raise http.CloudError("the platform returned an invalid continuation URL.")
    interactive = (
        not as_json
        and sys.stdin.isatty()
        and sys.stdout.isatty()
        and not getattr(args, "no_browser", False)
    )
    if as_json:
        emit(console, result, as_json=True)
    else:
        console.print("Open this URL to continue:")
        console.print(f"  {sanitize_terminal_text(url)}", markup=False, soft_wrap=True)
    if interactive:
        webbrowser.open(url)
    return http.EXIT_OK


def _load_data(value: str) -> dict[str, Any]:
    """Read a JSON object from a literal string, a `@file` path, or `-` for stdin."""
    if value == "-":
        text = sys.stdin.read()
    elif value.startswith("@"):
        path = Path(value[1:]).expanduser()
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise http.CloudError(f"could not read {path}: {exc}") from exc
    else:
        text = value
    try:
        parsed_value = json.loads(text)
    except ValueError as exc:
        raise http.CloudError("--data must be a JSON object.", exit_code=http.EXIT_USAGE) from exc
    if not isinstance(parsed_value, dict):
        raise http.CloudError("--data must be a JSON object.", exit_code=http.EXIT_USAGE)
    return cast("dict[str, Any]", parsed_value)


def _merge_extra_body(body: dict[str, Any], extra_body: dict[str, Any]) -> None:
    collisions = sorted(body.keys() & extra_body.keys())
    if collisions:
        flags = ", ".join(f"--{name.replace('_', '-')}" for name in collisions)
        raise http.CloudError(
            f"--data cannot override explicit option(s): {flags}",
            exit_code=http.EXIT_USAGE,
        )
    body.update(extra_body)


def _build_parser(group: str, verb_label: str, cmd: Cmd) -> argparse.ArgumentParser:
    parser = CloudArgumentParser(prog=f"strix cloud {group} {verb_label}", description=cmd.help)
    for name in _PLACEHOLDER.findall(cmd.path):
        parser.add_argument(_dest(name), metavar=_metavar(name))
    for param in cmd.query:
        _add_option(parser, param, required=param.required)
    for param in cmd.body:
        # Required body fields may be supplied securely through --data @file/-;
        # validate them only after the two body sources are merged.
        _add_option(parser, param, required=False)
    json_help = "Print the raw JSON response."
    if cmd.binary:
        json_help = "With --output, print structured download metadata as JSON."
    elif cmd.path == "/audit":
        json_help = "Print JSON results, or download metadata when exporting with --output."
    parser.add_argument("--json", action="store_true", help=json_help)
    parser.add_argument("--token", default=None, help="API token override.")
    parser.add_argument(
        "--workspace-id",
        default=None,
        metavar="ORG_ID",
        help="Expected workspace for an override CLI token (or STRIX_WORKSPACE_ID).",
    )
    parser.add_argument("--app-url", default=None, metavar="URL", help="Platform URL override.")
    parser.add_argument(
        "--timeout",
        default=None,
        type=_positive_seconds,
        metavar="SECONDS",
        help="Request timeout in seconds.",
    )
    if cmd.method in ("POST", "PUT", "PATCH"):
        parser.add_argument(
            "--data",
            default=None,
            metavar="JSON",
            help="JSON object with extra request fields. Use @file to read a file, or - for stdin.",
        )
    _add_idempotency_option(parser, cmd)
    if cmd.path == "/billing/auto-topup" and cmd.method == "PUT":
        parser.add_argument(
            "--no-monthly-cap",
            action="store_true",
            help="Remove the monthly cap. Omit this flag to keep the stored cap.",
        )
    if cmd.binary or cmd.path == "/audit":
        output_help = (
            "Write the CSV or NDJSON-compatible export to this file."
            if cmd.path == "/audit" and not cmd.binary
            else "Write to this file."
        )
        parser.add_argument("--output", default=None, metavar="FILE", help=output_help)
        parser.add_argument(
            "--force",
            action="store_true",
            help="Replace --output if it already exists.",
        )
    if cmd.link:
        parser.add_argument(
            "--no-browser",
            action="store_true",
            help="Do not open the browser. Print the URL only.",
        )
    if cmd.wait_path or cmd.wait_self:
        parser.add_argument(
            "--wait", action="store_true", help="Wait until the operation reaches a final state."
        )
        parser.add_argument(
            "--wait-timeout",
            type=_positive_seconds,
            default=float(_DEFAULT_WAIT_TIMEOUT_S),
            metavar="SECONDS",
            help=(
                "Maximum total time to wait before returning an error "
                f"(default: {_DEFAULT_WAIT_TIMEOUT_S})."
            ),
        )
    if cmd.path == "/billing/topup":
        payment_mode = parser.add_mutually_exclusive_group()
        payment_mode.add_argument(
            "--yes",
            action="store_true",
            help=(
                "Explicitly authorize payment without a TTY prompt. Required in "
                "non-interactive mode."
            ),
        )
        payment_mode.add_argument(
            "--no-pay",
            action="store_true",
            help="Print the payment challenge instead of paying it.",
        )
        parser.add_argument(
            "--payment-method",
            default=None,
            metavar="PM_ID",
            help=(
                "Pay with the mppx wallet client and this Stripe payment method "
                "instead of the Stripe Link wallet. Defaults to "
                "MPPX_STRIPE_PAYMENT_METHOD."
            ),
        )
    if cmd.path == "/scans" and cmd.method == "POST":
        parser.add_argument(
            "--source",
            default=None,
            metavar="DIRECTORY",
            help="Package a local directory, upload it, and attach it to this scan.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Build and print the source manifest without uploading or starting a scan.",
        )
        source_approval = parser.add_mutually_exclusive_group()
        source_approval.add_argument(
            "--yes",
            action="store_true",
            help="Approve the source snapshot built by this invocation without a prompt.",
        )
        source_approval.add_argument(
            "--approve-sha256",
            default=None,
            metavar="SHA256",
            help=(
                "Upload only if the archive exactly matches this --dry-run SHA-256 digest. "
                "Best for agent and CI approval handoffs."
            ),
        )
        parser.add_argument(
            "--show-files",
            action="store_true",
            help="Include every selected relative path in the source manifest.",
        )
        parser.add_argument(
            "--exclude",
            action="append",
            default=[],
            metavar="GLOB",
            help="Exclude a path glob from the upload. May be repeated.",
        )
        parser.add_argument(
            "--include-hidden",
            action="store_true",
            help="Include hidden files except .git and secret-like filenames.",
        )
        parser.add_argument(
            "--include-sensitive",
            action="store_true",
            help="Include files with secret-like names. Use only after reviewing --dry-run.",
        )
        parser.add_argument(
            "--include-archives",
            action="store_true",
            help="Include nested archives. Use only when they are required source inputs.",
        )
    return parser


def _add_idempotency_option(parser: argparse.ArgumentParser, cmd: Cmd) -> None:
    if not cmd.idempotent:
        return
    parser.add_argument(
        "--idempotency-key",
        default=None,
        metavar="KEY",
        help=(
            "Stable key for an exact retry after an ambiguous response. A fresh UUID is "
            "generated when omitted; never reuse a key for a different request."
        ),
    )


def _wait_status_error(
    result: Any,
    *,
    error: http.CloudError | None = None,
    interrupted: bool = False,
) -> http.CloudError:
    operation_id = _created_id(result)
    suffix = f" Operation ID: {operation_id}." if operation_id else ""
    prefix = (
        "Interrupted while waiting"
        if interrupted
        else f"Waiting for the remote operation failed: {error}"
    )
    message = (
        f"{prefix}; the remote operation may still be running.{suffix} "
        "Check its status before retrying."
    )
    payload: dict[str, Any] = {
        "error": message,
        "status_unknown": True,
    }
    if interrupted:
        payload["interrupted"] = True
    if operation_id:
        payload["operation_id"] = operation_id
    return http.CloudError(
        message,
        exit_code=130 if interrupted else (error.exit_code if error else http.EXIT_ERROR),
        payload=payload,
    )


def _interrupted_scan_launch_error(idempotency_key: str | None = None) -> http.CloudError:
    retry_note = _idempotency_retry_note(idempotency_key)
    message = (
        "Interrupted while starting the scan. The launch outcome is unknown; check "
        f"`strix cloud scans list` before retrying.{retry_note}"
    )
    payload: dict[str, Any] = {
        "error": message,
        "interrupted": True,
        "launch_outcome_unknown": True,
    }
    _attach_idempotency_recovery(payload, idempotency_key)
    return http.CloudError(
        message,
        exit_code=130,
        payload=payload,
    )


def _ambiguous_scan_launch_error(
    error: Exception, idempotency_key: str | None = None
) -> http.CloudError:
    retry_note = _idempotency_retry_note(idempotency_key)
    message = (
        f"{error} The scan launch outcome is unknown; check `strix cloud scans list` before "
        f"retrying to avoid a duplicate scan or charge.{retry_note}"
    )
    payload: dict[str, Any] = {
        "error": message,
        "launch_outcome_unknown": True,
    }
    exit_code = http.EXIT_ERROR
    if isinstance(error, http.CloudError):
        exit_code = error.exit_code
        raw_payload: Any = error.payload
        error_payload = cast("dict[str, Any]", raw_payload)
        if isinstance(raw_payload, dict):
            payload.update(error_payload)
            payload["error"] = message
    _attach_idempotency_recovery(payload, idempotency_key)
    return http.CloudError(message, exit_code=exit_code, payload=payload)


def _idempotency_retry_note(idempotency_key: str | None) -> str:
    if not idempotency_key:
        return ""
    return (
        f" An exact retry is safe with the same request and `--idempotency-key {idempotency_key}`."
    )


def _attach_idempotency_recovery(payload: dict[str, Any], idempotency_key: str | None) -> None:
    if not idempotency_key:
        return
    payload.update(
        {
            "idempotency_key": idempotency_key,
            "retry_safe": True,
            "retry_same_request": True,
        }
    )


def _add_option(parser: argparse.ArgumentParser, param: P, *, required: bool) -> None:
    flag = "--" + (param.flag or param.name.replace("_", "-"))
    if param.kind == "bool":
        parser.add_argument(
            flag,
            dest=param.name,
            action=argparse.BooleanOptionalAction,
            default=None,
            required=required,
            help=param.help,
        )
    elif param.kind == "list":
        parser.add_argument(
            flag,
            dest=param.name,
            nargs="+",
            default=None,
            required=required,
            help=param.help,
        )
    elif param.kind in ("int", "float"):
        parser.add_argument(
            flag,
            dest=param.name,
            type=int if param.kind == "int" else float,
            default=None,
            required=required,
            help=param.help,
        )
    else:
        parser.add_argument(flag, dest=param.name, default=None, required=required, help=param.help)


def _collect(args: argparse.Namespace, params: tuple[P, ...]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for param in params:
        value = getattr(args, param.name, None)
        if value is None:
            continue
        if param.kind in ("json", "json-list") and isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError as exc:
                raise http.CloudError(
                    f"--{param.name.replace('_', '-')} must be JSON",
                    exit_code=http.EXIT_USAGE,
                ) from exc
        if param.kind == "json-list" and not isinstance(value, list):
            raise http.CloudError(
                f"--{param.name.replace('_', '-')} must be a JSON array",
                exit_code=http.EXIT_USAGE,
            )
        values[param.name] = value
    return values


def _emit_binary(
    console: Console,
    response: Any,
    output: str | None,
    *,
    force: bool = False,
    json_metadata: bool = False,
) -> int:
    try:
        if not 200 <= response.status_code < 300:
            http.check(response)
        if output:
            return _write_binary_file(
                console,
                response,
                Path(output).expanduser(),
                force=force,
                as_json=json_metadata,
            )
        if sys.stdout.isatty():
            raise http.CloudError(
                "binary responses require --output FILE when stdout is a terminal; "
                "redirect stdout only when intentionally piping the bytes.",
                exit_code=http.EXIT_USAGE,
            )
        output_stream: Any = getattr(sys.stdout, "buffer", None)
        try:
            for chunk in _response_chunks(response):
                if output_stream is not None:
                    output_stream.write(chunk)
                else:
                    sys.stdout.write(chunk.decode("utf-8"))
        except (OSError, UnicodeDecodeError, requests.RequestException) as exc:
            raise http.CloudError(f"could not write the response to stdout: {exc}") from exc
        return http.EXIT_OK
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            with suppress(Exception):
                close()


def _write_binary_file(
    console: Console, response: Any, path: Path, *, force: bool, as_json: bool
) -> int:
    if path.exists() and not force:
        raise http.CloudError(
            f"refusing to replace existing file {path}; pass --force to overwrite it."
        )
    temporary: Path | None = None
    bytes_written = 0
    try:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=path.parent,
                delete=False,
            ) as stream:
                temporary = Path(stream.name)
                for chunk in _response_chunks(response):
                    stream.write(chunk)
                    bytes_written += len(chunk)
        except (OSError, requests.RequestException) as exc:
            raise http.CloudError(f"could not write {path}: {exc}") from exc

        try:
            if force:
                temporary.replace(path)
            else:
                os.link(temporary, path)
                temporary.unlink()
        except FileExistsError as exc:
            raise http.CloudError(
                f"refusing to replace existing file {path}; pass --force to overwrite it."
            ) from exc
        except OSError as exc:
            raise http.CloudError(f"could not write {path}: {exc}") from exc

        if as_json:
            content_type = str(getattr(response, "headers", {}).get("content-type", ""))
            emit(
                console,
                {
                    "output": str(path),
                    "bytes": bytes_written,
                    **({"content_type": content_type} if content_type else {}),
                },
                as_json=True,
                view="binary_download",
            )
        else:
            console.print("Saved to:")
            console.print(sanitize_terminal_text(path), markup=False, soft_wrap=True)
        return http.EXIT_OK
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _response_chunks(response: Any) -> Iterator[bytes]:
    iter_content = getattr(response, "iter_content", None)
    if callable(iter_content):
        chunks = cast("Iterator[bytes]", iter_content(chunk_size=1024 * 1024))
        for chunk in chunks:
            if chunk:
                yield bytes(chunk)
        return
    content = getattr(response, "content", b"")
    if content:
        yield bytes(content)


def _emit_error(
    console: Console, exc: http.CloudError, *, as_json: bool, to_stderr: bool = False
) -> None:
    if as_json:
        raw_payload: Any = exc.payload
        error_payload = cast("dict[str, Any]", raw_payload)
        if isinstance(raw_payload, dict):
            payload = dict(error_payload)
            payload.setdefault("error", str(exc))
            if payload.get("detail") == payload.get("error"):
                payload.pop("detail", None)
        else:
            payload = {"error": str(exc)}
            if exc.payload is not None:
                payload["detail"] = exc.payload
        if exc.next_step:
            payload["next_step"] = exc.next_step
        sys.stdout.write(json.dumps(payload, indent=2, default=str) + "\n")
        return
    target = Console(stderr=True) if to_stderr else console
    target.print(f"[red]Error:[/] {escape(sanitize_terminal_text(exc))}")
    if exc.next_step:
        target.print(f"[yellow]Next step:[/] {escape(sanitize_terminal_text(exc.next_step))}")


def _emit_interrupted(console: Console, *, as_json: bool, to_stderr: bool) -> None:
    if as_json and not to_stderr:
        sys.stdout.write(json.dumps({"error": "Interrupted.", "interrupted": True}) + "\n")
        return
    target = Console(stderr=True) if to_stderr else console
    target.print("[yellow]Interrupted.[/]")


def _created_id(created: Any) -> str | None:
    """Read the identifier of a created item. The API names it `id` or `<resource>_id`."""
    if not isinstance(created, dict):
        return None
    fields = cast("dict[str, Any]", created)
    for key, value in fields.items():
        if (key == "id" or key.endswith("_id")) and isinstance(value, str) and value.strip():
            return value
    return None


def _validated_operation_result(result: Any, cmd: Cmd) -> Any:
    """Reject malformed success bodies for mutations that create a scan."""
    if cmd.wait_path and _created_id(result) is None:
        raise http.CloudError(
            "the platform returned a successful operation response without an operation ID."
        )
    return result


def _wait(
    console: Console,
    cmd: Cmd,
    created: Any,
    *,
    token: str | None,
    as_json: bool,
    wait_timeout: float,
) -> Any:
    item_id = _created_id(created)
    if not cmd.wait_path:
        return created
    if not item_id:
        raise http.CloudError(
            "cannot wait because the platform response did not include an operation ID."
        )
    path = cmd.wait_path.replace("{id}", str(item_id))
    if not as_json:
        console.print(
            f"[dim]Waiting for {escape(sanitize_terminal_text(item_id))} to reach a final state…[/]"
        )
    return _poll(
        console,
        path,
        token=token,
        as_json=as_json,
        wait_timeout=wait_timeout,
    )


def _poll(
    console: Console,
    path: str,
    *,
    token: str | None,
    as_json: bool,
    wait_timeout: float,
) -> Any:
    """Poll a GET path until its status is final. Returns the last response."""
    deadline = time.monotonic() + wait_timeout
    while True:
        current: Any = http.check(http.request("GET", path, token=token))
        fields = cast("dict[str, Any]", current) if isinstance(current, dict) else {}
        status = str(fields.get("status", ""))
        if status.lower() in _TERMINAL_STATUSES:
            return fields if isinstance(current, dict) else current
        if not as_json:
            console.print(
                f"[dim]  status: {escape(sanitize_terminal_text(status or 'unknown'))}[/]"
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise http.CloudError(
                f"wait timed out after {wait_timeout:g} seconds; the remote operation is still "
                "running. Re-run its get command to check the status."
            )
        time.sleep(min(_WAIT_POLL_S, remaining))
