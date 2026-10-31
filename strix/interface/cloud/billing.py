"""Billing top-up and agent-wallet execution for ``strix cloud``."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import webbrowser
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import strix.interface.cloud.http as http  # noqa: PLR0402
from strix.interface.cloud.payment_proxy import WalletUpstreamResponse, wallet_payment_bridge
from strix.interface.cloud.render import emit
from strix.interface.terminal_text import sanitize_terminal_text


if TYPE_CHECKING:
    import argparse

    from rich.console import Console


_MAX_WALLET_DETAIL_CHARS = 2_000
# Keep the wallet client on the exact protocol implementation used by the
# platform. This version is also old enough to remain installable in npm
# environments that apply a short package-publication safety window.
_MPPX_PACKAGE = "mppx@0.8.17"
# Stripe's own wallet client. It runs the complete challenge flow: it creates a
# spend request, waits for the person to approve it in the Link app, and retries
# the payment with the approved credential.
_LINK_CLI_PACKAGE = "@stripe/link-cli@0.13.1"
_LINK_CLI_CLIENT_NAME = "Strix CLI"
_LINK_LOGIN_TIMEOUT_S = 300
# Poll every 2 seconds while the person approves the spend request in the Link
# app. 150 attempts give the person 5 minutes.
_LINK_APPROVAL_POLL_INTERVAL_S = 2
_LINK_APPROVAL_MAX_ATTEMPTS = 150
# Bound every wallet subprocess so a stalled npm download or wallet request
# cannot block the top-up command forever. The poll step gets the full
# approval window plus this margin.
_WALLET_STEP_TIMEOUT_S = 300
_LINK_APPROVAL_TIMEOUT_S = (
    _LINK_APPROVAL_POLL_INTERVAL_S * _LINK_APPROVAL_MAX_ATTEMPTS + _WALLET_STEP_TIMEOUT_S
)
_NPM_REGISTRY = "https://registry.npmjs.org"
_WALLET_ENV_NAMES = frozenset(
    {
        "ALL_PROXY",
        "APPDATA",
        "COLORTERM",
        "COMSPEC",
        "FORCE_COLOR",
        "HOME",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOCALAPPDATA",
        "NO_COLOR",
        "NO_PROXY",
        "PATH",
        "PATHEXT",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TERM",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "all_proxy",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)
_AUTHORIZATION_SECRET = re.compile(r"(?i)((?:bearer|payment)\s+)[^\s\"']+")
_LOOPBACK_NO_PROXY = ("127.0.0.1", "localhost", "::1")


@dataclass(frozen=True)
class _WalletClientResult:
    process: subprocess.CompletedProcess[str]
    upstream_responses: tuple[WalletUpstreamResponse, ...]


def run_topup(  # noqa: PLR0911, PLR0912, PLR0915
    console: Console,
    args: argparse.Namespace,
    body: dict[str, Any],
    *,
    as_json: bool,
    token: str | None,
) -> int:
    """Handle the HTTP 402 challenge and optional agent-wallet payment."""
    response = http.request("POST", "/billing/topup", token=token, body=body)
    if response.status_code != 402:
        emit(console, http.check(response), as_json=as_json)
        return http.EXIT_OK

    challenge = http.parsed(response)
    if getattr(args, "no_pay", False):
        emit(
            console,
            {"error": "Payment required", "challenge": challenge},
            as_json=as_json,
        )
        return http.EXIT_PAYMENT

    credit_count = body.get("credits")
    if not getattr(args, "yes", False):
        if as_json or not (sys.stdin.isatty() and sys.stdout.isatty()):
            emit(
                console,
                {
                    "error": (
                        "Payment requires explicit approval in non-interactive mode. "
                        "Review the challenge, then re-run with --yes to authorize payment."
                    ),
                    "challenge": challenge,
                },
                as_json=as_json,
            )
            return http.EXIT_PAYMENT
        answer = console.input(f"Buy {credit_count} credit(s) now? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            console.print("[yellow]Payment cancelled.[/]")
            return http.EXIT_PAYMENT

    npx = shutil.which("npx")
    if npx is None:
        message = (
            "Payment requires a wallet client. Install Node.js and run the command again, "
            "or pay the challenge with an MPP wallet client."
        )
        if as_json:
            emit(
                console,
                {"error": message, "challenge": challenge},
                as_json=True,
            )
        else:
            emit(console, challenge, as_json=False)
            console.print(f"[yellow]Payment required.[/] {message}")
        return http.EXIT_PAYMENT

    payment_method = getattr(args, "payment_method", None) or os.environ.get(
        "MPPX_STRIPE_PAYMENT_METHOD"
    )
    use_link_wallet = payment_method is None and not _mppx_wallet_configured()
    if use_link_wallet:
        setup_error = _prepare_link_wallet(console, npx, as_json=as_json)
        if setup_error is not None:
            emit(
                console,
                {"error": setup_error, "challenge": challenge},
                as_json=as_json,
            )
            return http.EXIT_PAYMENT
    try:
        wallet_result = _run_wallet_client(
            console,
            npx,
            args,
            body,
            token=token,
            payment_method=payment_method,
            use_link_wallet=use_link_wallet,
            capture_output=as_json,
        )
    except KeyboardInterrupt:
        emit(
            console,
            {
                "error": (
                    "Payment was interrupted after the wallet started. The outcome is unknown; "
                    "run `strix cloud billing credits` and check the balance before retrying."
                ),
                "interrupted": True,
                "payment_outcome_unknown": True,
            },
            as_json=as_json,
        )
        return 130
    except OSError:
        emit(
            console,
            {
                "error": "Could not start the wallet client securely.",
                "challenge": challenge,
            },
            as_json=as_json,
        )
        return http.EXIT_PAYMENT

    result = wallet_result.process
    confirmed_receipt = _confirmed_topup_receipt(wallet_result.upstream_responses)
    if confirmed_receipt is not None:
        emit(console, confirmed_receipt, as_json=as_json)
        return http.EXIT_OK

    stdout = str(getattr(result, "stdout", "") or "").strip()
    stderr = str(getattr(result, "stderr", "") or "").strip()
    if not as_json:
        console.print(
            "[yellow]The wallet exited without a confirmed receipt. The payment outcome is "
            "unknown; run `strix cloud billing credits` before retrying.[/]"
        )
        detail = _wallet_detail(stderr or stdout or "")
        if detail:
            console.print(f"[dim]Wallet output: {detail}[/]")
        return http.EXIT_PAYMENT
    if result.returncode == 0:
        try:
            receipt = json.loads(stdout)
        except (TypeError, ValueError):
            emit(
                console,
                {
                    "error": (
                        "The wallet reported success but did not return JSON. Check the credit "
                        "balance before retrying payment."
                    ),
                    "detail": _wallet_detail(stdout or stderr or "No wallet output was returned."),
                    "payment_outcome_unknown": True,
                },
                as_json=True,
            )
            return http.EXIT_PAYMENT
        if not _valid_topup_receipt(receipt):
            emit(
                console,
                {
                    "error": (
                        "The wallet returned an invalid top-up receipt. Check the credit balance "
                        "before retrying payment."
                    ),
                    "detail": _wallet_detail(stdout),
                    "payment_outcome_unknown": True,
                },
                as_json=True,
            )
            return http.EXIT_PAYMENT
        emit(
            console,
            {
                "error": (
                    "The wallet returned a receipt, but the Strix billing endpoint did not "
                    "confirm it. Check the credit balance before retrying payment."
                ),
                "detail": _wallet_detail(stdout),
                "payment_outcome_unknown": True,
            },
            as_json=True,
        )
        return http.EXIT_PAYMENT

    emit(
        console,
        {
            "error": (
                "The wallet exited without a confirmed receipt. The payment outcome is unknown; "
                "run `strix cloud billing credits` and check the balance before retrying."
            ),
            "detail": _wallet_detail(
                stderr or stdout or f"Wallet client exited with status {result.returncode}."
            ),
            "wallet_exit_code": result.returncode,
            "payment_outcome_unknown": True,
        },
        as_json=True,
    )
    return http.EXIT_PAYMENT


def _run_wallet_client(
    console: Console,
    npx: str,
    args: argparse.Namespace,
    body: dict[str, Any],
    *,
    token: str | None,
    payment_method: str | None,
    use_link_wallet: bool,
    capture_output: bool,
) -> _WalletClientResult:
    """Run the wallet through the loopback bridge without exposing the API token."""
    upstream_url = f"{http.app_url()}/api/v1/billing/topup"
    body_json = json.dumps(body)
    wallet_env = _wallet_environment()
    upstream_responses: list[WalletUpstreamResponse] = []
    with tempfile.TemporaryDirectory(prefix="strix-wallet-") as wallet_cwd:
        wallet_root = Path(wallet_cwd)
        user_config = wallet_root / "user.npmrc"
        global_config = wallet_root / "global.npmrc"
        user_config.touch(mode=0o600)
        global_config.touch(mode=0o600)
        npx_prefix = _npx_prefix(npx, wallet_root)
        with wallet_payment_bridge(
            upstream_url=upstream_url,
            api_token=http.api_token(token),
            workspace_id=http.expected_workspace_id(token_override=token is not None),
            expected_body=body_json.encode(),
            timeout=getattr(args, "timeout", None),
            response_observer=upstream_responses.append,
        ) as wallet_url:
            if use_link_wallet:
                process = _run_link_wallet_flow(
                    console,
                    npx_prefix,
                    wallet_url,
                    body,
                    body_json,
                    wallet_env,
                    wallet_root,
                    quiet=capture_output,
                )
            else:
                command = [
                    *npx_prefix,
                    _MPPX_PACKAGE,
                    wallet_url,
                    "--fail",
                    "-J",
                    body_json,
                ]
                if payment_method:
                    command += ["-M", f"paymentMethod={payment_method}"]
                try:
                    process = subprocess.run(  # noqa: S603
                        command,
                        check=False,
                        capture_output=capture_output,
                        text=True,
                        env=wallet_env,
                        cwd=wallet_root,
                        timeout=_LINK_APPROVAL_TIMEOUT_S,
                    )
                except subprocess.TimeoutExpired as timeout_error:
                    process = subprocess.CompletedProcess(
                        args=command,
                        returncode=1,
                        stdout=_decoded_stream(timeout_error.stdout),
                        stderr=(
                            "The wallet step did not complete within "
                            f"{_LINK_APPROVAL_TIMEOUT_S} seconds."
                        ),
                    )
    return _WalletClientResult(process=process, upstream_responses=tuple(upstream_responses))


def _run_link_wallet_flow(
    console: Console,
    npx_prefix: list[str],
    wallet_url: str,
    body: dict[str, Any],
    body_json: str,
    wallet_env: dict[str, str],
    wallet_root: Path,
    *,
    quiet: bool,
) -> subprocess.CompletedProcess[str]:
    """Create the spend request, wait for approval in the Link app, then pay."""

    def run_step(
        arguments: list[str],
        progress_message: str,
        timeout: int = _WALLET_STEP_TIMEOUT_S,
    ) -> subprocess.CompletedProcess[str]:
        command = [*npx_prefix, _LINK_CLI_PACKAGE, *arguments]

        def run() -> subprocess.CompletedProcess[str]:
            try:
                return subprocess.run(  # noqa: S603
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    env=wallet_env,
                    cwd=wallet_root,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired as timeout_error:
                return subprocess.CompletedProcess(
                    args=command,
                    returncode=1,
                    stdout=_decoded_stream(timeout_error.stdout),
                    stderr=f"The wallet step did not complete within {timeout} seconds.",
                )

        if quiet:
            return run()
        with console.status(progress_message):
            return run()

    created = run_step(
        [
            "mpp",
            "pay",
            wallet_url,
            "--method",
            "POST",
            "--data",
            body_json,
            "--context",
            _payment_context(body),
            "--format",
            "json",
        ],
        "Starting the Stripe Link wallet…",
    )
    spend_request = _pending_spend_request(created.stdout)
    if spend_request is None:
        return created
    request_id, approval_url = spend_request

    if not quiet:
        console.print(f"[yellow]Approve the payment in the Link app:[/] {approval_url}")
        if sys.stdin.isatty() and sys.stdout.isatty() and approval_url.startswith("https://"):
            with suppress(Exception):
                webbrowser.open(approval_url)
    polled = run_step(
        [
            "spend-request",
            "retrieve",
            request_id,
            "--interval",
            str(_LINK_APPROVAL_POLL_INTERVAL_S),
            "--max-attempts",
            str(_LINK_APPROVAL_MAX_ATTEMPTS),
            "--format",
            "jsonl",
        ],
        "Waiting for the approval in the Link app…",
        timeout=_LINK_APPROVAL_TIMEOUT_S,
    )
    if _final_spend_request_status(polled.stdout) != "approved":
        return polled

    return run_step(
        [
            "mpp",
            "pay",
            wallet_url,
            "--spend-request-id",
            request_id,
            "--method",
            "POST",
            "--data",
            body_json,
            "--format",
            "json",
        ],
        "Completing the payment…",
    )


def _decoded_stream(stream: str | bytes | None) -> str:
    """Return captured subprocess output as text."""
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode(errors="replace")
    return stream


def _embedded_json_documents(text: str) -> list[Any]:
    """Extract JSON documents from wallet output that can contain other text."""
    documents: list[Any] = []
    decoder = json.JSONDecoder()
    position = 0
    while position < len(text):
        start_candidates = [
            index for index in (text.find("[", position), text.find("{", position)) if index != -1
        ]
        if not start_candidates:
            break
        start = min(start_candidates)
        try:
            document, end = decoder.raw_decode(text, start)
        except ValueError:
            position = start + 1
            continue
        documents.append(document)
        position = end
    return documents


def _spend_request_records(stdout: str) -> list[dict[str, Any]]:
    """Parse spend-request records from JSON or JSON-lines wallet output."""
    records: list[dict[str, Any]] = []
    for candidate in _embedded_json_documents((stdout or "").strip()):
        items = candidate if isinstance(candidate, list) else [candidate]
        for item in items:
            if not isinstance(item, dict):
                continue
            record = cast("dict[str, Any]", item)
            data = record.get("data")
            if isinstance(data, dict):
                record = cast("dict[str, Any]", data)
            records.append(record)
    return records


def _pending_spend_request(stdout: str) -> tuple[str, str] | None:
    """Find a spend request that waits for approval in the Link app."""
    for record in _spend_request_records(stdout):
        request_id = record.get("id")
        approval_url = record.get("approval_url")
        if (
            record.get("status") == "pending_approval"
            and isinstance(request_id, str)
            and request_id
            and isinstance(approval_url, str)
        ):
            return request_id, approval_url
    return None


def _final_spend_request_status(stdout: str) -> str | None:
    """Return the last reported status from the approval poll output."""
    status: str | None = None
    for record in _spend_request_records(stdout):
        value = record.get("status")
        if isinstance(value, str):
            status = value
    return status


def _npx_prefix(npx: str, wallet_root: Path) -> list[str]:
    """Install the wallet client from a fixed registry without lifecycle scripts."""
    return [
        npx,
        "--yes",
        f"--registry={_NPM_REGISTRY}",
        "--ignore-scripts",
        f"--userconfig={wallet_root / 'user.npmrc'}",
        f"--globalconfig={wallet_root / 'global.npmrc'}",
        f"--cache={_wallet_npm_cache()}",
    ]


def _wallet_npm_cache() -> Path:
    """Keep one private npm cache so the pinned wallet client installs once."""
    cache = Path.home() / ".strix" / "wallet-npm-cache"
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    return cache


def _payment_context(body: dict[str, Any]) -> str:
    """Describe the purchase for the person who approves it in the Link app."""
    credits_requested = body.get("credits")
    return (
        f"Strix scan credits. The Strix command line interface asks to buy "
        f"{credits_requested} scan credit(s) for the selected Strix workspace on "
        "app.strix.ai. Strix spends the credits on managed penetration test scans "
        "that the user starts."
    )


def _mppx_wallet_configured() -> bool:
    """Report whether the person already configured the mppx wallet client."""
    return bool(os.environ.get("MPPX_ACCOUNT") or os.environ.get("MPPX_STRIPE_SECRET_KEY"))


def _run_link_cli(
    npx: str,
    arguments: list[str],
    *,
    capture_output: bool,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one Stripe Link wallet command in an isolated npm environment."""
    with tempfile.TemporaryDirectory(prefix="strix-wallet-") as wallet_cwd:
        wallet_root = Path(wallet_cwd)
        (wallet_root / "user.npmrc").touch(mode=0o600)
        (wallet_root / "global.npmrc").touch(mode=0o600)
        return subprocess.run(  # noqa: S603
            [*_npx_prefix(npx, wallet_root), _LINK_CLI_PACKAGE, *arguments],
            check=False,
            capture_output=capture_output,
            text=True,
            env=_wallet_environment(),
            cwd=wallet_root,
            timeout=timeout,
        )


def _link_wallet_authenticated(npx: str) -> bool:
    """Report whether a Link wallet is already connected to this machine."""
    try:
        result = _run_link_cli(
            npx,
            ["auth", "status", "--format", "json"],
            capture_output=True,
            timeout=_LINK_LOGIN_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    try:
        payload = json.loads(result.stdout or "null")
    except (TypeError, ValueError):
        return False
    if isinstance(payload, list):
        payload = payload[0] if payload else None
    return bool(isinstance(payload, dict) and payload.get("authenticated"))


def _prepare_link_wallet(console: Console, npx: str, *, as_json: bool) -> str | None:
    """Connect a Link wallet when none is present. Return an error message on failure."""
    if _link_wallet_authenticated(npx):
        return None

    manual_setup = (
        "Payment needs a Stripe Link wallet. Run `strix cloud billing topup` in an "
        "interactive terminal to connect one, or set up the wallet at "
        "https://link.com/agents. For a browser checkout instead, run "
        "`strix cloud billing subscribe --plan strix_top_up`."
    )
    if as_json or not (sys.stdin.isatty() and sys.stdout.isatty()):
        return manual_setup

    console.print(
        "[yellow]No Stripe Link wallet is connected.[/] Strix starts the Link sign-in now. "
        "Approve the connection in the Link app, then Strix continues the payment. "
        "The user approves every payment in the Link app."
    )
    try:
        _run_link_cli(
            npx,
            [
                "auth",
                "login",
                "--client-name",
                _LINK_CLI_CLIENT_NAME,
                "--interval",
                "3",
                "--timeout",
                str(_LINK_LOGIN_TIMEOUT_S),
            ],
            capture_output=False,
            timeout=_LINK_LOGIN_TIMEOUT_S + 30,
        )
    except (OSError, subprocess.SubprocessError):
        return manual_setup
    if _link_wallet_authenticated(npx):
        return None
    return manual_setup


def _wallet_environment() -> dict[str, str]:
    """Pass only platform essentials and explicit wallet variables to npm/mppx."""
    environment = {
        name: value
        for name, value in os.environ.items()
        if name in _WALLET_ENV_NAMES or name.startswith(("LINK_", "MPPX_"))
    }
    for name in ("NO_PROXY", "no_proxy"):
        entries = [entry.strip() for entry in environment.get(name, "").split(",") if entry.strip()]
        normalized = {entry.lower().strip("[]") for entry in entries}
        entries.extend(host for host in _LOOPBACK_NO_PROXY if host not in normalized)
        environment[name] = ",".join(entries)
    return environment


def _wallet_detail(value: str) -> str:
    """Bound and redact third-party wallet diagnostics before returning JSON."""
    redacted = _AUTHORIZATION_SECRET.sub(r"\1[redacted]", sanitize_terminal_text(value))
    if len(redacted) <= _MAX_WALLET_DETAIL_CHARS:
        return redacted
    return redacted[: _MAX_WALLET_DETAIL_CHARS - 1] + "…"


def _valid_topup_receipt(value: Any) -> bool:
    """Require the documented success shape before reporting a paid top-up."""
    if not isinstance(value, dict):
        return False
    fields = cast("dict[str, Any]", value)
    credits_granted = fields.get("credits_granted")
    balance = fields.get("balance")
    return (
        isinstance(credits_granted, int)
        and not isinstance(credits_granted, bool)
        and credits_granted >= 0
        and isinstance(fields.get("duplicate"), bool)
        and isinstance(fields.get("reference"), str)
        and bool(fields["reference"])
        and isinstance(balance, int)
        and not isinstance(balance, bool)
        and balance >= 0
    )


def _confirmed_topup_receipt(
    responses: tuple[WalletUpstreamResponse, ...],
) -> dict[str, Any] | None:
    """Return a receipt only when the trusted bridge observed its successful response."""
    for response in reversed(responses):
        if not 200 <= response.status_code < 300:
            continue
        try:
            receipt = json.loads(response.body)
        except (TypeError, ValueError):
            continue
        if _valid_topup_receipt(receipt):
            return cast("dict[str, Any]", receipt)
    return None
