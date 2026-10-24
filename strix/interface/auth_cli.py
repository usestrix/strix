"""`strix auth` — sign-in for ChatGPT subscriptions and Microsoft Entra ID.

``login chatgpt`` stores ChatGPT OAuth tokens (``~/.strix/subscription-auth.json``);
a ``chatgpt/<model>`` STRIX_LLM then runs on the subscription. ``login entra``
stores an Entra ID user sign-in (``~/.strix/entra-auth.json``) that Anthropic
Workload Identity Federation uses as its identity token. ``status`` and
``logout`` cover both providers. ``test`` runs one Anthropic federation exchange
with the identity token source a scan would use.
"""

from __future__ import annotations

import argparse
import base64
import logging
import os
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import anthropic_wif, apply_config_override, codex, entra_user, load_settings


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)

_CALLBACK_TIMEOUT_S = 300

# CLI-facing name for the login provider. Internally this is the Codex OAuth
# flow (``codex.PROVIDER``), but users know it as ChatGPT, so that's what the
# command and messaging say. ``codex`` is accepted as an alias.
LOGIN_PROVIDER = "chatgpt"
_ACCEPTED_PROVIDERS = frozenset({LOGIN_PROVIDER, codex.PROVIDER})
ENTRA_PROVIDER = entra_user.PROVIDER

_USAGE = (
    "Usage:\n"
    "  strix auth login chatgpt [--manual]\n"
    "  strix auth login entra [--manual] [--tenant ID] [--app ID]\n"
    "  strix auth status\n"
    "  strix auth logout\n"
    "  strix auth test [--config PATH]   test Anthropic Workload Identity Federation"
)


def run_auth(argv: list[str]) -> int:
    """Entry point for ``strix auth …``. Returns a process exit code."""
    console = Console()
    # Bare `strix auth` (no subcommand) defaults to login.
    subcommand = argv[0] if argv else "login"
    rest = argv[1:]

    if subcommand in ("-h", "--help", "help"):
        console.print(_USAGE)
        return 0

    handlers: dict[str, Callable[[], int]] = {
        "login": lambda: _login(console, rest),
        "status": lambda: _status(console),
        "logout": lambda: _logout(console),
        "test": lambda: _test(console, rest),
    }
    handler = handlers.get(subcommand)
    if handler is not None:
        return handler()

    console.print(f"[red]Unknown auth command:[/] {subcommand}\n")
    console.print(_USAGE)
    return 2


def _login(console: Console, argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="strix auth login", add_help=True)
    parser.add_argument(
        "provider",
        nargs="?",
        default=LOGIN_PROVIDER,
        help="Provider to sign in with: chatgpt (default) or entra.",
    )
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Skip the local callback server and paste the redirect URL by hand.",
    )
    parser.add_argument(
        "--tenant", help="Entra tenant ID (entra only; default: STRIX_ENTRA_TENANT_ID)."
    )
    parser.add_argument(
        "--app",
        help="Entra app registration (client) ID (entra only; default: STRIX_ENTRA_APP_ID).",
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse already printed the message
        return int(exc.code or 2)

    if args.provider.lower() == ENTRA_PROVIDER:
        return _login_entra(console, args)
    if args.provider.lower() not in _ACCEPTED_PROVIDERS:
        console.print(
            f"[red]Unsupported provider:[/] {args.provider}. "
            f"Use '{LOGIN_PROVIDER}' (ChatGPT subscription) or '{ENTRA_PROVIDER}' "
            "(Microsoft Entra ID, for Anthropic Workload Identity Federation)."
        )
        return 2

    verifier, challenge = codex.generate_pkce()
    state = codex.create_state()
    authorize_url = codex.build_authorize_url(challenge, state)

    console.print()
    console.print("[bold]Signing in with ChatGPT[/] [dim](provider: chatgpt)[/]")
    console.print(
        "[dim]This uses your ChatGPT Plus/Pro plan for inference instead of a metered API key.[/]"
    )
    console.print()

    try:
        record = _run_oauth_flow(console, authorize_url, verifier, state, manual=args.manual)
    except codex.CodexAuthError as exc:
        return _fail(console, exc)
    except KeyboardInterrupt:
        console.print("\n[yellow]Sign-in cancelled.[/]")
        return 130

    codex.save_record(record)
    _print_success(console)
    return 0


def _login_entra(console: Console, args: argparse.Namespace) -> int:
    default_tenant, default_app = entra_user.configured_ids()
    tenant = (args.tenant or default_tenant or "").strip()
    app = (args.app or default_app or "").strip()
    if not tenant or not app:
        console.print(
            "[red]Missing Entra IDs.[/] Pass [cyan]--tenant[/] and [cyan]--app[/], or set "
            "[cyan]STRIX_ENTRA_TENANT_ID[/] and [cyan]STRIX_ENTRA_APP_ID[/]."
        )
        return 2

    verifier, challenge = codex.generate_pkce()
    state = codex.create_state()
    authorize_url = entra_user.build_authorize_url(tenant, app, challenge, state)

    console.print()
    console.print("[bold]Signing in with Microsoft Entra ID[/] [dim](provider: entra)[/]")
    console.print(
        "[dim]Anthropic Workload Identity Federation will exchange this sign-in for "
        "short-lived Anthropic tokens.[/]"
    )
    if os.environ.get("SSH_CONNECTION") and not args.manual:
        console.print(
            "[yellow]Over SSH:[/] the browser can't reach this host's localhost. Re-run with "
            f"[cyan]--manual[/], or tunnel port {entra_user.CALLBACK_PORT} "
            f"([cyan]ssh -L {entra_user.CALLBACK_PORT}:127.0.0.1:{entra_user.CALLBACK_PORT} …[/])."
        )
    console.print()

    try:
        record = _run_oauth_flow(
            console,
            authorize_url,
            verifier,
            state,
            manual=args.manual,
            exchange=lambda code, code_verifier: entra_user.exchange_code(
                tenant, app, code, code_verifier
            ),
            port=entra_user.CALLBACK_PORT,
            path=entra_user.CALLBACK_PATH,
            account_label="your Microsoft Entra ID account",
        )
    except (codex.CodexAuthError, entra_user.EntraAuthError) as exc:
        return _fail(console, exc)
    except KeyboardInterrupt:
        console.print("\n[yellow]Sign-in cancelled.[/]")
        return 130

    entra_user.save_record(record)
    _print_entra_success(console, record)
    return 0


def _run_oauth_flow(
    console: Console,
    authorize_url: str,
    verifier: str,
    state: str,
    *,
    manual: bool,
    exchange: Callable[[str, str], dict[str, Any]] | None = None,
    port: int = codex.CALLBACK_PORT,
    path: str = codex.CALLBACK_PATH,
    account_label: str = "your ChatGPT subscription",
) -> dict[str, Any]:
    """Drive the browser (or manual) OAuth flow and return a token record.

    ``exchange(code, verifier)`` redeems the code; it defaults to the ChatGPT one.
    """
    server = None if manual else _try_start_callback_server(port, path, account_label)

    console.print("Open this URL in your browser to authorize:")
    # soft_wrap: no hard line breaks inside the URL, so it copies as one piece.
    console.print(f"[cyan]{authorize_url}[/]", soft_wrap=True)
    console.print()
    if not manual:
        try:
            webbrowser.open(authorize_url)
        except Exception:  # noqa: BLE001 - opening a browser is best-effort
            logger.debug("could not open browser", exc_info=True)

    if server is not None:
        console.print("[dim]Waiting for you to finish signing in…[/]")
        result = server.wait(_CALLBACK_TIMEOUT_S)
        server.shutdown()
        if result is not None:
            code, returned_state, error = result
            if error:
                raise codex.CodexAuthError("oauth_error", error)
            return _finish(
                code, returned_state, verifier, state, require_state=True, exchange=exchange
            )
        console.print("[yellow]Timed out waiting for the browser. Falling back to manual paste.[/]")

    # Manual fallback: the user completes sign-in and pastes the redirect URL
    # (the browser lands on a localhost page that won't load if no server is up;
    # the address bar still holds the code+state).
    console.print()
    try:
        pasted = console.input("Paste the full redirect URL (or code#state): ").strip()
    except EOFError as exc:
        raise codex.CodexAuthError("no_input", "no redirect URL provided") from exc
    code, returned_state = codex.parse_redirect_input(pasted)
    return _finish(code, returned_state, verifier, state, require_state=False, exchange=exchange)


def _finish(
    code: str | None,
    returned_state: str | None,
    verifier: str,
    expected_state: str,
    *,
    require_state: bool,
    exchange: Callable[[str, str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not code:
        raise codex.CodexAuthError("no_code", "no authorization code found in the redirect")
    # The loopback callback from OpenAI always carries state, so a missing or
    # mismatched value there is forged (CSRF) and must be rejected. Manual paste
    # is user-initiated (the user copies their own redirect), so state is only
    # validated when the pasted value includes it.
    if require_state and returned_state is None:
        raise codex.CodexAuthError("state_mismatch", "missing state in callback; possible CSRF")
    if returned_state is not None and returned_state != expected_state:
        raise codex.CodexAuthError("state_mismatch", "state did not match; possible CSRF")
    return (exchange or codex.exchange_code)(code, verifier)


class _CallbackServer:
    """A one-shot local HTTP server that catches the OAuth redirect."""

    def __init__(self, httpd: HTTPServer, event: threading.Event, holder: dict[str, Any]) -> None:
        self._httpd = httpd
        self._event = event
        self._holder = holder
        self._thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        self._thread.start()

    def wait(self, timeout: float) -> tuple[str | None, str | None, str | None] | None:
        if not self._event.wait(timeout):
            return None
        return (
            self._holder.get("code"),
            self._holder.get("state"),
            self._holder.get("error"),
        )

    def shutdown(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def _try_start_callback_server(
    port: int = codex.CALLBACK_PORT,
    path: str = codex.CALLBACK_PATH,
    account_label: str = "your ChatGPT subscription",
) -> _CallbackServer | None:
    event = threading.Event()
    holder: dict[str, Any] = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # silence default stderr logging
            pass

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            # With a bare "/" callback path, ignore stray requests (favicon, probes)
            # that carry neither a code nor an error.
            if parsed.path != path or not ("code" in query or "error" in query):
                self.send_response(404)
                self.end_headers()
                return
            holder["code"] = _first(query, "code")
            holder["state"] = _first(query, "state")
            holder["error"] = _first(query, "error_description") or _first(query, "error")
            body = _render_callback_html(account_label).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            event.set()

    try:
        httpd = HTTPServer(("127.0.0.1", port), Handler)
    except OSError:
        logger.debug("could not bind callback port %d", port, exc_info=True)
        return None
    return _CallbackServer(httpd, event, holder)


def _first(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    return values[0] if values else None


def _status(console: Console) -> int:
    """Report every provider; exit 0 if any of them is signed in."""
    chatgpt = _status_chatgpt(console)
    console.print()
    entra = _status_entra(console)
    return 0 if chatgpt or entra else 1


def _status_chatgpt(console: Console) -> bool:
    console.print("[bold]ChatGPT subscription[/]")
    record = codex.read_record()
    if record is None:
        console.print(
            "  [yellow]Not signed in.[/] Run [cyan]strix auth login chatgpt[/] to sign in."
        )
        return False
    settings = load_settings()
    console.print("  [green]Signed in[/] with a ChatGPT subscription.")
    console.print(f"  Account: [bold]{record.get('account_id')}[/]")
    if codex.subscription_model(settings.llm.model):
        console.print(f"  Runs use the subscription (STRIX_LLM=[bold]{settings.llm.model}[/]).")
    else:
        console.print(
            "  [yellow]Note:[/] set [cyan]STRIX_LLM[/] to e.g. [cyan]chatgpt/gpt-5.4[/] "
            "to run on the subscription."
        )
    return True


def _status_entra(console: Console) -> bool:
    console.print("[bold]Microsoft Entra ID[/] [dim](Anthropic Workload Identity Federation)[/]")
    record = entra_user.read_record()
    if record is None:
        console.print("  [yellow]Not signed in.[/] Run [cyan]strix auth login entra[/] to sign in.")
        return False
    console.print(f"  [green]Signed in[/] as [bold]{record.get('username') or 'unknown user'}[/]")
    console.print(f"  Tenant: {record['tenant']}", soft_wrap=True)
    console.print(f"  App:    {record['app']}", soft_wrap=True)
    expires_at = record.get("expires_at")
    left = int(expires_at - time.time()) if isinstance(expires_at, int | float) else 0
    if left > 0:
        console.print(f"  Access token: valid for {left // 60}m (refreshed automatically)")
    else:
        console.print("  Access token: expired (refreshed on next use)")
    claims = entra_user.jwt_claims(record.get("access"))
    aud = claims.get("aud")
    console.print(f"  aud:    {'OK' if aud == record['app'] else f'[red]MISMATCH ({aud})[/]'}")
    console.print(f"  azp:    {claims.get('azp')}", soft_wrap=True)
    console.print(f"  oid:    {claims.get('oid')}", soft_wrap=True)
    console.print(f"  sub:    {claims.get('sub')}", soft_wrap=True)
    if not entra_user.is_configured():
        console.print(
            "  [yellow]Not used:[/] STRIX_ENTRA_TENANT_ID / STRIX_ENTRA_APP_ID name a different "
            "tenant or app. Sign in again or update them."
        )
    return True


def _logout(console: Console) -> int:
    """Sign out of every provider and say which ones had a stored sign-in."""
    cleared: list[str] = []
    if codex.read_record() is not None:
        cleared.append("ChatGPT subscription")
    codex.logout()
    if entra_user.logout():
        cleared.append("Microsoft Entra ID")
    if not cleared:
        console.print("Not signed in to any provider.")
        return 0
    console.print(f"[green]Signed out[/] of {' and '.join(cleared)}. Stored credentials removed.")
    if "Microsoft Entra ID" in cleared:
        console.print(
            "[dim]The Entra refresh token was deleted on this host only; revoke the user's "
            "sessions in Entra to invalidate it everywhere.[/]"
        )
    return 0


def _test(console: Console, argv: list[str]) -> int:
    """Run one Anthropic federation exchange the way a scan would, and report it.

    Prints the identity token's claims and the minted token's prefix, never a
    token value.
    """
    parser = argparse.ArgumentParser(prog="strix auth test", add_help=True)
    parser.add_argument("--config", type=Path, help="Strix config file (as for a scan)")
    args = parser.parse_args(argv)
    if args.config is not None:
        apply_config_override(args.config)

    settings = load_settings()
    wif = settings.anthropic_wif
    console.print("[bold]Anthropic Workload Identity Federation[/]")
    missing = [
        name
        for name, value in (
            ("ANTHROPIC_FEDERATION_RULE_ID", wif.federation_rule_id),
            ("ANTHROPIC_ORGANIZATION_ID", wif.organization_id),
            ("ANTHROPIC_SERVICE_ACCOUNT_ID", wif.service_account_id),
        )
        if not value
    ]
    if missing:
        console.print(f"  [red]Not configured:[/] set {', '.join(missing)}.", soft_wrap=True)
        return 1
    source = anthropic_wif.identity_source()
    if source is None:
        console.print(
            "  [red]No identity token source:[/] set ANTHROPIC_IDENTITY_TOKEN_FILE or "
            "ANTHROPIC_IDENTITY_TOKEN_COMMAND, or run [cyan]strix auth login entra[/]."
        )
        return 1
    console.print(f"  Identity token source: [bold]{source}[/]", soft_wrap=True)

    try:
        assertion = anthropic_wif.read_identity_token()
    except anthropic_wif.WifAuthError as exc:
        console.print(f"  [red]Identity token failed:[/] {exc}", soft_wrap=True)
        return 1
    claims = entra_user.jwt_claims(assertion)
    for claim in ("iss", "aud", "azp", "oid", "sub"):
        if claims.get(claim):
            console.print(f"  {claim + ':':<7} {claims[claim]}", soft_wrap=True)

    try:
        access, expires_at = anthropic_wif.exchange(assertion)
    except anthropic_wif.WifAuthError as exc:
        console.print(f"  [red]Exchange failed:[/] {exc}", soft_wrap=True)
        return 1
    console.print(
        f"  [green]Exchange OK:[/] {access[:13]}… valid for {int(expires_at - time.time())}s"
    )

    model = settings.llm.model or ""
    if settings.llm.api_key:
        console.print(
            "  [yellow]Note:[/] LLM_API_KEY is set, so scans use it instead of federation. "
            "Set it to empty to use federation."
        )
    elif not anthropic_wif.is_anthropic_model(model):
        console.print(
            f"  [yellow]Note:[/] STRIX_LLM={model or '(unset)'} is not an anthropic/ model, "
            "so scans don't use federation."
        )
    return 0


def _fail(console: Console, exc: Exception) -> int:
    error_text = Text()
    error_text.append("SIGN-IN FAILED", style="bold red")
    error_text.append("\n\n", style="white")
    error_text.append(f"{exc}", style="white")
    console.print()
    console.print(
        Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
    )
    return 1


def _print_success(console: Console) -> None:
    text = Text()
    text.append("Signed in with your ChatGPT subscription", style="bold #22c55e")
    text.append("\n\n", style="white")
    text.append("Set ", style="white")
    text.append("STRIX_LLM", style="bold white")
    text.append(" to a ", style="white")
    text.append("chatgpt/", style="bold cyan")
    text.append(" model (e.g. ", style="white")
    text.append("chatgpt/gpt-5.4", style="bold cyan")
    text.append(") — runs are billed to your ChatGPT plan.", style="white")
    text.append("\n\n", style="white")
    text.append("Run a scan as usual, e.g. ", style="white")
    text.append("strix --target https://example.com", style="bold cyan")
    console.print()
    console.print(
        Panel(
            text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="#22c55e",
            padding=(1, 2),
        )
    )
    console.print()


def _print_entra_success(console: Console, record: dict[str, Any]) -> None:
    claims = entra_user.jwt_claims(record.get("access"))
    text = Text()
    text.append(
        f"Signed in to Microsoft Entra ID as {record.get('username') or 'unknown user'}",
        style="bold #22c55e",
    )
    text.append("\n\n", style="white")
    text.append("For the Anthropic federation rule: ", style="white")
    text.append(f"oid {claims.get('oid')}, sub {claims.get('sub')}", style="bold white")
    text.append("\n\n", style="white")
    text.append("Set ", style="white")
    text.append("STRIX_LLM", style="bold white")
    text.append(" to an ", style="white")
    text.append("anthropic/", style="bold cyan")
    text.append(" model and the ", style="white")
    text.append("ANTHROPIC_FEDERATION_RULE_ID", style="bold white")
    text.append(", ", style="white")
    text.append("_ORGANIZATION_ID", style="bold white")
    text.append(", ", style="white")
    text.append("_SERVICE_ACCOUNT_ID", style="bold white")
    text.append(" and ", style="white")
    text.append("_WORKSPACE_ID", style="bold white")
    text.append(" variables, with no ", style="white")
    text.append("LLM_API_KEY", style="bold white")
    text.append(". Scans then federate with this sign-in.", style="white")
    console.print()
    console.print(
        Panel(
            text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="#22c55e",
            padding=(1, 2),
        )
    )
    console.print()


_LOGO_PATH = Path(__file__).resolve().parent.parent / "viewer" / "static" / "logo.png"


def _logo_img_tag() -> str:
    """Return an ``<img>`` for the Strix logo as an inline data URI, or "".

    The callback page is served offline by the local OAuth server, so the logo
    is embedded rather than linked. Missing/unreadable file degrades to just the
    "Strix" wordmark.
    """
    try:
        data = _LOGO_PATH.read_bytes()
    except OSError:
        return ""
    encoded = base64.b64encode(data).decode("ascii")
    return f'<img class="logo" src="data:image/png;base64,{encoded}" alt="" />'


def _render_callback_html(account_label: str = "your ChatGPT subscription") -> str:
    return _CALLBACK_HTML.replace("<!--LOGO-->", _logo_img_tag()).replace(
        "<!--ACCOUNT-->", account_label
    )


_CALLBACK_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Strix — signed in</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; padding: 24px;
    font-family: 'Geist', 'Geist Sans', ui-sans-serif, system-ui, -apple-system,
      "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale;
    background: #000; color: #ededed;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
  }
  .topbar {
    position: absolute; top: 20px; left: 22px;
    display: flex; align-items: center; gap: 6px; text-decoration: none;
  }
  .topbar .logo { width: 40px; height: 40px; display: block; }
  .topbar span {
    font-size: 1.1rem; font-weight: 600; letter-spacing: -.01em; color: #fff;
    transition: color .15s ease;
  }
  .topbar:hover span { color: #c9c9c9; }
  .brand {
    font-size: 2.1rem; font-weight: 700; letter-spacing: -.02em; color: #fff;
    text-align: center; margin: 0 0 10px;
  }
  h1 {
    font-size: 1.35rem; font-weight: 600; letter-spacing: -.01em; color: #f5f5f5;
    text-align: center; margin: 0 0 28px;
  }
  .card {
    width: 100%; max-width: 430px; text-align: center;
    background: #171717; border: 1px solid rgba(255, 255, 255, .06);
    border-radius: 24px; padding: 40px 40px 34px;
  }
  .badge {
    margin: 0 auto 22px; width: 52px; height: 52px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center; font-size: 23px; color: #fff;
    background: rgba(255, 255, 255, .05); border: 1px solid rgba(255, 255, 255, .14);
  }
  .msg { margin: 0 auto; max-width: 34ch; color: #b5b5b5; line-height: 1.6; font-size: .98rem; }
  .rule { height: 1px; background: rgba(255, 255, 255, .07); margin: 26px 0 0; }
  .tagline { margin: 22px 0 0; color: #7c7c7c; font-size: .9rem; line-height: 1.55; }
  .tagline b { color: #ededed; font-weight: 500; }
  .links {
    margin-top: 18px; display: flex; gap: 8px; justify-content: center;
    align-items: center; flex-wrap: wrap; font-size: .84rem;
  }
  .links a { color: #a3a3a3; text-decoration: none; transition: color .15s ease; }
  .links a:hover { color: #fff; }
  .links .dot { color: #3a3a3a; }
  .close { margin: 24px 0 0; color: #5a5a5a; font-size: .78rem; text-align: center; }
</style></head>
<body>
  <a class="topbar" href="https://strix.ai" target="_blank" rel="noopener"
     aria-label="Strix — strix.ai">
    <!--LOGO-->
    <span>Strix</span>
  </a>
  <div class="brand">Strix</div>
  <h1>You're signed in</h1>
  <main class="card">
    <div class="badge">✓</div>
    <p class="msg">Strix is connected to <!--ACCOUNT-->. Head back to your
      terminal — your security test runs there.</p>
    <div class="rule"></div>
    <p class="tagline">Autonomous AI hackers that <b>find and fix</b> your app's
      vulnerabilities.</p>
    <nav class="links">
      <a href="https://strix.ai" target="_blank" rel="noopener">strix.ai</a>
      <span class="dot">·</span>
      <a href="https://docs.strix.ai" target="_blank" rel="noopener">docs</a>
      <span class="dot">·</span>
      <a href="https://discord.gg/strix-ai" target="_blank" rel="noopener">community</a>
    </nav>
  </main>
  <p class="close">You can close this tab.</p>
</body></html>"""


__all__ = ["run_auth"]
