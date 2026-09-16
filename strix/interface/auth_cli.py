"""`strix auth` — model-subscription sign-in (login / status / logout).

Signing in only stores OAuth tokens (``~/.strix/subscription-auth.json``); model
selection stays with ``STRIX_LLM``. A ``chatgpt/<model>`` STRIX_LLM runs on a
ChatGPT subscription; a ``claude/<model>`` STRIX_LLM runs on a Claude subscription.
"""

from __future__ import annotations

import argparse
import base64
import logging
import threading
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import claude, codex, load_settings


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)

_CALLBACK_TIMEOUT_S = 300


@dataclass(frozen=True)
class _AuthProvider:
    """One subscription sign-in flow (ChatGPT or Claude)."""

    key: str  # canonical CLI name shown in messages
    aliases: frozenset[str]  # every accepted spelling, including the key
    module: Any  # strix.config.codex | strix.config.claude
    display: str  # e.g. "ChatGPT" / "Claude"
    plan_hint: str  # one-line description of what the subscription is
    model_example: str  # e.g. "chatgpt/gpt-5.4" / "claude/opus-5"
    error_type: type[Exception]
    supports_callback: bool  # loopback redirect server vs. manual paste only

    def exchange(self, code: str, verifier: str, state: str | None) -> dict[str, Any]:
        # codex.exchange_code(code, verifier); claude also takes the state.
        if self.module is claude:
            return claude.exchange_code(code, verifier, state)
        return codex.exchange_code(code, verifier)


_CODEX_PROVIDER = _AuthProvider(
    key="chatgpt",
    aliases=frozenset({"chatgpt", "codex"}),
    module=codex,
    display="ChatGPT",
    plan_hint="your ChatGPT Plus/Pro plan for inference instead of a metered API key",
    model_example="chatgpt/gpt-5.4",
    error_type=codex.CodexAuthError,
    supports_callback=True,
)
_CLAUDE_PROVIDER = _AuthProvider(
    key="claude",
    aliases=frozenset({"claude", "anthropic"}),
    module=claude,
    display="Claude",
    plan_hint="your Claude Pro/Max plan for inference instead of a metered API key",
    model_example="claude/opus-5",
    error_type=claude.ClaudeAuthError,
    supports_callback=False,
)
_PROVIDERS = (_CODEX_PROVIDER, _CLAUDE_PROVIDER)

# Bare `strix auth login` keeps the historical default (ChatGPT).
DEFAULT_PROVIDER = _CODEX_PROVIDER

_USAGE = (
    "Usage:\n"
    "  strix auth login [chatgpt|claude] [--manual]\n"
    "  strix auth status\n"
    "  strix auth logout [chatgpt|claude]"
)


def _resolve_provider(name: str | None) -> _AuthProvider | None:
    if not name:
        return DEFAULT_PROVIDER
    lowered = name.lower()
    for provider in _PROVIDERS:
        if lowered in provider.aliases:
            return provider
    return None


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
        "logout": lambda: _logout(console, rest),
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
        default=DEFAULT_PROVIDER.key,
        help="Model provider to sign in with: chatgpt or claude (default: chatgpt).",
    )
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Skip the local callback server and paste the redirect URL by hand.",
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse already printed the message
        return int(exc.code or 2)

    provider = _resolve_provider(args.provider)
    if provider is None:
        console.print(
            f"[red]Unsupported provider:[/] {args.provider}. "
            "Choose 'chatgpt' (ChatGPT subscription) or 'claude' (Claude subscription)."
        )
        return 2

    mod = provider.module
    verifier, challenge = mod.generate_pkce()
    state = mod.create_state()
    authorize_url = mod.build_authorize_url(challenge, state)

    console.print()
    console.print(f"[bold]Signing in with {provider.display}[/] [dim](provider: {provider.key})[/]")
    console.print(f"[dim]This uses {provider.plan_hint}.[/]")
    console.print()

    try:
        record = _run_oauth_flow(
            console, provider, authorize_url, verifier, state, manual=args.manual
        )
    except provider.error_type as exc:
        return _fail(console, exc)
    except KeyboardInterrupt:
        console.print("\n[yellow]Sign-in cancelled.[/]")
        return 130

    mod.save_record(record)
    _print_success(console, provider)
    return 0


def _run_oauth_flow(
    console: Console,
    provider: _AuthProvider,
    authorize_url: str,
    verifier: str,
    state: str,
    *,
    manual: bool,
) -> dict[str, Any]:
    """Drive the browser (or manual) OAuth flow and return a token record."""
    use_callback = provider.supports_callback and not manual
    server = _try_start_callback_server() if use_callback else None

    console.print("Open this URL in your browser to authorize:")
    console.print(f"[cyan]{authorize_url}[/]")
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
                raise provider.error_type("oauth_error", error)
            return _finish(provider, code, returned_state, verifier, state, require_state=True)
        console.print("[yellow]Timed out waiting for the browser. Falling back to manual paste.[/]")

    # Manual paste: the user completes sign-in and pastes the redirect URL (or the
    # authorization code shown on the provider's callback page).
    console.print()
    try:
        pasted = console.input("Paste the full redirect URL (or code#state): ").strip()
    except EOFError as exc:
        raise provider.error_type("no_input", "no redirect URL provided") from exc
    code, returned_state = provider.module.parse_redirect_input(pasted)
    return _finish(provider, code, returned_state, verifier, state, require_state=False)


def _finish(
    provider: _AuthProvider,
    code: str | None,
    returned_state: str | None,
    verifier: str,
    expected_state: str,
    *,
    require_state: bool,
) -> dict[str, Any]:
    if not code:
        raise provider.error_type("no_code", "no authorization code found in the redirect")
    # A loopback callback always carries state, so a missing or mismatched value
    # there is forged (CSRF) and must be rejected. Manual paste is user-initiated
    # (the user copies their own redirect), so state is only validated when the
    # pasted value includes it.
    if require_state and returned_state is None:
        raise provider.error_type("state_mismatch", "missing state in callback; possible CSRF")
    if returned_state is not None and returned_state != expected_state:
        raise provider.error_type("state_mismatch", "state did not match; possible CSRF")
    return provider.exchange(code, verifier, returned_state)


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


def _try_start_callback_server() -> _CallbackServer | None:
    event = threading.Event()
    holder: dict[str, Any] = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # silence default stderr logging
            pass

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != codex.CALLBACK_PATH:
                self.send_response(404)
                self.end_headers()
                return
            query = parse_qs(parsed.query)
            holder["code"] = _first(query, "code")
            holder["state"] = _first(query, "state")
            holder["error"] = _first(query, "error_description") or _first(query, "error")
            body = _render_callback_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            event.set()

    try:
        httpd = HTTPServer(("127.0.0.1", codex.CALLBACK_PORT), Handler)
    except OSError:
        logger.debug("could not bind callback port %d", codex.CALLBACK_PORT, exc_info=True)
        return None
    return _CallbackServer(httpd, event, holder)


def _first(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    return values[0] if values else None


def _status(console: Console) -> int:
    signed_in = [p for p in _PROVIDERS if p.module.is_authenticated()]
    if not signed_in:
        console.print(
            "[yellow]Not signed in.[/] Run [cyan]strix auth login chatgpt[/] "
            "or [cyan]strix auth login claude[/] to sign in."
        )
        return 1
    settings = load_settings()
    for provider in signed_in:
        record = provider.module.read_record() or {}
        account = record.get("account_id") or record.get("account_label")
        console.print(f"[green]Signed in[/] with a {provider.display} subscription.")
        if account:
            console.print(f"  Account: [bold]{account}[/]")
        if provider.module.subscription_model(settings.llm.model):
            console.print(f"  Runs use the subscription (STRIX_LLM=[bold]{settings.llm.model}[/]).")
        else:
            console.print(
                f"  [yellow]Note:[/] set [cyan]STRIX_LLM[/] to e.g. "
                f"[cyan]{provider.model_example}[/] to run on this subscription."
            )
    return 0


def _logout(console: Console, argv: list[str]) -> int:
    provider = _resolve_provider(argv[0]) if argv else None
    if argv and provider is None:
        console.print(f"[red]Unsupported provider:[/] {argv[0]}. Choose 'chatgpt' or 'claude'.")
        return 2
    targets = (provider,) if provider is not None else _PROVIDERS
    for target in targets:
        target.module.logout()
    console.print("[green]Signed out.[/] Stored subscription credentials removed.")
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


def _print_success(console: Console, provider: _AuthProvider) -> None:
    prefix = f"{provider.key}/"
    text = Text()
    text.append(f"Signed in with your {provider.display} subscription", style="bold #22c55e")
    text.append("\n\n", style="white")
    text.append("Set ", style="white")
    text.append("STRIX_LLM", style="bold white")
    text.append(" to a ", style="white")
    text.append(prefix, style="bold cyan")
    text.append(" model (e.g. ", style="white")
    text.append(provider.model_example, style="bold cyan")
    text.append(f") — runs are billed to your {provider.display} plan.", style="white")
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


def _render_callback_html() -> str:
    return _CALLBACK_HTML.replace("<!--LOGO-->", _logo_img_tag())


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
    <p class="msg">Strix is connected to your ChatGPT subscription. Head back to your
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
