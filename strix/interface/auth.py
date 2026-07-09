"""Strix Cloud authentication commands: login, logout, whoami.

Stdlib only — no third-party dependencies so `strix login` works even
before optional extras are installed.
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import secrets
import socket
import stat
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any


DEFAULT_APP_URL = "https://app.strix.ai"
CREDENTIALS_PATH = Path.home() / ".strix" / "credentials.json"
LOGIN_TIMEOUT_SECONDS = 600
CALLBACK_PATH = "/callback"

_SUCCESS_HTML = """<!doctype html>
<html><head><title>Strix CLI</title>
<style>body{background:#000;color:#fff;font-family:ui-sans-serif,system-ui,sans-serif;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{text-align:center;border:1px solid rgba(255,255,255,.1);border-radius:12px;
padding:48px 64px;background:rgba(255,255,255,.03)}h1{font-size:20px;margin:0 0 8px}
p{color:rgba(255,255,255,.6);margin:0}</style></head>
<body><div class="card"><h1>Strix CLI authorized</h1>
<p>You can close this tab and return to your terminal.</p></div></body></html>"""

_FAILURE_HTML = _SUCCESS_HTML.replace("Strix CLI authorized", "Authorization failed").replace(
    "You can close this tab and return to your terminal.",
    "Return to your terminal for details.",
)


def _app_url() -> str:
    return os.environ.get("STRIX_APP_URL", DEFAULT_APP_URL).rstrip("/")


def _api_url() -> str:
    return f"{_app_url()}/api/v1"


def _urlopen(request: urllib.request.Request, timeout: int) -> Any:
    scheme = urllib.parse.urlparse(request.full_url).scheme
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {scheme}")
    return urllib.request.urlopen(request, timeout=timeout)  # nosec B310


def _post_json(url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode()
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with _urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode() or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = {}
        return e.code, body
    except urllib.error.URLError as e:
        return 0, {"error": "network_error", "error_description": f"Network error: {e.reason}"}
    except TimeoutError:
        return 0, {
            "error": "network_error",
            "error_description": "Network error: request timed out",
        }


def load_credentials() -> dict[str, Any] | None:
    try:
        with CREDENTIALS_PATH.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) and data.get("token") else None


def save_credentials(credentials: dict[str, Any]) -> None:
    CREDENTIALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        CREDENTIALS_PATH,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        stat.S_IRUSR | stat.S_IWUSR,
    )
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(credentials, indent=2) + "\n")
    CREDENTIALS_PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    server: "_CallbackServer"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != CALLBACK_PATH:
            self.send_error(404)
            return
        params = urllib.parse.parse_qs(parsed.query)
        code = params.get("code", [None])[0]
        state = params.get("state", [None])[0]
        error = params.get("error", [None])[0]

        ok = bool(code) and state == self.server.expected_state and not error
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write((_SUCCESS_HTML if ok else _FAILURE_HTML).encode())

        self.server.result = {"code": code, "state": state, "error": error}
        self.server.done.set()

    def log_message(self, *args: Any) -> None:
        pass


class _CallbackServer(http.server.HTTPServer):
    def __init__(self, expected_state: str) -> None:
        super().__init__(("127.0.0.1", 0), _CallbackHandler)
        self.expected_state = expected_state
        self.result: dict[str, Any] | None = None
        self.done = threading.Event()


def _login_loopback(server: _CallbackServer) -> int:
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    state = server.expected_state
    port = server.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}{CALLBACK_PATH}"

    query = urllib.parse.urlencode(
        {
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "device": socket.gethostname()[:100],
        }
    )
    authorize_url = f"{_app_url()}/cli/authorize?{query}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    print("Opening your browser to authorize the Strix CLI...")
    print(f"If it doesn't open automatically, visit:\n\n  {authorize_url}\n")
    webbrowser.open(authorize_url)

    try:
        if not server.done.wait(timeout=LOGIN_TIMEOUT_SECONDS):
            print("Timed out waiting for browser authorization.", file=sys.stderr)
            return 1
    finally:
        server.shutdown()

    result = server.result or {}
    if result.get("error"):
        print(f"Authorization failed: {result['error']}", file=sys.stderr)
        return 1
    if result.get("state") != state or not result.get("code"):
        print("Authorization failed: invalid callback.", file=sys.stderr)
        return 1

    status, body = _post_json(
        f"{_api_url()}/auth/cli/token",
        {
            "grant_type": "authorization_code",
            "code": result["code"],
            "code_verifier": verifier,
            "redirect_uri": redirect_uri,
        },
    )
    if status != 200 or not body.get("token"):
        detail = body.get("error_description") or body.get("error") or f"HTTP {status}"
        print(f"Failed to exchange authorization code: {detail}", file=sys.stderr)
        return 1

    return _finish_login(body)


def _login_device() -> int:
    status, body = _post_json(
        f"{_api_url()}/auth/cli/device", {"device_name": socket.gethostname()[:100]}
    )
    if status != 201:
        detail = body.get("detail") or body.get("error_description") or f"HTTP {status}"
        print(f"Failed to start device authorization: {detail}", file=sys.stderr)
        return 1

    user_code = body.get("user_code")
    verification_uri = body.get("verification_uri")
    device_code = body.get("device_code")
    if not (user_code and verification_uri and device_code):
        print("Device authorization failed: malformed server response.", file=sys.stderr)
        return 1
    try:
        interval = max(int(body.get("interval", 5)), 1)
        expires_in = int(body.get("expires_in", 600))
    except (TypeError, ValueError):
        interval, expires_in = 5, 600

    print(f"\nVisit {verification_uri} and enter this code:\n\n  {user_code}\n")
    webbrowser.open(body.get("verification_uri_complete", verification_uri))
    print("Waiting for approval...", end="", flush=True)

    deadline = time.monotonic() + expires_in
    while time.monotonic() < deadline:
        time.sleep(interval)
        status, token_body = _post_json(
            f"{_api_url()}/auth/cli/token",
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            },
        )
        error = token_body.get("error")
        if status == 200 and token_body.get("token"):
            print()
            return _finish_login(token_body)
        if error == "authorization_pending":
            print(".", end="", flush=True)
            continue
        if error == "slow_down":
            interval += 5
            continue
        print()
        detail = token_body.get("error_description") or error or f"HTTP {status}"
        print(f"Device authorization failed: {detail}", file=sys.stderr)
        return 1

    print()
    print("Device authorization timed out.", file=sys.stderr)
    return 1


def _finish_login(token_body: dict[str, Any]) -> int:
    save_credentials(
        {
            "api_url": _api_url(),
            "token": token_body["token"],
            "organization_id": token_body.get("organization_id"),
            "created_at": int(time.time()),
        }
    )
    print(f"Logged in to Strix Cloud. Credentials saved to {CREDENTIALS_PATH}")
    return 0


def run_login(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="strix login", description="Authenticate the Strix CLI with Strix Cloud."
    )
    parser.add_argument(
        "--device",
        action="store_true",
        help="Use the device-code flow (for SSH/headless machines without a local browser).",
    )
    args = parser.parse_args(argv)

    if args.device:
        return _login_device()
    try:
        server = _CallbackServer(secrets.token_urlsafe(32))
    except OSError as e:
        print(
            f"Could not start local callback server ({e}); falling back to device-code flow.",
            file=sys.stderr,
        )
        return _login_device()
    return _login_loopback(server)


def run_logout(argv: list[str]) -> int:
    argparse.ArgumentParser(
        prog="strix logout", description="Remove saved Strix Cloud credentials."
    ).parse_args(argv)
    if CREDENTIALS_PATH.exists():
        try:
            CREDENTIALS_PATH.unlink()
        except OSError as e:
            print(f"Failed to remove credentials: {e}", file=sys.stderr)
            return 1
        print("Logged out. Credentials removed.")
    else:
        print("No saved credentials found.")
    return 0


def run_whoami(argv: list[str]) -> int:
    argparse.ArgumentParser(
        prog="strix whoami", description="Show the current Strix Cloud login."
    ).parse_args(argv)
    credentials = load_credentials()
    if not credentials:
        print("Not logged in. Run `strix login` to authenticate.", file=sys.stderr)
        return 1

    api_url = credentials.get("api_url", _api_url())
    token = credentials["token"]
    request = urllib.request.Request(
        f"{api_url}/scans?limit=1", headers={"Authorization": f"Bearer {token}"}
    )
    try:
        with _urlopen(request, timeout=15) as response:
            valid = response.status == 200
    except urllib.error.HTTPError as e:
        valid = e.code != 401
    except urllib.error.URLError:
        valid = None  # network error — can't tell

    print(f"API: {api_url}")
    if credentials.get("organization_id"):
        print(f"Organization: {credentials['organization_id']}")
    print(f"Token: {token[:8]}...{token[-4:]}")
    if valid is True:
        print("Status: token is valid")
        return 0
    if valid is None:
        print("Status: could not verify token (network error)")
        return 0
    print("Status: token is invalid or expired — run `strix login` again")
    return 1


AUTH_COMMANDS = {
    "login": run_login,
    "logout": run_logout,
    "whoami": run_whoami,
}


def dispatch_auth_command(argv: list[str]) -> int | None:
    """If argv starts with an auth subcommand, run it and return its exit code."""
    if argv and argv[0] in AUTH_COMMANDS:
        return AUTH_COMMANDS[argv[0]](argv[1:])
    return None
