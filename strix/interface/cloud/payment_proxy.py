"""Loopback bridge for wallet clients that only accept secrets in argv.

The ``mppx`` CLI accepts custom HTTP headers through ``-H`` only.  Passing a
Strix API token that way exposes it to process-listing tools.  This module keeps
the token in the Strix process and injects it while forwarding the wallet's few
requests (challenge probes and the paid retry) to the fixed billing endpoint.
"""

from __future__ import annotations

import secrets
import threading
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any

import requests


if TYPE_CHECKING:
    from collections.abc import Callable, Generator


_DEFAULT_REQUEST_TIMEOUT_S = 120.0
_MAX_REQUEST_BODY_BYTES = 64 * 1024
_MAX_UPSTREAM_RESPONSE_BYTES = 1024 * 1024
_MAX_WALLET_REQUESTS = 3
_HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


@dataclass
class _BridgeState:
    upstream_url: str
    authorization: str
    workspace_id: str | None
    expected_body: bytes
    path: str
    timeout: float
    response_observer: Callable[[WalletUpstreamResponse], None] | None = None
    request_count: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def claim_request(self) -> bool:
        """Allow only the challenge probes and the one paid retry."""
        with self.lock:
            if self.request_count >= _MAX_WALLET_REQUESTS:
                return False
            self.request_count += 1
            return True


class _ResponseTooLargeError(Exception):
    """The fixed billing endpoint returned more data than a wallet needs."""


@dataclass(frozen=True)
class WalletUpstreamResponse:
    """A bounded upstream response observed by the trusted loopback bridge."""

    status_code: int
    body: bytes


def _bounded_response_body(response: requests.Response) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > _MAX_UPSTREAM_RESPONSE_BYTES:
                raise _ResponseTooLargeError
        except ValueError:
            pass

    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        total += len(chunk)
        if total > _MAX_UPSTREAM_RESPONSE_BYTES:
            raise _ResponseTooLargeError
        chunks.append(chunk)
    return b"".join(chunks)


def _connection_header_names(handler: BaseHTTPRequestHandler) -> set[str]:
    value = handler.headers.get("Connection", "")
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def _forward_request_headers(handler: BaseHTTPRequestHandler) -> dict[str, str]:
    blocked = {
        *_HOP_BY_HOP_HEADERS,
        *_connection_header_names(handler),
        "content-length",
        "forwarded",
        "host",
        "true-client-ip",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "x-strix-authorization",
        "x-strix-workspace",
        "x-vercel-forwarded-for",
    }
    return {name: value for name, value in handler.headers.items() if name.lower() not in blocked}


def _send_json_error(handler: BaseHTTPRequestHandler, status: int, message: str) -> None:
    body = f'{{"error": "{message}"}}'.encode()
    handler.close_connection = True
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Connection", "close")
    handler.end_headers()
    with suppress(BrokenPipeError, ConnectionResetError):
        handler.wfile.write(body)


def _make_handler(state: _BridgeState) -> type[BaseHTTPRequestHandler]:
    class WalletBridgeHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            """Do not write wallet request metadata to stderr."""
            del format, args

        def do_POST(self) -> None:  # noqa: PLR0911, PLR0912
            if self.path != state.path:
                _send_json_error(self, 404, "Not found")
                return
            if self.headers.get("Transfer-Encoding"):
                _send_json_error(self, 400, "Chunked request bodies are not supported")
                return
            try:
                content_length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                _send_json_error(self, 411, "A valid Content-Length is required")
                return
            if content_length < 0 or content_length > _MAX_REQUEST_BODY_BYTES:
                _send_json_error(self, 413, "Request body is too large")
                return
            body = self.rfile.read(content_length)
            if body != state.expected_body:
                _send_json_error(self, 403, "Request body did not match the approved top-up")
                return
            if not state.claim_request():
                _send_json_error(self, 429, "Wallet request limit reached")
                return

            headers = _forward_request_headers(self)
            headers["X-Strix-Authorization"] = state.authorization
            if state.workspace_id:
                headers["X-Strix-Workspace"] = state.workspace_id
            try:
                response = requests.request(
                    "POST",
                    state.upstream_url,
                    headers=headers,
                    data=body,
                    timeout=state.timeout,
                    allow_redirects=False,
                    stream=True,
                )
                try:
                    response_body = _bounded_response_body(response)
                    response_status = response.status_code
                    response_headers = dict(response.headers)
                finally:
                    response.close()
            except _ResponseTooLargeError:
                _send_json_error(self, 502, "Strix billing response was too large")
                return
            except requests.RequestException:
                _send_json_error(self, 502, "Could not reach the Strix billing endpoint")
                return

            if state.response_observer is not None:
                with suppress(Exception):
                    state.response_observer(
                        WalletUpstreamResponse(status_code=response_status, body=response_body)
                    )

            if 300 <= response_status < 400:
                _send_json_error(self, 502, "Strix billing refused an unexpected redirect")
                return

            self.send_response(response_status)
            response_connection_headers = {
                item.strip().lower()
                for item in response_headers.get("Connection", "").split(",")
                if item.strip()
            }
            blocked_response_headers = {
                *_HOP_BY_HOP_HEADERS,
                *response_connection_headers,
                "cache-control",
                "content-encoding",
                "content-length",
                "location",
            }
            for name, value in response_headers.items():
                if (
                    name.lower() not in blocked_response_headers
                    and "\r" not in value
                    and "\n" not in value
                ):
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(response_body)

        def do_GET(self) -> None:
            _send_json_error(self, 405, "Method not allowed")

        def do_PUT(self) -> None:
            _send_json_error(self, 405, "Method not allowed")

        def do_PATCH(self) -> None:
            _send_json_error(self, 405, "Method not allowed")

        def do_DELETE(self) -> None:
            _send_json_error(self, 405, "Method not allowed")

    return WalletBridgeHandler


@contextmanager
def wallet_payment_bridge(
    *,
    upstream_url: str,
    api_token: str,
    workspace_id: str | None = None,
    expected_body: bytes,
    timeout: float | None = None,
    response_observer: Callable[[WalletUpstreamResponse], None] | None = None,
) -> Generator[str]:
    """Yield a one-run loopback URL that injects the Strix API token upstream.

    The random path prevents accidental cross-process requests and limits local
    denial-of-service races.  It is not an authentication boundary against a
    same-user process that can inspect another process's argv.
    """
    capability = secrets.token_urlsafe(32)
    path = f"/topup/{capability}"
    state = _BridgeState(
        upstream_url=upstream_url,
        authorization=f"Bearer {api_token}",
        workspace_id=workspace_id,
        expected_body=expected_body,
        path=path,
        timeout=timeout or _DEFAULT_REQUEST_TIMEOUT_S,
        response_observer=response_observer,
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.05},
        name="strix-wallet-bridge",
        daemon=True,
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}{path}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
