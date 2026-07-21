"""Local HTTP server that serves the viewer SPA and a run's data from disk.

Design notes:
- Uses only the standard library (no new runtime dependency). The workload is
  serving static files plus a handful of JSON reads off disk, so an async stack
  buys nothing here.
- The browser polls the JSON endpoints (~1s) rather than using SSE: a finished
  run stops polling, and short-lived polls survive sleep/network blips without
  server-side connection state, which suits a stdlib ThreadingHTTPServer.
- All reads happen per-request straight from disk, so the same server serves a
  live in-progress run and a finished one identically; the SPA distinguishes
  them via the ``finished`` flag on /api/run.
"""

from __future__ import annotations

import json
import logging
import mimetypes
import secrets
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

from strix.core.paths import run_record_path
from strix.viewer import auth
from strix.viewer.transcript import (
    build_run_state,
    primary_target,
    read_report_markdown,
    read_run_summary,
    read_vulnerabilities,
    severity_counts,
)


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)


def bundle_dir() -> Path:
    """Directory holding the committed, prebuilt SPA (index.html + assets)."""
    return Path(__file__).resolve().parent / "static"


def bundle_is_built() -> bool:
    return (bundle_dir() / "index.html").is_file()


def _iter_run_dirs(base_dir: Path) -> list[Path]:
    """Every run directory under ``base_dir``, newest first by record mtime."""
    if not base_dir.is_dir():
        return []
    run_dirs = [child for child in base_dir.iterdir() if run_record_path(child).is_file()]
    run_dirs.sort(key=lambda child: run_record_path(child).stat().st_mtime, reverse=True)
    return run_dirs


def run_list_entry(run_dir: Path) -> dict[str, Any]:
    """Compact summary of a single run for the history list."""
    record = read_run_summary(run_dir)
    return {
        "name": record.get("run_name") or run_dir.name,
        "target": primary_target(record),
        "scan_mode": record.get("scan_mode"),
        "status": record.get("status"),
        "start_time": record.get("start_time"),
        "end_time": record.get("end_time"),
        "finished": bool(record.get("finished")),
        "severity_counts": severity_counts(read_vulnerabilities(run_dir)),
    }


def build_runs_payload(base_dir: Path, *, verified: bool) -> dict[str, Any]:
    """The /api/runs payload. Gates the run list behind email verification.

    The count is always advertised so the UI can tease the history, but the
    entries only appear once the viewer is verified.
    """
    run_dirs = _iter_run_dirs(base_dir)
    count = len(run_dirs)
    if not verified:
        return {"locked": True, "count": count, "runs": []}
    return {"locked": False, "count": count, "runs": [run_list_entry(d) for d in run_dirs]}


def resolve_run_dir(base_dir: Path, run_param: str | None, default_run_dir: Path) -> Path | None:
    """Resolve a ``?run=`` value to a real run directory under ``base_dir``.

    Returns ``default_run_dir`` when no run is requested. Rejects traversal and
    unknown runs (returns None) so the caller can answer 404.
    """
    if not run_param:
        return default_run_dir
    base = base_dir.resolve()
    candidate = (base / run_param).resolve()
    # Only direct children of the runs base that actually hold a run record.
    if candidate.parent != base or not run_record_path(candidate).is_file():
        return None
    return candidate


# Name of the cookie carrying the per-process session capability.
SESSION_COOKIE = "strix_viewer_session"


class _ViewerState:
    def __init__(
        self,
        run_dir: Path,
        assets_dir: Path,
        steer_handler: Callable[[str, str], bool] | None = None,
    ) -> None:
        self.run_dir = run_dir
        self.assets_dir = assets_dir
        # The strix_runs directory that holds the launched run; used to
        # enumerate and resolve other runs for the history list.
        self.base_dir = run_dir.parent
        # Set only when the viewer runs inside a live scan process (the TUI
        # launcher), which can deliver a message to a running agent. Absent for
        # standalone ``strix view`` / finished runs, so steering is unavailable.
        self.steer_handler = steer_handler
        # Unguessable per-process capability. It is minted here, printed/opened
        # for the operator who started the server (see ``authorized_url``), and
        # exchanged for a session cookie only when presented on the initial page
        # load. It is the request-level authorization the review asked for:
        # reachability of the port (e.g. when bound with ``--host``) is not
        # enough to steer a live scan, trigger a report, or browse history --
        # the token is never handed to a caller who merely reaches ``/``.
        self.session_token = secrets.token_urlsafe(32)


def _make_handler(state: _ViewerState) -> type[BaseHTTPRequestHandler]:
    class ViewerHandler(BaseHTTPRequestHandler):
        server_version = "StrixViewer/1.0"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            logger.debug("viewer %s - %s", self.address_string(), format % args)

        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            path = parts.path
            try:
                if path.startswith("/api/"):
                    self._handle_api(path, parse_qs(parts.query))
                else:
                    self._handle_static(path, parse_qs(parts.query))
            except BrokenPipeError:
                # The browser closed the connection mid-response (e.g. it
                # navigated away between polls). Not an error.
                logger.debug("viewer client disconnected during %s", path)
            except Exception:
                # A bad request must never kill the worker thread.
                logger.exception("viewer request failed: %s", path)
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            try:
                if path == "/api/event":
                    self._handle_event()
                elif path == "/api/auth/otp/start":
                    self._handle_otp_start()
                elif path == "/api/auth/otp/verify":
                    self._handle_otp_verify()
                elif path == "/api/auth/forget":
                    self._handle_forget()
                elif path == "/api/report/send":
                    self._handle_report_send()
                elif path == "/api/agents/steer":
                    self._handle_steer()
                else:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})
            except BrokenPipeError:
                logger.debug("viewer client disconnected during POST %s", path)
            except Exception:
                # A bad request must never kill the worker thread.
                logger.exception("viewer request failed: POST %s", path)
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})

        def _read_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return {}
            return body if isinstance(body, dict) else {}

        # Funnel events the viewer is allowed to forward. This handler is the
        # trust boundary: only these event names, with only their known props,
        # ever reach PostHog. Everything else (including any PII) is dropped.
        _EMAIL_EVENTS = frozenset(
            {"email_submitted", "email_verified", "report_sent", "work_email_required"}
        )

        def _handle_event(self) -> None:
            body = self._read_body()
            # Forwarded as anonymous PostHog events that respect the global
            # telemetry opt-out. Never forward the email, code, or report body:
            # only the whitelisted event names and their known props are passed.
            event = body.get("event")
            if event == "cta_clicked":
                from strix.telemetry import posthog

                cta = str(body.get("cta") or "unknown")
                surface = body.get("surface")
                posthog.viewer_cta_clicked(cta, surface=str(surface) if surface else None)
            elif event in self._EMAIL_EVENTS:
                from strix.telemetry import posthog

                purpose = body.get("purpose")
                posthog.viewer_email_event(str(event), purpose=str(purpose) if purpose else None)
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()

        def _handle_api(self, path: str, query: dict[str, list[str]]) -> None:
            # The launched run is always viewable with no verification. The
            # cross-run history list (/api/runs) unlocks its entries only for a
            # caller that holds this process's session capability *and* is email
            # verified, so merely reaching an exposed --host port never leaks the
            # run list (the payload still advertises the count as a teaser).
            if path == "/api/runs":
                unlocked = self._has_session() and auth.is_verified()
                payload = build_runs_payload(state.base_dir, verified=unlocked)
                self._send_json(HTTPStatus.OK, payload)
                return
            if path == "/api/capabilities":
                # Steering is only possible when the viewer shares a live scan's
                # coordinator + event loop (the TUI launcher wires a handler).
                self._send_json(HTTPStatus.OK, {"can_steer": state.steer_handler is not None})
                return
            if path == "/api/auth/status":
                self._handle_auth_status()
                return

            run_values = query.get("run")
            run_param = run_values[0] if run_values else None
            run_dir = resolve_run_dir(state.base_dir, run_param, state.run_dir)
            if run_dir is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown run"})
                return

            # The launched run is always viewable. Any *other* run's data is part
            # of the gated history: it needs this process's session capability
            # (so merely reaching an exposed --host port is not enough) *and*
            # email verification -- otherwise knowing a run name would leak its
            # metadata, vulnerabilities, report, and transcript.
            if run_dir.resolve() != state.run_dir.resolve():
                if not self._has_session():
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                    return
                if not auth.is_verified():
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unverified"})
                    return

            if path == "/api/run":
                self._send_json(HTTPStatus.OK, read_run_summary(run_dir))
            elif path == "/api/vulnerabilities":
                self._send_json(HTTPStatus.OK, read_vulnerabilities(run_dir))
            elif path == "/api/report":
                self._send_json(HTTPStatus.OK, {"markdown": read_report_markdown(run_dir)})
            elif path == "/api/transcript":
                self._send_json(HTTPStatus.OK, build_run_state(run_dir))
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})

        def _handle_auth_status(self) -> None:
            # The cached verified email is only disclosed to a caller holding this
            # process's session capability, so a cookie-less client on an exposed
            # --host port cannot read it; everyone else looks unverified.
            # Verification is reported through is_verified() so an expired record
            # is advertised as unverified -- otherwise the SPA would suppress
            # re-verification while history stays locked, stranding the user.
            if not self._has_session():
                self._send_json(HTTPStatus.OK, {"verified": False, "email": None})
                return
            record = auth.read_auth()
            self._send_json(
                HTTPStatus.OK,
                {
                    "verified": auth.is_verified(),
                    "email": record.get("email") if record else None,
                },
            )

        def _handle_otp_start(self) -> None:
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            email = str(self._read_body().get("email") or "").strip()
            if not email:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_email"})
                return
            try:
                auth.otp_start(email)
            except auth.RelayError as exc:
                self._send_relay_error(exc)
                return
            self._send_json(HTTPStatus.OK, {"ok": True})

        def _handle_otp_verify(self) -> None:
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            body = self._read_body()
            email = str(body.get("email") or "").strip()
            code = str(body.get("code") or "").strip()
            if not email or not code:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_code"})
                return
            try:
                result = auth.otp_verify(email, code)
            except auth.RelayError as exc:
                self._send_relay_error(exc)
                return
            auth.write_auth(
                email=result.get("email") or email,
                token=result["token"],
                verified_at=result.get("expires_at") or "",
            )
            verified_email = result.get("email") or email
            self._send_json(HTTPStatus.OK, {"verified": True, "email": verified_email})

        def _handle_forget(self) -> None:
            # Clearing the cached verification is a state change, so it requires
            # this process's session capability: a cookie-less caller on an
            # exposed --host port must not be able to log the operator out.
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            auth.forget()
            self._send_json(HTTPStatus.OK, {"ok": True})

        def _handle_report_send(self) -> None:
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            record = auth.read_auth()
            if record is None:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unverified"})
                return
            run_param = str(self._read_body().get("run") or "") or None
            run_dir = resolve_run_dir(state.base_dir, run_param, state.run_dir)
            if run_dir is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown run"})
                return

            summary = read_run_summary(run_dir)
            # Emailing only makes sense for a completed run; a live scan would
            # send a partial report. The UI hides the entry point, but fail
            # closed here too so the endpoint can't be driven mid-scan.
            if not summary.get("finished", False):
                self._send_json(HTTPStatus.CONFLICT, {"error": "run_not_finished"})
                return

            from strix.viewer.report_pdf import build_encrypted_report

            pdf_bytes, password, filename = build_encrypted_report(run_dir)
            run_name = str(summary.get("run_name") or run_dir.name)
            target = primary_target(summary) or "unknown target"
            try:
                # The password is intentionally NOT passed here; only the
                # encrypted PDF bytes reach the relay.
                auth.report_send(record["token"], pdf_bytes, filename, run_name, target)
            except auth.RelayError as exc:
                self._send_relay_error(exc)
                return
            # The password is returned only to the local (127.0.0.1) browser.
            self._send_json(
                HTTPStatus.OK,
                {"ok": True, "password": password, "filename": filename},
            )

        # Cap on a steering message so a runaway client cannot flood the agent.
        _STEER_MESSAGE_MAX = 4000

        def _handle_steer(self) -> None:
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            body = self._read_body()
            agent_id = body.get("agent_id")
            message = body.get("message")
            if not isinstance(agent_id, str) or not agent_id.strip():
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_agent_id"})
                return
            if (
                not isinstance(message, str)
                or not message.strip()
                or len(message) > self._STEER_MESSAGE_MAX
            ):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_message"})
                return
            if state.steer_handler is None:
                # Standalone / finished-run viewing has no live scan to steer.
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "steering_unavailable"})
                return
            delivered = state.steer_handler(agent_id, message)
            if delivered:
                self._send_json(HTTPStatus.OK, {"ok": True})
            else:
                self._send_json(HTTPStatus.OK, {"ok": False, "error": "not_delivered"})

        def _send_relay_error(self, exc: auth.RelayError) -> None:
            status_by_code = {
                "rate_limited": HTTPStatus.TOO_MANY_REQUESTS,
                "invalid_email": HTTPStatus.BAD_REQUEST,
                "work_email_required": HTTPStatus.BAD_REQUEST,
                "invalid_code": HTTPStatus.FORBIDDEN,
                "reverify": HTTPStatus.UNAUTHORIZED,
                "forbidden": HTTPStatus.FORBIDDEN,
                "too_large": HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "unavailable": HTTPStatus.BAD_GATEWAY,
            }
            status = status_by_code.get(exc.code, HTTPStatus.BAD_GATEWAY)
            self._send_json(status, {"error": exc.code})

        def _cookies(self) -> dict[str, str]:
            jar: dict[str, str] = {}
            for chunk in (self.headers.get("Cookie") or "").split(";"):
                name, sep, value = chunk.strip().partition("=")
                if sep:
                    jar[name] = value
            return jar

        def _has_session(self) -> bool:
            """True when the request carries this process's session capability.

            The cookie is set only when the SPA is served (index.html), so only
            the browser this process handed the page to can pass. A direct
            caller on an exposed port has no cookie and is rejected.
            """
            supplied = self._cookies().get(SESSION_COOKIE, "")
            return bool(supplied) and secrets.compare_digest(supplied, state.session_token)

        def _token_presented(self, query: dict[str, list[str]]) -> bool:
            """True when the request carries the correct bootstrap token.

            The token reaches the operator's browser through the URL printed /
            opened by the process that started the server, a channel an
            arbitrary network caller on an exposed port cannot observe.
            """
            supplied = (query.get("token") or [""])[0]
            return bool(supplied) and secrets.compare_digest(supplied, state.session_token)

        def _handle_static(self, path: str, query: dict[str, list[str]]) -> None:
            target = self._resolve_asset(path)
            if target is None:
                # SPA fallback: unknown non-asset routes render index.html so
                # client-side deep links work.
                target = state.assets_dir / "index.html"
            is_index = target.name == "index.html"
            if not target.is_file():
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            content = target.read_bytes()
            content_type, _ = mimetypes.guess_type(str(target))
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type or "application/octet-stream")
            self.send_header("Content-Length", str(len(content)))
            if is_index and self._token_presented(query):
                # Exchange the bootstrap token for the per-process session
                # capability. Issued only when the correct token is presented,
                # so a caller who merely reaches ``/`` never obtains it.
                # HttpOnly (JS never needs it; fetch sends it automatically) and
                # SameSite=Strict (never sent from a cross-site context).
                self.send_header(
                    "Set-Cookie",
                    f"{SESSION_COOKIE}={state.session_token}; Path=/; HttpOnly; SameSite=Strict",
                )
            self.end_headers()
            self.wfile.write(content)

        def _resolve_asset(self, path: str) -> Path | None:
            rel = unquote(path).lstrip("/")
            if not rel or rel.endswith("/"):
                return None
            root = state.assets_dir.resolve()
            candidate = (root / rel).resolve()
            # Path-traversal guard: never serve outside the bundle root.
            if root != candidate and root not in candidate.parents:
                logger.warning("viewer rejected traversal attempt: %s", path)
                return None
            return candidate if candidate.is_file() else None

        def _send_json(self, status: HTTPStatus, payload: Any) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ViewerHandler


def authorized_url(base_url: str, token: str) -> str:
    """URL that bootstraps the viewer session for the operator.

    Presenting ``token`` on the initial page load is what mints the session
    cookie, so this URL is printed / opened only for the operator who started
    the server. Sharing it (rather than the bare ``base_url``) is what lets a
    trusted remote user authorize when the viewer is exposed with ``--host``.
    """
    return f"{base_url}/?{urlencode({'token': token})}"


def serve(
    run_dir: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    open_browser: bool = True,
    steer_handler: Callable[[str, str], bool] | None = None,
) -> tuple[ThreadingHTTPServer, str, str]:
    """Start the viewer server on a background thread; return (server, url, token).

    ``url`` is the bare base; pass it through ``authorized_url(url, token)`` to
    build the operator link that authorizes the browser.

    Binds an ephemeral port by default. If a fixed ``port`` is requested but in
    use, falls back to an ephemeral port. Reused by both the ``strix view``
    command and the in-TUI launcher; callers own the server's lifetime.

    ``steer_handler`` is supplied only by the in-TUI launcher, which runs inside
    the live scan process and can forward a message to a running agent. Left
    ``None`` (standalone ``strix view``), steering is reported unavailable.
    """
    assets_dir = bundle_dir()
    state = _ViewerState(run_dir=run_dir, assets_dir=assets_dir, steer_handler=steer_handler)
    handler = _make_handler(state)

    try:
        httpd = ThreadingHTTPServer((host, port), handler)
    except OSError:
        if port == 0:
            raise
        logger.info("viewer port %s unavailable, falling back to an ephemeral port", port)
        httpd = ThreadingHTTPServer((host, 0), handler)

    httpd.daemon_threads = True
    bound_port = int(httpd.server_address[1])
    url = f"http://{host}:{bound_port}"

    thread = threading.Thread(target=httpd.serve_forever, name="strix-viewer", daemon=True)
    thread.start()

    if open_browser:
        _open_browser(authorized_url(url, state.session_token))

    return httpd, url, state.session_token


def _open_browser(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001 - launching the browser is best-effort
        logger.debug("could not open browser for %s", url, exc_info=True)


__all__ = ["authorized_url", "bundle_dir", "bundle_is_built", "serve"]
