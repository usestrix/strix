"""Browser-driven outbound-request assertions for the CSPT fixtures.

This is the runtime counterpart to the structural checks in
``test_cspt_skill.py``. It answers the acceptance-criterion the structural
tests cannot: *does the tainted source actually flow into the request sink and
steer the browser's outbound path?*

For each fixture we:

1. Serve the fixture directory from a local HTTP server that also **captures**
   every request whose path escapes the intended ``/api/...`` prefix (the
   traversed target) and every ``/api/...`` request (the benign/intended one).
2. Drive a real headless Chromium at the fixture with a crafted source value.
3. Read what the *server* actually received off the wire and assert the exact
   outbound path.

Positives must emit a traversed request to the exact escaped path; negatives
must emit **no** traversed request (the value is validated away or kept out of
the path). A fixture whose source and sink exist but are not connected would
never produce the traversed request, so this fails closed — unlike a purely
textual "contains a source and a sink" check.

Skips cleanly when Playwright or its Chromium build is unavailable, so CI
without a browser stays green; the structural suite still runs there.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest


playwright_sync = pytest.importorskip("playwright.sync_api")

FIXTURES = Path(__file__).parent / "fixtures" / "cspt"


@dataclass
class _Capture:
    """Records the request paths the server observed, by category."""

    intended: list[str] = field(default_factory=list)  # /api/... (benign target)
    traversed: list[str] = field(default_factory=list)  # escaped /api/... prefix
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, path: str) -> None:
        with self.lock:
            if path.startswith("/api/"):
                self.intended.append(path)
            else:
                self.traversed.append(path)


def _make_handler(capture: _Capture, root: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:  # silence stderr spam
            return

        def _serve(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path

            # A fixture file request: serve it so the page (and its script) load.
            if path == "/" or path.endswith(".html"):
                name = "index.html" if path == "/" else Path(path).name
                target = (root / name).resolve()
                if target.is_file() and root.resolve() in target.parents:
                    body = target.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

            # Any other path is a request the page's sink emitted. Record which
            # bucket it fell into, then answer 200 so the fetch/XHR resolves.
            capture.record(path)
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            self._serve()

    return Handler


@dataclass
class _Server:
    base_url: str
    capture: _Capture
    _httpd: ThreadingHTTPServer
    _thread: threading.Thread

    def stop(self) -> None:
        self._httpd.shutdown()
        self._thread.join(timeout=5)


def _start_server() -> _Server:
    capture = _Capture()
    handler = _make_handler(capture, FIXTURES)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[0], httpd.server_address[1]
    return _Server(f"http://{host}:{port}", capture, httpd, thread)


# Each case: fixture, how to drive the source, and the exact traversed path the
# server must observe on the wire. ``drive`` returns the URL to open (fragment /
# query sources) or ``None`` when the page must be seeded via JS (postMessage /
# storage), handled explicitly in the test body.


@pytest.fixture(scope="module")
def browser():  # type: ignore[no-untyped-def]
    try:
        pw = playwright_sync.sync_playwright().start()
    except Exception as exc:  # pragma: no cover - env without playwright runtime
        pytest.skip(f"playwright runtime unavailable: {exc}")
    try:
        try:
            browser = pw.chromium.launch()
        except Exception as exc:  # pragma: no cover - chromium not installed
            pytest.skip(f"chromium not installed for playwright: {exc}")
        yield browser
        browser.close()
    finally:
        pw.stop()


@pytest.fixture()
def server():  # type: ignore[no-untyped-def]
    srv = _start_server()
    yield srv
    srv.stop()


def _drive(browser, url: str, *, before_load_js: str | None = None):  # type: ignore[no-untyped-def]
    """Open ``url`` in a fresh page, optionally running JS first, and wait for
    network to settle so the sink's request has left the browser."""
    context = browser.new_context()
    page = context.new_page()
    if before_load_js:
        page.add_init_script(before_load_js)
    page.goto(url, wait_until="networkidle")
    page.wait_for_timeout(150)
    context.close()


# --------------------------------------------------------------------------- #
# Positives — a traversed request must appear on the wire at the exact path.
# --------------------------------------------------------------------------- #

# Payloads use RAW ../ with literal slashes (browser-normalized dot-segments).
# The encoded fixture decodes at the app layer (decodeURIComponent), so it is
# fed a %2e%2e%2f payload that the page decodes before joining.


def test_positive_direct_traverses(browser, server) -> None:  # type: ignore[no-untyped-def]
    # #/orders/../../admin/keys -> orderId="../../admin/keys"
    # -> fetch("/api/orders/../../admin/keys/detail") -> /admin/keys/detail
    _drive(browser, f"{server.base_url}/positive_direct.html#/orders/../../admin/keys")
    assert server.capture.traversed == ["/admin/keys/detail"], server.capture


def test_positive_encoded_traverses(browser, server) -> None:  # type: ignore[no-untyped-def]
    # ?resource=%2e%2e%2f%2e%2e%2fadmin%2fconfig -> decoded to ../../admin/config
    # -> fetch("/api/resources/../../admin/config") -> /admin/config
    payload = "%2e%2e%2f%2e%2e%2fadmin%2fconfig"
    _drive(browser, f"{server.base_url}/positive_encoded.html?resource={payload}")
    assert server.capture.traversed == ["/admin/config"], server.capture


def test_positive_normalized_traverses(browser, server) -> None:  # type: ignore[no-untyped-def]
    # #/view/....//....//admin/settings survives the single-pass strip and
    # traverses. Assert the exact observed path rather than hand-computing it.
    _drive(
        browser,
        f"{server.base_url}/positive_normalized.html#/view/....//....//admin/settings",
    )
    assert len(server.capture.traversed) == 1, server.capture
    observed = server.capture.traversed[0]
    assert not observed.startswith("/api/"), observed
    assert "admin/settings" in observed, observed


def test_positive_postmessage_traverses(browser, server) -> None:  # type: ignore[no-untyped-def]
    # Post a crafted message after load; listener joins it into the path.
    context = browser.new_context()
    page = context.new_page()
    page.goto(f"{server.base_url}/positive_postmessage.html", wait_until="networkidle")
    page.evaluate("window.postMessage({ path: '../../admin/keys' }, '*')")
    page.wait_for_timeout(200)
    context.close()
    # fetch("/api/widgets/../../admin/keys") -> /admin/keys
    assert server.capture.traversed == ["/admin/keys"], server.capture


def test_positive_storage_traverses(browser, server) -> None:  # type: ignore[no-untyped-def]
    # Seed localStorage before the page script runs, then load.
    _drive(
        browser,
        f"{server.base_url}/positive_storage.html",
        before_load_js="localStorage.setItem('activeTenant', '../../admin')",
    )
    # api.get("/tenants/../../admin/summary") over baseURL "/api"
    # -> fetch("/api/tenants/../../admin/summary") -> /admin/summary
    assert server.capture.traversed == ["/admin/summary"], server.capture


# --------------------------------------------------------------------------- #
# Negatives — no traversed request may leave the browser.
# --------------------------------------------------------------------------- #


def test_negative_validated_emits_no_traversal(browser, server) -> None:  # type: ignore[no-untyped-def]
    # The allowlist rejects a traversal payload before the sink fires.
    _drive(browser, f"{server.base_url}/negative_validated.html#/orders/../../admin/keys")
    assert server.capture.traversed == [], server.capture
    assert server.capture.intended == [], server.capture  # guard failed -> no request at all


def test_negative_safe_construction_stays_on_constant_path(browser, server) -> None:  # type: ignore[no-untyped-def]
    # The value is a query param on a constant path; nothing escapes /api/.
    _drive(browser, f"{server.base_url}/negative_safe_construction.html?q=../../admin")
    assert server.capture.traversed == [], server.capture
    assert server.capture.intended, "expected the benign /api/search request to fire"
    assert all(p.startswith("/api/search") for p in server.capture.intended), server.capture


# --------------------------------------------------------------------------- #
# Browser URL-normalization ground truth (WHATWG). These pin the exact claim
# the review corrected: the browser collapses raw ``..`` dot-segments delimited
# by literal ``/``, but does NOT decode ``%2f`` into a separator, so an
# un-decoded ``..%2f..%2f`` stays a single literal segment and does not traverse.
# --------------------------------------------------------------------------- #


def _fetch_from_page(browser, server, url_to_fetch: str) -> list[str]:  # type: ignore[no-untyped-def]
    """Load a served origin, issue a raw ``fetch`` of ``url_to_fetch`` from the
    page (no application decoding in between), and return the path(s) the server
    observed off the wire."""
    context = browser.new_context()
    page = context.new_page()
    page.goto(f"{server.base_url}/positive_direct.html#noop", wait_until="networkidle")
    server.capture.intended.clear()
    server.capture.traversed.clear()
    page.evaluate("(u) => fetch(u).catch(() => {})", url_to_fetch)
    page.wait_for_timeout(200)
    context.close()
    return server.capture.traversed + server.capture.intended


def test_browser_collapses_raw_dotdot_with_literal_slashes(browser, server) -> None:  # type: ignore[no-untyped-def]
    # Raw ../ delimited by literal / IS collapsed by the URL parser.
    observed = _fetch_from_page(browser, server, "/api/orders/../../admin/keys")
    assert observed == ["/admin/keys"], observed
    assert not observed[0].startswith("/api/"), observed


def test_browser_does_not_decode_percent_2f_as_separator(browser, server) -> None:  # type: ignore[no-untyped-def]
    # ..%2f..%2f is a single literal segment: NOT decoded to ../../, so the path
    # does NOT escape the /api/ prefix. This is the exact misconception the
    # review flagged.
    observed = _fetch_from_page(browser, server, "/api/orders/..%2f..%2fadmin%2fkeys")
    assert len(observed) == 1, observed
    assert observed[0].startswith("/api/orders/"), observed
    # It did not collapse to /admin/keys.
    assert observed[0] != "/admin/keys", observed


def test_browser_collapses_encoded_dot_segments_with_literal_slashes(browser, server) -> None:  # type: ignore[no-untyped-def]
    # %2e%2e are recognized as dot-segments when delimited by literal / .
    observed = _fetch_from_page(browser, server, "/api/orders/%2e%2e/%2e%2e/admin/keys")
    assert observed == ["/admin/keys"], observed
