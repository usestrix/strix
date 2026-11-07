#!/usr/bin/env python3
"""Minimal local page: paste authorized URL → queue scan / stage demo.

Opens a small stdlib HTTP UI so users do not need a prior ``strix view`` session.
For the full Attack Path graph, prefer the viewer Attack path tab after staging.
"""

from __future__ import annotations

import json
import sys
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[2]


def _load_authorized_scan():
    """Load authorized_scan.py without importing strix.interface.viewer package.

    ``viewer/__init__.py`` pulls the TUI/MCP stack; the portal only needs the
    gate helpers.
    """
    import importlib.util

    path = ROOT / "strix" / "interface" / "viewer" / "authorized_scan.py"
    spec = importlib.util.spec_from_file_location("authorized_scan_portal", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_auth = _load_authorized_scan()
AUTH_WARNING = _auth.AUTH_WARNING
MODELED_NOTE = _auth.MODELED_NOTE
queue_authorized_scan = _auth.queue_authorized_scan
stage_authorized_demo_fixture = _auth.stage_authorized_demo_fixture


HTML = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DSA authorized target</title>
  <style>
    :root {{ color-scheme: dark; font-family: ui-sans-serif, system-ui, sans-serif; }}
    body {{ margin: 0; background: #0b0b0b; color: #ddd; }}
    main {{ max-width: 40rem; margin: 2rem auto; padding: 0 1rem; }}
    h1 {{ font-size: 1.25rem; color: #fff; }}
    .warn {{ border: 1px solid #b45309; background: #422006; padding: .75rem 1rem;
             border-radius: .5rem; font-size: .85rem; margin: 1rem 0; }}
    label {{ display: block; font-size: .8rem; color: #999; margin: .75rem 0 .25rem; }}
    input[type=url] {{ width: 100%; box-sizing: border-box; padding: .6rem .75rem;
      border-radius: .4rem; border: 1px solid #333; background: #111; color: #eee; }}
    .auth {{ display: flex; gap: .5rem; align-items: flex-start; font-size: .85rem; margin: 1rem 0; }}
    button {{ margin-right: .5rem; margin-top: .5rem; padding: .5rem .9rem; border-radius: .4rem;
      border: 1px solid #065f46; background: #064e3b; color: #a7f3d0; cursor: pointer; }}
    button.secondary {{ border-color: #075985; background: #0c4a6e; color: #bae6fd; }}
    button:disabled {{ opacity: .4; cursor: not-allowed; }}
    pre {{ white-space: pre-wrap; background: #111; border: 1px solid #222; padding: .75rem;
      border-radius: .4rem; font-size: .75rem; }}
    .note {{ font-size: .75rem; color: #888; margin-top: 1rem; }}
  </style>
</head>
<body>
<main>
  <h1>Authorized target URL</h1>
  <p class="note">{MODELED_NOTE}</p>
  <div class="warn">{AUTH_WARNING}</div>
  <label for="url">Target URL</label>
  <input id="url" type="url" placeholder="https://your-authorized-lab.example" />
  <label class="auth">
    <input id="auth" type="checkbox" />
    <span>I confirm I own this system or have written authorization to test it.</span>
  </label>
  <button id="scan" disabled>Queue authorized Strix scan</button>
  <button id="demo" class="secondary" disabled>Stage MODELED Attack Path demo</button>
  <pre id="out">Waiting for input…</pre>
  <p class="note">After staging, run <code>uv run strix view &lt;run&gt;</code> and open the
  <strong>Attack path</strong> tab for BFS / Dijkstra / bottleneck highlights.</p>
</main>
<script>
const url = document.getElementById('url');
const auth = document.getElementById('auth');
const scan = document.getElementById('scan');
const demo = document.getElementById('demo');
const out = document.getElementById('out');
function sync() {{
  const ok = auth.checked && url.value.trim().length > 0;
  scan.disabled = !ok; demo.disabled = !ok;
}}
auth.addEventListener('change', sync);
url.addEventListener('input', sync);
async function post(action) {{
  out.textContent = 'Submitting…';
  const res = await fetch('/api/authorized-scan', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{ url: url.value, authorized: auth.checked, action }})
  }});
  const data = await res.json();
  out.textContent = JSON.stringify(data, null, 2);
}}
scan.onclick = () => post('queue_scan');
demo.onclick = () => post('demo_fixture');
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("portal: " + (fmt % args) + "\n")

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in {"/", "/index.html"}:
            self._send(HTTPStatus.OK, HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        self._send(HTTPStatus.NOT_FOUND, b'{"error":"not found"}', "application/json")

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/api/authorized-scan":
            self._send(HTTPStatus.NOT_FOUND, b'{"error":"not found"}', "application/json")
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        authorized = body.get("authorized") is True
        target = str(body.get("url") or "")
        action = str(body.get("action") or "queue_scan")
        runs = ROOT / "strix_runs"
        if action == "demo_fixture":
            payload = stage_authorized_demo_fixture(
                target_url=target,
                authorized=authorized,
                runs_base=runs,
                repo_root=ROOT,
            )
        else:
            payload = queue_authorized_scan(
                target_url=target,
                authorized=authorized,
                runs_base=runs,
                repo_root=ROOT,
                start_process=True,
            )
        code = HTTPStatus.OK if payload.get("ok") else HTTPStatus.BAD_REQUEST
        if payload.get("error") == "authorization_required":
            code = HTTPStatus.FORBIDDEN
        data = json.dumps(payload, indent=2).encode("utf-8")
        self._send(code, data, "application/json; charset=utf-8")


def main() -> int:
    host, port = "127.0.0.1", 8765
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"DSA authorized-target portal at {url}")
    print(AUTH_WARNING)
    print(MODELED_NOTE)
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001
        pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
