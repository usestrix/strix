"""Authorized-target scan queue for the local viewer / demo portal.

Hard gate: callers must set ``authorized=true`` after acknowledging they may
only scan systems they own or have written permission to test.

This does **not** invent exploit chains. Queued Strix scans are normal Strix
runs; DSA attack-path output remains MODELED. Simulated lateral stays OFF.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


AUTH_WARNING = (
    "Only scan systems you own or have explicit written permission to test. "
    "Unauthorized scanning may be illegal."
)

MODELED_NOTE = (
    "Attack-path graphs are MODELED (finding-derived + optional simulated "
    "scaffolding) — not confirmed multi-hop exploit chains. Simulated lateral "
    "stays OFF by default."
)

_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def normalize_target_url(raw: str) -> str | None:
    text = (raw or "").strip()
    if not text:
        return None
    if not _URL_RE.match(text):
        if "://" not in text and re.match(r"^[A-Za-z0-9._:-]+(/.*)?$", text):
            text = "https://" + text
        else:
            return None
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc or not parsed.hostname:
        return None
    return text


def _slug_from_url(url: str) -> str:
    host = (urlparse(url).hostname or "target").replace(".", "-")
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "-", host).strip("-").lower() or "target"
    return f"auth-{safe}-{stamp}"[:80]


def _find_strix_cmd(repo_root: Path | None) -> list[str] | None:
    if repo_root:
        venv = repo_root / ".venv" / "Scripts" / "strix.exe"
        if venv.is_file():
            return [str(venv)]
        if shutil.which("uv"):
            return ["uv", "run", "strix"]
    if shutil.which("strix"):
        return ["strix"]
    return None


def _find_repo_root(hint: Path | None) -> Path | None:
    if hint and (hint / "dsa_attack_path" / "CMakeLists.txt").is_file():
        return hint.resolve()
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "dsa_attack_path" / "CMakeLists.txt").is_file():
            return parent
    return None


def _write_ack(path: Path, url: str, action: str) -> None:
    ack = {
        "authorized": True,
        "acknowledged_at": datetime.now(UTC).isoformat(),
        "target_url": url,
        "action": action,
        "warning": AUTH_WARNING,
        "modeled_note": MODELED_NOTE,
        "simulated_lateral_default": False,
    }
    path.write_text(json.dumps(ack, indent=2) + "\n", encoding="utf-8")


def queue_authorized_scan(
    *,
    target_url: str,
    authorized: bool,
    runs_base: Path,
    repo_root: Path | None = None,
    scan_mode: str = "quick",
    start_process: bool = True,
) -> dict[str, Any]:
    """Validate authorization + URL, log ack, optionally spawn ``strix -n -t``.

    Never starts a scan when ``authorized`` is false.
    """
    if not authorized:
        return {
            "ok": False,
            "error": "authorization_required",
            "message": (
                "Refused: check the authorization box confirming you own this "
                "target or have written permission to test it."
            ),
            "warning": AUTH_WARNING,
            "modeled_note": MODELED_NOTE,
        }

    url = normalize_target_url(target_url)
    if not url:
        return {
            "ok": False,
            "error": "invalid_url",
            "message": "Provide a valid http(s) URL (e.g. https://example.com).",
            "warning": AUTH_WARNING,
            "modeled_note": MODELED_NOTE,
        }

    runs_base = runs_base.resolve()
    runs_base.mkdir(parents=True, exist_ok=True)
    queue_dir = runs_base / "_authorization_queue"
    queue_dir.mkdir(parents=True, exist_ok=True)
    job_name = _slug_from_url(url)
    ack_path = queue_dir / f"{job_name}.json"
    _write_ack(ack_path, url, action="queue_scan")

    repo = _find_repo_root(repo_root)
    cmd = _find_strix_cmd(repo)
    started = False
    skipped_reason: str | None = None
    spawn_cmd: list[str] | None = None

    if cmd is None:
        skipped_reason = (
            "Strix CLI not found. Authorization saved. Start manually after "
            f"`uv sync`: uv run strix -n -t {url} --scan-mode {scan_mode}"
        )
    else:
        spawn_cmd = [*cmd, "-n", "-t", url, "--scan-mode", scan_mode]
        if start_process:
            try:
                creationflags = 0
                if sys.platform == "win32":
                    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
                log_path = queue_dir / f"{job_name}.log"
                log_fh = log_path.open("w", encoding="utf-8")
                subprocess.Popen(  # noqa: S603 — operator-approved local spawn after auth gate
                    spawn_cmd,
                    cwd=str(repo) if repo else None,
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,
                    creationflags=creationflags,
                    env={**os.environ, "PYTHONUNBUFFERED": "1"},
                )
                started = True
            except OSError as exc:
                skipped_reason = f"Failed to spawn Strix: {exc}"
        else:
            skipped_reason = "start_process=false (dry queue)"

    return {
        "ok": True,
        "error": None,
        "action": "queue_scan",
        "message": (
            "Authorization recorded. Strix scan process started in the background."
            if started
            else "Authorization recorded. Use the command below to start the scan."
        ),
        "warning": AUTH_WARNING,
        "modeled_note": MODELED_NOTE,
        "target_url": url,
        "authorization_file": str(ack_path),
        "scan_started": started,
        "skipped_reason": skipped_reason,
        "command": spawn_cmd
        or ["strix", "-n", "-t", url, "--scan-mode", scan_mode],
        "next_steps": [
            "When the scan finishes (or while live): uv run strix view",
            "Then open the Attack path tab (MODELED graph; lateral OFF by default).",
            "If attack_path/ is missing: uv run strix attack-path <run> "
            "or python -m strix_dsa_backend <run>",
        ],
        "simulated_lateral_default": False,
    }


def stage_authorized_demo_fixture(
    *,
    target_url: str,
    authorized: bool,
    runs_base: Path,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Copy the synthetic DSA fixture into a new run labeled with the URL.

    For thesis demos without Docker/LLM. Clearly marked SYNTHETIC — not a live
    pentest. Still requires the authorization checkbox (user affirms the URL
    is one they may associate with a modeled demo).
    """
    if not authorized:
        return {
            "ok": False,
            "error": "authorization_required",
            "message": (
                "Refused: check the authorization box confirming you own this "
                "target or have written permission to test it."
            ),
            "warning": AUTH_WARNING,
            "modeled_note": MODELED_NOTE,
        }

    url = normalize_target_url(target_url)
    if not url:
        return {
            "ok": False,
            "error": "invalid_url",
            "message": "Provide a valid http(s) URL (e.g. https://example.com).",
            "warning": AUTH_WARNING,
            "modeled_note": MODELED_NOTE,
        }

    repo = _find_repo_root(repo_root)
    if repo is None:
        return {
            "ok": False,
            "error": "repo_not_found",
            "message": "Cannot locate dsa_attack_path in this checkout.",
            "warning": AUTH_WARNING,
            "modeled_note": MODELED_NOTE,
        }

    sample = repo / "dsa_attack_path" / "backend" / "fixtures" / "sample_run_dir"
    engine = repo / "dsa_attack_path" / "build" / "strix_dsa_cli.exe"
    # Ensure fixture + attack_path exist
    backend = repo / "dsa_attack_path" / "backend"
    make_fx = backend / "fixtures" / "make_fixture_run.py"
    if make_fx.is_file():
        subprocess.run(  # noqa: S603
            [sys.executable, str(make_fx), str(sample)],
            cwd=str(backend),
            check=False,
            capture_output=True,
            text=True,
        )
    if engine.is_file():
        subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-m",
                "strix_dsa_backend",
                str(sample),
                "--engine",
                str(engine),
            ],
            cwd=str(backend),
            check=False,
            capture_output=True,
            text=True,
        )

    runs_base = runs_base.resolve()
    runs_base.mkdir(parents=True, exist_ok=True)
    run_name = _slug_from_url(url).replace("auth-", "demo-", 1)
    dest = runs_base / run_name
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    if sample.is_dir():
        for item in sample.iterdir():
            target = dest / item.name
            if item.is_dir():
                shutil.copytree(item, target)
            else:
                shutil.copy2(item, target)

    _write_ack(dest / "AUTHORIZATION.json", url, action="demo_fixture")
    run_json_path = dest / "run.json"
    try:
        run_record = json.loads(run_json_path.read_text(encoding="utf-8"))
        if not isinstance(run_record, dict):
            run_record = {}
    except (OSError, json.JSONDecodeError):
        run_record = {}
    run_record.update(
        {
            "run_name": run_name,
            "targets": [url],
            "status": "completed",
            "fixture": True,
            "disclaimer": (
                "SYNTHETIC fixture labeled with your authorized URL for thesis "
                "Attack Path demo — not live pentest results. " + MODELED_NOTE
            ),
        }
    )
    run_json_path.write_text(json.dumps(run_record, indent=2) + "\n", encoding="utf-8")

    return {
        "ok": True,
        "error": None,
        "action": "demo_fixture",
        "message": (
            "Authorization recorded. Staged a SYNTHETIC modeled Attack Path demo "
            "run labeled with your URL (not live scan findings)."
        ),
        "warning": AUTH_WARNING,
        "modeled_note": MODELED_NOTE,
        "target_url": url,
        "run_name": run_name,
        "run_dir": str(dest),
        "scan_started": False,
        "next_steps": [
            f"Open viewer: uv run strix view {run_name}",
            "Go to the Attack path tab — BFS / Dijkstra / Bottleneck highlights are MODELED.",
        ],
        "simulated_lateral_default": False,
    }
