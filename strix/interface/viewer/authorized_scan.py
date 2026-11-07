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
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse


AUTH_WARNING = (
    "Only scan systems you own or have explicit written permission to test. "
    "Unauthorized scanning may be illegal."
)

MODELED_NOTE = (
    "Attack-path graphs are MODELED (finding-derived + optional simulated "
    "scaffolding) — not confirmed multi-hop exploit chains. Simulated lateral "
    "stays OFF by default."
)

SYNTHETIC_BANNER = (
    "SYNTHETIC DEMO RUN — sample findings for thesis Attack Path UI. "
    "Not a live Strix pentest of your URL. Do not treat Issues as real vulns "
    "on the authorized target."
)

_URL_RE = re.compile(r"^https?://", re.IGNORECASE)

_FAIL_MARKERS = (
    "DOCKER NOT INSTALLED",
    "docker' CLI was not found",
    "Docker daemon is not running",
    "Cannot connect to the Docker daemon",
    "LLM_API_KEY",
    "STRIX_LLM",
    "No API key",
    "authentication failed",
    "litellm",
)


def normalize_target_url(raw: str) -> str | None:
    """Normalize http(s) URL; strip fragments (#...) before scanning."""
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
    # Drop SPA fragments (e.g. https://host/#/home) — scanners should not keep them.
    cleaned = parsed._replace(fragment="")
    return urlunparse(cleaned)


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


def _docker_preflight() -> str | None:
    """Return an error message if Docker CLI/daemon is unusable; else None."""
    if shutil.which("docker") is None:
        return (
            "DOCKER NOT INSTALLED — the `docker` CLI was not found in PATH. "
            "Install Docker Desktop, ensure `docker` works, then retry the "
            "authorized scan. (A SYNTHETIC Attack Path demo does not need Docker.)"
        )
    try:
        completed = subprocess.run(  # noqa: S603
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"Docker preflight failed: {exc}"
    if completed.returncode != 0:
        err = (completed.stderr or completed.stdout or "").strip()
        return (
            "Docker daemon is not usable "
            f"(exit {completed.returncode}). {err[:400]}"
        )
    return None


def _classify_log(text: str) -> str | None:
    upper = text.upper()
    for marker in _FAIL_MARKERS:
        if marker.upper() in upper:
            # Return a short human line around the marker when possible.
            for line in text.splitlines():
                if marker.upper() in line.upper():
                    return line.strip()[:300]
            return marker
    return None


def _wait_spawn(
    proc: subprocess.Popen[Any],
    log_path: Path,
    *,
    settle_s: float = 2.5,
) -> tuple[bool, str | None, int | None]:
    """Return (alive_or_ok, error_message, returncode)."""
    deadline = time.time() + settle_s
    while time.time() < deadline:
        rc = proc.poll()
        if rc is not None:
            break
        time.sleep(0.15)
    else:
        rc = proc.poll()

    log_text = ""
    try:
        # Flush-friendly: reopen for read after brief settle.
        if log_path.is_file():
            log_text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        log_text = ""

    marker = _classify_log(log_text) if log_text else None
    if rc is None:
        # Still running — treat as started unless log already shows a fatal banner.
        if marker:
            return False, marker, None
        return True, None, None
    if rc == 0:
        return True, None, rc
    if marker:
        return False, marker, rc
    tail = log_text.strip()[-500:] if log_text.strip() else f"exit code {rc}"
    return False, tail, rc


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

    Never starts a scan when ``authorized`` is false. ``scan_started`` is true
    only if the process is still alive (or exited 0) after a short settle and
    the log does not show a fatal Docker/LLM banner.
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
    log_path = queue_dir / f"{job_name}.log"
    _write_ack(ack_path, url, action="queue_scan")

    repo = _find_repo_root(repo_root)
    cmd = _find_strix_cmd(repo)
    spawn_cmd: list[str] | None = None
    log_excerpt: str | None = None

    if cmd is None:
        return {
            "ok": False,
            "error": "strix_not_found",
            "message": (
                "Authorization saved, but Strix CLI was not found. "
                f"After `uv sync`, run: uv run strix -n -t {url} --scan-mode {scan_mode}"
            ),
            "warning": AUTH_WARNING,
            "modeled_note": MODELED_NOTE,
            "target_url": url,
            "authorization_file": str(ack_path),
            "scan_started": False,
            "command": ["strix", "-n", "-t", url, "--scan-mode", scan_mode],
            "switch_to_run": None,
            "simulated_lateral_default": False,
        }

    if not start_process:
        return {
            "ok": True,
            "error": None,
            "action": "queue_scan",
            "message": "Authorization recorded (dry queue; process not started).",
            "warning": AUTH_WARNING,
            "modeled_note": MODELED_NOTE,
            "target_url": url,
            "authorization_file": str(ack_path),
            "scan_started": False,
            "skipped_reason": "start_process=false (dry queue)",
            "command": [*cmd, "-n", "-t", url, "--scan-mode", scan_mode],
            "switch_to_run": None,
            "simulated_lateral_default": False,
        }

    docker_err = _docker_preflight()
    if docker_err:
        log_path.write_text(docker_err + "\n", encoding="utf-8")
        return {
            "ok": False,
            "error": "docker_unavailable",
            "message": docker_err,
            "warning": AUTH_WARNING,
            "modeled_note": MODELED_NOTE,
            "target_url": url,
            "authorization_file": str(ack_path),
            "log_file": str(log_path),
            "log_excerpt": docker_err,
            "scan_started": False,
            "command": [*cmd, "-n", "-t", url, "--scan-mode", scan_mode],
            "next_steps": [
                "Install/start Docker Desktop so `docker info` succeeds.",
                "Or use **Stage MODELED Attack Path demo** for a SYNTHETIC fixture "
                "(not a live scan of the URL).",
                "This viewer may still be showing an older fixture run (e.g. dsa-demo) "
                "— that is unrelated to the failed queue.",
            ],
            "switch_to_run": None,
            "simulated_lateral_default": False,
        }

    spawn_cmd = [*cmd, "-n", "-t", url, "--scan-mode", scan_mode]
    try:
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        log_fh = log_path.open("w", encoding="utf-8")
        proc = subprocess.Popen(  # noqa: S603 — operator-approved local spawn after auth gate
            spawn_cmd,
            cwd=str(repo) if repo else None,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
    except OSError as exc:
        return {
            "ok": False,
            "error": "spawn_failed",
            "message": f"Failed to spawn Strix: {exc}",
            "warning": AUTH_WARNING,
            "modeled_note": MODELED_NOTE,
            "target_url": url,
            "authorization_file": str(ack_path),
            "scan_started": False,
            "command": spawn_cmd,
            "switch_to_run": None,
            "simulated_lateral_default": False,
        }

    alive, err, rc = _wait_spawn(proc, log_path)
    try:
        log_excerpt = log_path.read_text(encoding="utf-8", errors="replace")[-800:]
    except OSError:
        log_excerpt = None

    if not alive:
        return {
            "ok": False,
            "error": "scan_exited",
            "message": (
                "Strix process exited before a live run appeared. "
                f"Detail: {err or f'exit {rc}'}"
            ),
            "warning": AUTH_WARNING,
            "modeled_note": MODELED_NOTE,
            "target_url": url,
            "authorization_file": str(ack_path),
            "log_file": str(log_path),
            "log_excerpt": log_excerpt,
            "scan_started": False,
            "returncode": rc,
            "command": spawn_cmd,
            "next_steps": [
                "Fix the error in log_excerpt (often Docker or LLM API key).",
                "Or stage a SYNTHETIC Attack Path demo (not a live scan).",
                "Do not assume the currently open viewer run is this target.",
            ],
            "switch_to_run": None,
            "simulated_lateral_default": False,
        }

    return {
        "ok": True,
        "error": None,
        "action": "queue_scan",
        "message": (
            "Authorization recorded. Strix appears to be running in the background. "
            "When a new folder appears under strix_runs/, open it via Past runs "
            "or `uv run strix view <run>` — this viewer window may still show an "
            "older fixture until you switch."
        ),
        "warning": AUTH_WARNING,
        "modeled_note": MODELED_NOTE,
        "target_url": url,
        "authorization_file": str(ack_path),
        "log_file": str(log_path),
        "log_excerpt": log_excerpt,
        "scan_started": True,
        "command": spawn_cmd,
        "next_steps": [
            "Wait for a new run under ./strix_runs/ (name usually includes the host).",
            "In this viewer: Past runs → select the new run (or restart: uv run strix view <run>).",
            "Attack path tab after findings exist + `strix attack-path <run>`.",
        ],
        "switch_to_run": None,
        "simulated_lateral_default": False,
    }


def _relabel_fixture_for_url(dest: Path, url: str, run_name: str) -> None:
    """Make the synthetic run obviously not a live pentest of ``url``."""
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
            "run_id": f"synthetic-{run_name}",
            "targets": [url],
            "targets_info": [{"original": url, "note": "authorized URL label only"}],
            "status": "completed",
            "fixture": True,
            "synthetic_demo": True,
            "end_time": datetime.now(UTC).isoformat(),
            "note": SYNTHETIC_BANNER,
            "disclaimer": SYNTHETIC_BANNER + " " + MODELED_NOTE,
        }
    )
    run_json_path.write_text(json.dumps(run_record, indent=2) + "\n", encoding="utf-8")

    vulns_path = dest / "vulnerabilities.json"
    try:
        vulns = json.loads(vulns_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        vulns = []
    if isinstance(vulns, list):
        for item in vulns:
            if not isinstance(item, dict):
                continue
            item["target"] = url
            item["title"] = f"[SYNTHETIC DEMO] {item.get('title') or 'sample finding'}"
            desc = str(item.get("description") or "")
            item["description"] = (
                SYNTHETIC_BANNER + "\n\n" + desc
                if desc
                else SYNTHETIC_BANNER
            )
        vulns_path.write_text(json.dumps(vulns, indent=2) + "\n", encoding="utf-8")

    (dest / "SYNTHETIC_DEMO.txt").write_text(SYNTHETIC_BANNER + "\n", encoding="utf-8")


def stage_authorized_demo_fixture(
    *,
    target_url: str,
    authorized: bool,
    runs_base: Path,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Copy the synthetic DSA fixture into a new run labeled with the URL.

    For thesis demos without Docker/LLM. Clearly marked SYNTHETIC — not a live
    pentest. Still requires the authorization checkbox.
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
    _relabel_fixture_for_url(dest, url, run_name)

    return {
        "ok": True,
        "error": None,
        "action": "demo_fixture",
        "message": (
            "Authorization recorded. Opened a SYNTHETIC modeled demo run labeled "
            f"with {url}. Issues are sample data — not live findings on that host."
        ),
        "warning": AUTH_WARNING,
        "modeled_note": MODELED_NOTE,
        "synthetic_banner": SYNTHETIC_BANNER,
        "target_url": url,
        "run_name": run_name,
        "run_dir": str(dest),
        "scan_started": False,
        "switch_to_run": run_name,
        "next_steps": [
            f"This UI should switch to run `{run_name}` (Past runs if not).",
            "Attack path tab shows MODELED BFS/DJ/BN — not confirmed exploits.",
            "For a real scan you need Docker + LLM keys, then Queue authorized Strix scan.",
        ],
        "simulated_lateral_default": False,
    }
