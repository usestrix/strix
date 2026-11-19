"""Serves Strix's own viewer SPA against the frontal's artifact store.

The SPA shipped in ``strix/interface/viewer/static`` is a prebuilt bundle that
talks to five read-only JSON endpoints. Reimplementing those endpoints here —
rather than running ``strix view`` and proxying it — is what lets the existing
results UI read the frontal's artifact store: the upstream server reads one
run directory off local disk and gates everything beyond it behind an email
OTP round-trip to Strix's relay.

Runs are addressed by scan id, not by the CLI-generated run name, so nothing
collides across apps. The payload shapes mirror
``strix.interface.viewer.server`` exactly; the SPA is unmodified.
"""

from __future__ import annotations

import mimetypes
from pathlib import Path

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from frontal.app.config import Settings, get_settings
from frontal.app.db import get_session
from frontal.app.models import Scan
from strix.interface.viewer.server import bundle_dir
from strix.interface.viewer.transcript import (
    build_run_state,
    primary_target,
    read_report_markdown,
    read_run_summary,
    read_vulnerabilities,
    severity_counts,
)


# The SPA remembers which run it is showing through this cookie, set when the
# page is served at /runs/<scan_id>. Its own first data fetch carries no
# ``?run=`` yet, and the bundle is not modified to add one.
RUN_COOKIE = "frontal_run"

router = APIRouter()


def _run_dir(settings: Settings, scan: Scan) -> Path | None:
    if not scan.artifact_path:
        return None
    candidate = (settings.artifacts_dir / scan.artifact_path).resolve()
    root = settings.artifacts_dir.resolve()
    if root != candidate and root not in candidate.parents:
        return None
    return candidate if (candidate / "run.json").is_file() else None


def _resolve_scan(
    session: Session,
    settings: Settings,
    run: str | None,
    cookie_run: str | None,
) -> tuple[Scan, Path]:
    raw = run or cookie_run
    scan: Scan | None = None
    if raw and raw.isdigit():
        scan = session.get(Scan, int(raw))
    if scan is None:
        scan = session.scalar(
            select(Scan).where(Scan.artifact_path.is_not(None)).order_by(Scan.id.desc()).limit(1)
        )
    if scan is None:
        raise HTTPException(status_code=404, detail="unknown run")
    run_dir = _run_dir(settings, scan)
    if run_dir is None:
        raise HTTPException(status_code=404, detail="run artifacts unavailable")
    return scan, run_dir


@router.get("/api/capabilities")
def capabilities() -> dict[str, bool]:
    # Steering needs to share a process with a live scan; the frontal launches
    # scans as separate processes, so it can never offer it.
    return {"can_steer": False}


@router.get("/api/auth/status")
def auth_status() -> dict[str, object]:
    # The SPA hides run history until this reports verified. Answered locally:
    # no email is collected and Strix's relay is never hit.
    return {"verified": True, "email": None}


@router.get("/api/runs")
def runs(
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    scans = session.scalars(
        select(Scan).where(Scan.artifact_path.is_not(None)).order_by(Scan.id.desc()).limit(100)
    ).all()

    entries = []
    for scan in scans:
        run_dir = _run_dir(settings, scan)
        if run_dir is None:
            continue
        record = read_run_summary(run_dir)
        entries.append(
            {
                "name": str(scan.id),
                "target": primary_target(record) or scan.app.target,
                "scan_mode": scan.scan_mode,
                "status": record.get("status") or scan.status,
                "start_time": record.get("start_time"),
                "end_time": record.get("end_time"),
                "finished": bool(record.get("finished")),
                "severity_counts": severity_counts(read_vulnerabilities(run_dir)),
            }
        )
    return {"locked": False, "count": len(entries), "runs": entries}


@router.get("/api/run")
def run_summary(
    run: str | None = Query(default=None),
    frontal_run: str | None = Cookie(default=None, alias=RUN_COOKIE),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    _scan, run_dir = _resolve_scan(session, settings, run, frontal_run)
    return read_run_summary(run_dir)


@router.get("/api/vulnerabilities")
def vulnerabilities(
    run: str | None = Query(default=None),
    frontal_run: str | None = Cookie(default=None, alias=RUN_COOKIE),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> list[object]:
    _scan, run_dir = _resolve_scan(session, settings, run, frontal_run)
    return read_vulnerabilities(run_dir)


@router.get("/api/report")
def report(
    run: str | None = Query(default=None),
    frontal_run: str | None = Cookie(default=None, alias=RUN_COOKIE),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    _scan, run_dir = _resolve_scan(session, settings, run, frontal_run)
    return {"markdown": read_report_markdown(run_dir)}


@router.get("/api/transcript")
def transcript(
    run: str | None = Query(default=None),
    frontal_run: str | None = Cookie(default=None, alias=RUN_COOKIE),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    _scan, run_dir = _resolve_scan(session, settings, run, frontal_run)
    return build_run_state(run_dir)


# The bundle posts to these. They are answered rather than 404'd so the SPA's
# error paths stay quiet, but nothing is relayed to Strix's servers.
@router.post("/api/event", status_code=204)
def swallow_event() -> Response:
    return Response(status_code=204)


@router.post("/api/feedback")
def feedback_unavailable() -> JSONResponse:
    return JSONResponse({"ok": False, "error": "unavailable"}, status_code=404)


@router.post("/api/report/send")
def report_send_unavailable() -> JSONResponse:
    # Upstream this uploads the PDF to Strix's relay; reports stay in-house.
    return JSONResponse({"ok": False, "error": "unavailable"}, status_code=404)


@router.post("/api/agents/steer")
def steer_unavailable() -> JSONResponse:
    return JSONResponse({"ok": False, "error": "steering_unavailable"}, status_code=403)


@router.get("/runs/{path:path}")
def viewer_spa(path: str) -> Response:
    """Serve the SPA bundle; any non-asset path renders the app shell.

    The bundle references its assets relatively (``./assets/...``), so it is
    served under this one prefix and ``/runs/<scan_id>`` resolves them to
    ``/runs/assets/...`` without touching the build.
    """
    root = bundle_dir()
    candidate = (root / path).resolve()
    if path and (root == candidate or root in candidate.parents) and candidate.is_file():
        content_type, _encoding = mimetypes.guess_type(str(candidate))
        return FileResponse(candidate, media_type=content_type or "application/octet-stream")

    index = root / "index.html"
    if not index.is_file():
        raise HTTPException(status_code=503, detail="viewer bundle not built")

    response = HTMLResponse(index.read_text(encoding="utf-8"))
    scan_id = path.strip("/")
    if scan_id.isdigit():
        response.set_cookie(RUN_COOKIE, scan_id, httponly=True, samesite="strict", path="/")
    return response
