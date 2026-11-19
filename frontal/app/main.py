"""Strix frontal: web console + REST API in front of the Kafka orchestrator.

The frontal never runs Strix. Launching a scan writes a ``scans`` row and
publishes it to ``audit.request``; the orchestrator (one KEDA Job per request)
runs it and answers on ``audit.result``, which :mod:`frontal.app.audit` folds
back into the database. See that module for the message contract.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from frontal.app.audit import (
    AuditProducer,
    AuditRequestError,
    AuditResultConsumer,
    build_audit_request,
)
from frontal.app.config import get_settings
from frontal.app.db import SessionLocal, get_session, init_db
from frontal.app.instruction_builder import UnknownTemplateError, builder_config, render_instruction
from frontal.app.models import App, Finding, FindingObservation, FindingTriage, Scan
from frontal.app.retest import build_retest_instruction, build_verify_instruction, finding_ref
from frontal.app.runfiles import read_report_markdown
from frontal.app.templates import INSTRUCTION_TEMPLATES, SCAN_MODE_INFO


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)

# The agent-transcript viewer is Strix's own SPA and needs the Strix package.
# Everything else works without it, so a slim image simply loses that one view.
try:
    from frontal.app.viewer_api import router as viewer_router
except ImportError as exc:  # pragma: no cover - depends on the image
    logger.warning("Strix viewer unavailable (%s); agent transcripts disabled", exc)
    viewer_router = None

ScanMode = Literal["quick", "standard", "deep"]
ScopeMode = Literal["auto", "diff", "full"]
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@asynccontextmanager
async def lifespan(api: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    settings.artifacts_dir.mkdir(parents=True, exist_ok=True)
    init_db()
    api.state.producer = AuditProducer(SessionLocal, settings)
    api.state.consumer = AuditResultConsumer(SessionLocal, settings)
    api.state.consumer.start()
    yield
    api.state.consumer.shutdown()
    api.state.producer.shutdown()


app = FastAPI(title="Strix Frontal", lifespan=lifespan)


def get_producer(request: Request) -> AuditProducer:
    producer = getattr(request.app.state, "producer", None)
    if producer is None:
        raise HTTPException(status_code=503, detail="producer not started")
    return producer


# ── Schemas ─────────────────────────────────────────────────────────────────


class AppIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1)
    environment: str | None = Field(default=None, max_length=50)


class ScanIn(BaseModel):
    # Defaults to the app's target; set it to scan another URL of the same asset.
    target: str | None = None
    scan_mode: ScanMode = "quick"
    instruction: str | None = None
    max_budget: float | None = Field(default=None, gt=0)
    scope_mode: ScopeMode | None = None


class PreviewIn(ScanIn):
    app_id: int | None = None


class RetestIn(BaseModel):
    finding_ids: list[int] | None = None
    scan_mode: ScanMode = "quick"
    max_budget: float | None = Field(default=None, gt=0)


class BuilderValueIn(BaseModel):
    value: str | None = Field(default=None, max_length=20000)
    selected: list[str] = Field(default_factory=list, max_length=50)
    custom: str | None = Field(default=None, max_length=5000)
    na: bool = False
    na_reason: str | None = Field(default=None, max_length=2000)


class BuilderRenderIn(BaseModel):
    template: str
    values: dict[str, BuilderValueIn] = Field(default_factory=dict)


class FindingPatch(BaseModel):
    status: Literal["open", "fixed", "accepted", "false_positive", "doubtful"]


# A false positive hides a finding from every later scan of the app, so it must
# say why; "x" is not a reason.
MIN_FP_JUSTIFICATION = 10
TRIAGE_ONLY_STATUSES = ("false_positive", "doubtful")


class TriageIn(BaseModel):
    decision: Literal["true_positive", "false_positive", "doubtful"]
    # Required for false_positive; for doubtful it is passed to the verify scan.
    justification: str | None = Field(default=None, max_length=5000)
    author: str | None = Field(default=None, max_length=200)
    # Only used by "doubtful", which launches a verify scan of this one finding.
    scan_mode: ScanMode = "quick"
    max_budget: float | None = Field(default=None, gt=0)


# ── Serializers ─────────────────────────────────────────────────────────────


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _app_json(row: App, open_findings: int = 0, scan_count: int = 0) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "target": row.target,
        "environment": row.environment,
        "open_findings": open_findings,
        "scan_count": scan_count,
        "created_at": _iso(row.created_at),
    }


def _scan_json(row: Scan, severity_counts: dict[str, int] | None = None) -> dict[str, Any]:
    result = row.result or {}
    usage = row.llm_usage or {}
    return {
        "id": row.id,
        "app_id": row.app_id,
        "app_name": row.app.name if row.app else None,
        "kind": row.kind,
        "status": row.status,
        "scan_mode": row.scan_mode,
        "target": row.target or (row.app.target if row.app else None),
        "max_budget": row.max_budget,
        "scope_mode": row.scope_mode,
        "request_id": row.request_id,
        "run_name": row.run_name,
        "created_at": _iso(row.created_at),
        "started_at": _iso(row.started_at),
        "ended_at": _iso(row.ended_at),
        "error": row.error,
        "cost": usage.get("cost") if usage.get("cost") is not None else result.get("cost"),
        "has_artifacts": bool(row.artifact_path),
        "retest_finding_ids": row.retest_finding_ids,
        "parent_scan_id": row.parent_scan_id,
        "severity_counts": severity_counts or {},
    }


def _finding_json(row: Finding) -> dict[str, Any]:
    return {
        "id": row.id,
        "ref": finding_ref(row),
        "app_id": row.app_id,
        "app_name": row.app.name if row.app else None,
        "title": row.title,
        "severity": row.severity,
        "cvss": row.cvss,
        "cwe": row.cwe,
        "method": row.method,
        "endpoint": row.endpoint,
        "status": row.status,
        "triage": row.triage,
        "last_verdict": row.last_verdict,
        "first_seen_scan_id": row.first_seen_scan_id,
        "last_seen_scan_id": row.last_seen_scan_id,
        "last_retest_scan_id": row.last_retest_scan_id,
        "updated_at": _iso(row.updated_at),
    }


def _sort_findings(rows: list[Finding]) -> list[Finding]:
    return sorted(rows, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -(f.cvss or 0), f.id))


def _scan_severity_counts(session: Session, scan_ids: list[int]) -> dict[int, dict[str, int]]:
    if not scan_ids:
        return {}
    rows = session.execute(
        select(FindingObservation.scan_id, Finding.severity, func.count())
        .join(Finding, Finding.id == FindingObservation.finding_id)
        .where(FindingObservation.scan_id.in_(scan_ids))
        .where(FindingObservation.verdict.in_(("observed", "still_vulnerable")))
        .group_by(FindingObservation.scan_id, Finding.severity)
    ).all()
    out: dict[int, dict[str, int]] = {}
    for scan_id, severity, count in rows:
        out.setdefault(scan_id, {})[severity] = count
    return out


def _get_or_404(session: Session, model: type, row_id: int, what: str) -> Any:
    row = session.get(model, row_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"unknown {what}")
    return row


def _launch(
    session: Session,
    producer: AuditProducer,
    scan: Scan,
) -> dict[str, Any]:
    # Validate before the row exists, so a bad request never shows up as a scan.
    try:
        build_audit_request(
            request_id="preview",
            target=scan.target or "",
            scan_mode=scan.scan_mode,
            instruction=scan.instruction,
            max_budget=scan.max_budget,
            scope_mode=scan.scope_mode,
        )
    except AuditRequestError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    session.add(scan)
    session.commit()
    published = producer.submit(scan.id)
    session.refresh(scan)
    if published.status == "failed":
        raise HTTPException(status_code=502, detail=published.error)
    return _scan_json(scan)


def _default_budget(value: float | None) -> float | None:
    return value if value is not None else get_settings().max_budget_usd


# ── Meta ────────────────────────────────────────────────────────────────────


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/manage/config")
def ui_config(request: Request) -> dict[str, Any]:
    settings = get_settings()
    consumer = getattr(request.app.state, "consumer", None)
    return {
        "scan_modes": SCAN_MODE_INFO,
        "templates": INSTRUCTION_TEMPLATES,
        "default_max_budget": settings.max_budget_usd,
        "topics": {
            "request": settings.audit_topic_request,
            "result": settings.audit_topic_result,
            "status": settings.audit_topic_status,
        },
        "kafka_connected": bool(consumer and consumer.connected),
        "viewer_available": viewer_router is not None,
    }


@app.get("/manage/instruction-builder")
def instruction_builder() -> dict[str, Any]:
    return builder_config()


@app.post("/manage/instruction-builder/render")
def instruction_builder_render(body: BuilderRenderIn) -> dict[str, Any]:
    values = {k: v.model_dump() for k, v in body.values.items()}
    try:
        return render_instruction(body.template, values)
    except UnknownTemplateError as exc:
        raise HTTPException(status_code=404, detail=f"unknown template {body.template!r}") from exc


@app.get("/manage/stats")
def stats(session: Session = Depends(get_session)) -> dict[str, Any]:
    by_severity = dict(
        session.execute(
            select(Finding.severity, func.count())
            .where(Finding.status == "open")
            .group_by(Finding.severity)
        ).all()
    )
    by_status = dict(
        session.execute(select(Finding.status, func.count()).group_by(Finding.status)).all()
    )
    scans_by_status = dict(
        session.execute(select(Scan.status, func.count()).group_by(Scan.status)).all()
    )
    total_cost = 0.0
    for usage in session.scalars(select(Scan.llm_usage).where(Scan.llm_usage.is_not(None))):
        with contextlib.suppress(TypeError, ValueError):
            total_cost += float((usage or {}).get("cost") or 0)
    return {
        "apps": session.scalar(select(func.count(App.id))) or 0,
        "open_by_severity": by_severity,
        "findings_by_status": by_status,
        "scans_by_status": scans_by_status,
        "total_cost": round(total_cost, 4),
    }


# ── Apps (assets) ───────────────────────────────────────────────────────────


@app.get("/manage/apps")
def list_apps(session: Session = Depends(get_session)) -> list[dict[str, Any]]:
    open_counts = dict(
        session.execute(
            select(Finding.app_id, func.count(Finding.id))
            .where(Finding.status == "open")
            .group_by(Finding.app_id)
        ).all()
    )
    scan_counts = dict(
        session.execute(select(Scan.app_id, func.count(Scan.id)).group_by(Scan.app_id)).all()
    )
    rows = session.scalars(select(App).order_by(App.name)).all()
    return [_app_json(r, open_counts.get(r.id, 0), scan_counts.get(r.id, 0)) for r in rows]


@app.post("/manage/apps", status_code=201)
def create_app(body: AppIn, session: Session = Depends(get_session)) -> dict[str, Any]:
    if session.scalar(select(App).where(App.name == body.name)):
        raise HTTPException(status_code=409, detail="Ya existe un activo con ese nombre")
    row = App(name=body.name, target=body.target.strip(), environment=body.environment)
    session.add(row)
    session.commit()
    return _app_json(row)


@app.get("/manage/apps/{app_id}")
def get_app(app_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
    row = _get_or_404(session, App, app_id, "app")
    open_count = session.scalar(
        select(func.count(Finding.id)).where(Finding.app_id == app_id, Finding.status == "open")
    )
    scan_count = session.scalar(select(func.count(Scan.id)).where(Scan.app_id == app_id))
    return _app_json(row, open_count or 0, scan_count or 0)


@app.delete("/manage/apps/{app_id}", status_code=204)
def delete_app(app_id: int, session: Session = Depends(get_session)) -> None:
    row = _get_or_404(session, App, app_id, "app")
    session.delete(row)
    session.commit()


@app.get("/manage/apps/{app_id}/findings")
def list_app_findings(
    app_id: int, status: str | None = None, session: Session = Depends(get_session)
) -> list[dict[str, Any]]:
    query = select(Finding).where(Finding.app_id == app_id)
    if status:
        query = query.where(Finding.status == status)
    return [_finding_json(r) for r in _sort_findings(list(session.scalars(query).all()))]


@app.get("/manage/apps/{app_id}/scans")
def list_app_scans(app_id: int, session: Session = Depends(get_session)) -> list[dict[str, Any]]:
    rows = list(
        session.scalars(
            select(Scan).where(Scan.app_id == app_id).order_by(Scan.id.desc()).limit(100)
        ).all()
    )
    counts = _scan_severity_counts(session, [r.id for r in rows])
    return [_scan_json(r, counts.get(r.id)) for r in rows]


# ── Scans ───────────────────────────────────────────────────────────────────


@app.get("/manage/scans")
def list_scans(
    status: str | None = None,
    kind: str | None = None,
    limit: int = 100,
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    query = select(Scan)
    if status:
        query = query.where(Scan.status.in_(status.split(",")))
    if kind:
        query = query.where(Scan.kind == kind)
    rows = list(session.scalars(query.order_by(Scan.id.desc()).limit(min(limit, 500))).all())
    counts = _scan_severity_counts(session, [r.id for r in rows])
    return [_scan_json(r, counts.get(r.id)) for r in rows]


@app.post("/manage/scans/preview")
def preview_request(body: PreviewIn, session: Session = Depends(get_session)) -> dict[str, Any]:
    """The exact ``audit.request`` JSON a launch would publish (id is illustrative)."""
    target = body.target
    if not target and body.app_id is not None:
        target = _get_or_404(session, App, body.app_id, "app").target
    try:
        payload = build_audit_request(
            request_id="frontal-<scan_id>-<nonce>",
            target=target or "",
            scan_mode=body.scan_mode,
            instruction=body.instruction,
            max_budget=_default_budget(body.max_budget),
            scope_mode=body.scope_mode,
        )
    except AuditRequestError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"topic": get_settings().audit_topic_request, "payload": payload}


@app.post("/manage/apps/{app_id}/scans", status_code=202)
def launch_scan(
    app_id: int,
    body: ScanIn,
    session: Session = Depends(get_session),
    producer: AuditProducer = Depends(get_producer),
) -> dict[str, Any]:
    target_app = _get_or_404(session, App, app_id, "app")
    scan = Scan(
        app_id=app_id,
        kind="scan",
        scan_mode=body.scan_mode,
        target=(body.target or target_app.target).strip(),
        instruction=(body.instruction or "").strip() or None,
        max_budget=_default_budget(body.max_budget),
        scope_mode=body.scope_mode,
    )
    return _launch(session, producer, scan)


@app.get("/manage/scans/{scan_id}")
def get_scan(scan_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
    row = _get_or_404(session, Scan, scan_id, "scan")
    observations = session.scalars(
        select(FindingObservation).where(FindingObservation.scan_id == scan_id)
    ).all()
    findings = []
    for obs in observations:
        item = _finding_json(obs.finding)
        item["verdict"] = obs.verdict
        item["evidence"] = obs.evidence
        findings.append(item)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["id"]))
    counts = _scan_severity_counts(session, [row.id])
    result = dict(row.result or {})
    return {
        **_scan_json(row, counts.get(row.id)),
        "instruction": row.instruction,
        "request_payload": row.request_payload,
        "result": result,
        "llm_usage": row.llm_usage,
        "findings": findings,
    }


@app.get("/manage/scans/{scan_id}/report")
def get_report(scan_id: int, session: Session = Depends(get_session)) -> dict[str, str]:
    row = _get_or_404(session, Scan, scan_id, "scan")
    if not row.artifact_path:
        raise HTTPException(status_code=404, detail="Este escaneo no tiene artefactos")
    run_dir = (get_settings().artifacts_dir / row.artifact_path).resolve()
    return {"markdown": read_report_markdown(run_dir)}


@app.post("/manage/scans/{scan_id}/rerun", status_code=202)
def rerun_scan(
    scan_id: int,
    session: Session = Depends(get_session),
    producer: AuditProducer = Depends(get_producer),
) -> dict[str, Any]:
    """Launch the same request again (a fresh scan; findings correlate by fingerprint)."""
    old = _get_or_404(session, Scan, scan_id, "scan")
    scan = Scan(
        app_id=old.app_id,
        kind=old.kind if old.kind in ("retest", "verify") else "scan",
        scan_mode=old.scan_mode,
        target=old.target or old.app.target,
        instruction=old.instruction,
        max_budget=old.max_budget,
        scope_mode=old.scope_mode,
        retest_finding_ids=old.retest_finding_ids,
        parent_scan_id=old.id,
    )
    return _launch(session, producer, scan)


@app.post("/manage/scans/{scan_id}/mark-failed")
def mark_failed(scan_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
    """Close a scan whose pod died: the orchestrator is at-most-once, no result will come."""
    row = _get_or_404(session, Scan, scan_id, "scan")
    if row.status not in ("queued", "running"):
        raise HTTPException(status_code=409, detail="El escaneo ya ha terminado")
    row.status = "failed"
    row.error = "Marcado como fallido manualmente (sin resultado del orquestador)"
    row.ended_at = datetime.now(UTC)
    session.commit()
    return _scan_json(row)


@app.get("/manage/scans/{scan_id}/instruction")
def get_instruction(scan_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
    row = _get_or_404(session, Scan, scan_id, "scan")
    return {"instruction": row.instruction or ""}


# ── Findings & retest ───────────────────────────────────────────────────────


@app.get("/manage/findings")
def list_findings(
    status: str | None = None,
    severity: str | None = None,
    app_id: int | None = None,
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    query = select(Finding)
    if status:
        query = query.where(Finding.status.in_(status.split(",")))
    if severity:
        query = query.where(Finding.severity.in_(severity.split(",")))
    if app_id is not None:
        query = query.where(Finding.app_id == app_id)
    return [_finding_json(r) for r in _sort_findings(list(session.scalars(query).all()))]


@app.get("/manage/findings/{finding_id}")
def get_finding(finding_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
    row = _get_or_404(session, Finding, finding_id, "finding")
    history = session.scalars(
        select(FindingObservation)
        .where(FindingObservation.finding_id == finding_id)
        .order_by(FindingObservation.id)
    ).all()
    return {
        **_finding_json(row),
        "target": row.app.target,
        "data": row.data,
        "verifying_scan_id": getattr(_active_verify_scan(session, row), "id", None),
        "history": [
            {
                "scan_id": item.scan_id,
                "scan_kind": item.scan.kind,
                "verdict": item.verdict,
                "confidence": item.confidence,
                "evidence": item.evidence,
                "observed_at": _iso(item.observed_at),
            }
            for item in history
        ],
        "triage_log": [
            {
                "decision": item.decision,
                "justification": item.justification,
                "author": item.author,
                "scan_id": item.scan_id,
                "created_at": _iso(item.created_at),
            }
            for item in row.triage_log
        ],
    }


@app.patch("/manage/findings/{finding_id}")
def patch_finding(
    finding_id: int, body: FindingPatch, session: Session = Depends(get_session)
) -> dict[str, Any]:
    row = _get_or_404(session, Finding, finding_id, "finding")
    # False positive and doubtful are triage decisions: they need a reason (or
    # launch a verify scan) and leave a trail, so they only go through /triage.
    if body.status in TRIAGE_ONLY_STATUSES or row.status in TRIAGE_ONLY_STATUSES:
        raise HTTPException(
            status_code=422,
            detail="Falso positivo y dudoso se gestionan con el triage "
            "(verdadero / falso positivo / dudoso)",
        )
    row.status = body.status
    session.commit()
    return _finding_json(row)


def _active_verify_scan(session: Session, finding: Finding) -> Scan | None:
    active = session.scalars(
        select(Scan).where(
            Scan.app_id == finding.app_id,
            Scan.kind == "verify",
            Scan.status.in_(("queued", "running")),
        )
    ).all()
    return next((scan for scan in active if finding.id in (scan.retest_finding_ids or [])), None)


@app.post("/manage/findings/{finding_id}/triage")
def triage_finding(
    finding_id: int,
    body: TriageIn,
    session: Session = Depends(get_session),
    producer: AuditProducer = Depends(get_producer),
) -> dict[str, Any]:
    """Record an analyst decision; "doubtful" also launches a verify scan of it."""
    row = _get_or_404(session, Finding, finding_id, "finding")
    justification = (body.justification or "").strip() or None
    author = (body.author or "").strip() or None

    if body.decision == "false_positive" and len(justification or "") < MIN_FP_JUSTIFICATION:
        raise HTTPException(
            status_code=422,
            detail="Para marcar un falso positivo hay que justificarlo "
            f"(mínimo {MIN_FP_JUSTIFICATION} caracteres)",
        )

    entry = FindingTriage(
        finding_id=row.id, decision=body.decision, justification=justification, author=author
    )
    row.triage = body.decision
    session.add(entry)

    if body.decision == "false_positive":
        row.status = "false_positive"
    elif body.decision == "true_positive":
        # Fixed / accepted are lifecycle states of a real finding: keep them.
        if row.status in TRIAGE_ONLY_STATUSES:
            row.status = "open"
    else:
        running = _active_verify_scan(session, row)
        if running is not None:
            raise HTTPException(
                status_code=409,
                detail=f"Ya hay una verificación en curso de este hallazgo (escaneo #{running.id})",
            )
        row.status = "doubtful"
        scan = Scan(
            app_id=row.app_id,
            kind="verify",
            scan_mode=body.scan_mode,
            target=row.app.target,
            instruction=build_verify_instruction(row.app, row, justification),
            max_budget=_default_budget(body.max_budget),
            retest_finding_ids=[row.id],
        )
        session.add(scan)
        session.flush()
        entry.scan_id = scan.id
        # _launch commits the decision together with the scan row.
        return {"finding": _finding_json(row), "scan": _launch(session, producer, scan)}

    session.commit()
    return {"finding": _finding_json(row), "scan": None}


@app.post("/manage/apps/{app_id}/retest", status_code=202)
def launch_retest(
    app_id: int,
    body: RetestIn,
    session: Session = Depends(get_session),
    producer: AuditProducer = Depends(get_producer),
) -> dict[str, Any]:
    target_app = _get_or_404(session, App, app_id, "app")
    query = select(Finding).where(Finding.app_id == app_id)
    if body.finding_ids:
        query = query.where(Finding.id.in_(body.finding_ids))
    else:
        # Default scope: everything still considered live. Accepted and
        # false-positive findings are settled decisions, not retest material.
        query = query.where(Finding.status == "open")
    findings = list(session.scalars(query.order_by(Finding.id)).all())
    if not findings:
        raise HTTPException(status_code=400, detail="No hay hallazgos que retestear")

    scan = Scan(
        app_id=app_id,
        kind="retest",
        scan_mode=body.scan_mode,
        target=target_app.target,
        instruction=build_retest_instruction(target_app, findings),
        max_budget=_default_budget(body.max_budget),
        retest_finding_ids=[row.id for row in findings],
    )
    return _launch(session, producer, scan)


# ── Web ─────────────────────────────────────────────────────────────────────

if viewer_router is not None:
    app.include_router(viewer_router)


# Split deployments serve the console from the nginx frontend
# (frontal/Dockerfile.frontend) and set FRONTAL_SERVE_CONSOLE=false here.
if get_settings().serve_console:

    @app.get("/", response_class=HTMLResponse)
    def console() -> HTMLResponse:
        return HTMLResponse((Path(__file__).parent / "console.html").read_text(encoding="utf-8"))
