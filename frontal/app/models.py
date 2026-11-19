from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# Postgres is the deployment target; the sqlite variants keep the models usable
# for tests and local smoke runs without a server. SQLite only auto-assigns
# rowids for plain INTEGER primary keys, hence the narrowing on Pk.
JsonB = JSONB().with_variant(JSON(), "sqlite")
Pk = BigInteger().with_variant(Integer(), "sqlite")

SCAN_STATUSES = ("queued", "running", "completed", "failed")
# "external": a result for a request this frontal did not send (manual Kafka use).
# "verify": re-check a single finding an analyst marked as doubtful.
SCAN_KINDS = ("scan", "retest", "verify", "external")
# "doubtful": an analyst is not sure it is real; a verify scan is on its way.
FINDING_STATUSES = ("open", "fixed", "accepted", "false_positive", "doubtful")
# confirmed/refuted come from verify scans, the rest from scans and retests.
VERDICTS = ("observed", "still_vulnerable", "fixed", "inconclusive", "confirmed", "refuted")
TRIAGE_DECISIONS = ("true_positive", "false_positive", "doubtful")


class Base(DeclarativeBase):
    pass


class App(Base):
    __tablename__ = "apps"

    id: Mapped[int] = mapped_column(Pk, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    target: Mapped[str] = mapped_column(Text)
    environment: Mapped[str | None] = mapped_column(String(50), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scans: Mapped[list[Scan]] = relationship(back_populates="app", cascade="all, delete-orphan")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="app", cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Pk, primary_key=True)
    app_id: Mapped[int] = mapped_column(ForeignKey("apps.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20), default="scan")
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    scan_mode: Mapped[str] = mapped_column(String(20), default="deep")
    # What was actually sent: the app's target can change after the scan ran.
    target: Mapped[str | None] = mapped_column(Text, default=None)
    max_budget: Mapped[float | None] = mapped_column(Float, default=None)
    scope_mode: Mapped[str | None] = mapped_column(String(20), default=None)
    # The audit.request "id": how an audit.result is matched back to this row.
    request_id: Mapped[str | None] = mapped_column(String(200), default=None, index=True)
    request_payload: Mapped[dict[str, Any] | None] = mapped_column(JsonB, default=None)
    # The audit.result event minus its echoed request (status, cost, storage...).
    result: Mapped[dict[str, Any] | None] = mapped_column(JsonB, default=None)
    # Filled in after the CLI generates it; runs are addressed by scan id
    # everywhere else, so two runs sharing a generated name never collide.
    run_name: Mapped[str | None] = mapped_column(String(200), default=None)
    instruction: Mapped[str | None] = mapped_column(Text, default=None)
    parent_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None
    )
    # Findings this run was asked to verify (retest scans only). Needed to tell
    # "agent did not re-report it" from "agent never looked at it".
    retest_finding_ids: Mapped[list[int] | None] = mapped_column(JsonB, default=None)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    llm_usage: Mapped[dict[str, Any] | None] = mapped_column(JsonB, default=None)
    # Run directory, relative to the artifacts dir.
    artifact_path: Mapped[str | None] = mapped_column(Text, default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    app: Mapped[App] = relationship(back_populates="scans")
    observations: Mapped[list[FindingObservation]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("app_id", "fingerprint", name="uq_findings_app_fingerprint"),
        Index("ix_findings_app_status", "app_id", "status"),
    )

    id: Mapped[int] = mapped_column(Pk, primary_key=True)
    app_id: Mapped[int] = mapped_column(ForeignKey("apps.id", ondelete="CASCADE"))
    fingerprint: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    cvss: Mapped[float | None] = mapped_column(Float, default=None)
    cwe: Mapped[str | None] = mapped_column(String(30), default=None)
    endpoint: Mapped[str | None] = mapped_column(Text, default=None)
    method: Mapped[str | None] = mapped_column(String(10), default=None)
    status: Mapped[str] = mapped_column(String(20), default="open")
    first_seen_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None
    )
    last_seen_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None
    )
    last_retest_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None
    )
    last_verdict: Mapped[str | None] = mapped_column(String(20), default=None)
    # Latest triage decision; the full trail (who, why) is in finding_triage.
    triage: Mapped[str | None] = mapped_column(String(20), default=None)
    # The full Strix vulnerability object. Promoted columns above are only the
    # ones that get filtered on; keeping the blob means new upstream fields
    # (http_exchange_ids, ...) land without a migration.
    data: Mapped[dict[str, Any]] = mapped_column(JsonB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    app: Mapped[App] = relationship(back_populates="findings")
    observations: Mapped[list[FindingObservation]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingObservation.id"
    )
    triage_log: Mapped[list[FindingTriage]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingTriage.id"
    )


class FindingObservation(Base):
    __tablename__ = "finding_observations"
    __table_args__ = (
        UniqueConstraint("finding_id", "scan_id", name="uq_observation_finding_scan"),
    )

    id: Mapped[int] = mapped_column(Pk, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    vuln_id: Mapped[str | None] = mapped_column(String(50), default=None)
    verdict: Mapped[str] = mapped_column(String(20), default="observed")
    confidence: Mapped[str | None] = mapped_column(String(20), default=None)
    evidence: Mapped[str | None] = mapped_column(Text, default=None)
    raw: Mapped[dict[str, Any]] = mapped_column(JsonB, default=dict)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    finding: Mapped[Finding] = relationship(back_populates="observations")
    scan: Mapped[Scan] = relationship(back_populates="observations")


class FindingTriage(Base):
    """One analyst (or verify-scan) decision on a finding. Append-only.

    The justification is the point: it is what makes a false positive
    auditable, and what a verify scan is told when the decision is "doubtful".
    """

    __tablename__ = "finding_triage"

    id: Mapped[int] = mapped_column(Pk, primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    decision: Mapped[str] = mapped_column(String(20))
    justification: Mapped[str | None] = mapped_column(Text, default=None)
    # Free text until the console has auth; "strix" for verify-scan outcomes.
    author: Mapped[str | None] = mapped_column(String(200), default=None)
    # The verify scan a "doubtful" launched, or the one that settled the decision.
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), default=None
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    finding: Mapped[Finding] = relationship(back_populates="triage_log")
