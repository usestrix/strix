"""Versioned contracts for verified fix preparation."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


if TYPE_CHECKING:
    from collections.abc import Mapping


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceIdentityKind(StrEnum):
    COMMIT = "commit"
    ARCHIVE = "archive"


class PreparationState(StrEnum):
    PREPARING = "preparing"
    READY = "ready"
    BLOCKED = "blocked"
    FAILED = "failed"
    STALE = "stale"


class CheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class VerificationDecision(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class RepairStatus(StrEnum):
    COMPLETE = "complete"
    BLOCKED = "blocked"
    BUDGET_EXHAUSTED = "budget_exhausted"
    INCOMPLETE = "incomplete"


class BlockerKind(StrEnum):
    SOURCE = "source"
    ENVIRONMENT = "environment"
    REPOSITORY_BASELINE = "repository_baseline"
    CREDENTIAL = "credential"
    EXTERNAL_CONFIGURATION = "external_configuration"
    SECURITY_EVIDENCE = "security_evidence"
    VERIFICATION_RUNTIME = "verification_runtime"


class PreparationBlocker(ContractModel):
    kind: BlockerKind
    summary: str = Field(min_length=1)
    user_action: str = Field(min_length=1)
    details: list[str] = []


class SourceIdentity(ContractModel):
    kind: SourceIdentityKind
    value: str = Field(min_length=1)
    repository: str | None = None

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized or any(char not in "0123456789abcdef" for char in normalized):
            raise ValueError("source identity must be a hexadecimal digest")
        return normalized

    @model_validator(mode="after")
    def validate_digest_length(self) -> SourceIdentity:
        valid_lengths = {40, 64} if self.kind is SourceIdentityKind.COMMIT else {64}
        if len(self.value) not in valid_lengths:
            expected = "40 or 64" if self.kind is SourceIdentityKind.COMMIT else "64"
            raise ValueError(f"{self.kind} identity must contain {expected} hexadecimal characters")
        return self


def _validate_relative_path(value: str) -> str:
    path = value.strip()
    parsed = PurePosixPath(path)
    if not path or parsed.is_absolute() or ".." in parsed.parts or path.startswith("./"):
        raise ValueError("path must be relative to the repository root")
    return path


class CandidateLocation(ContractModel):
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    snippet: str | None = None
    label: str | None = None

    _relative_file = field_validator("file")(_validate_relative_path)

    @model_validator(mode="after")
    def validate_range(self) -> CandidateLocation:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


class FixEdit(CandidateLocation):
    before: str = Field(min_length=1)
    after: str
    original_sha256: str | None = None


class CommandSpec(ContractModel):
    name: str = Field(min_length=1, max_length=120)
    argv: list[str] = Field(min_length=1)
    required: bool = True
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    cwd: str = "."
    purpose: Literal["quality", "regression", "unit", "security"] = "quality"

    _relative_cwd = field_validator("cwd")(_validate_relative_path)

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: list[str]) -> list[str]:
        if any(not argument or "\x00" in argument for argument in value):
            raise ValueError("command arguments must be non-empty and cannot contain NUL")
        return value


class ReproductionSpec(ContractModel):
    instructions: str = Field(min_length=1)
    command: CommandSpec | None = None


class ReportedCheck(ContractModel):
    name: str
    result: str
    executed: bool = False


class FindingContext(ContractModel):
    validation_status: Literal["confirmed", "unconfirmed"] | None = None
    title: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""


class FixCandidateBlocker(ContractModel):
    """Why the reporting agent cannot hand off a code fix for this finding."""

    reason: str = Field(min_length=1)

    @field_validator("reason")
    @classmethod
    def nonempty_reason(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("explain what prevents a code fix")
        return value.strip()


class FixCandidateV1(ContractModel):
    version: Literal["1"] = "1"
    source_identity: SourceIdentity | None = None
    security_invariant: str = Field(min_length=1)
    finding_locations: list[CandidateLocation] = []
    draft_edits: list[FixEdit] = []
    reproduction: ReproductionSpec | None = None
    reported_checks: list[ReportedCheck] = []
    known_gaps: list[str] = []
    finding: FindingContext | None = None
    blocker: FixCandidateBlocker | None = None

    def digest(self) -> str:
        data = self.model_dump(mode="json")
        if self.finding is None:
            data.pop("finding", None)  # Preserve digests for stored legacy candidates.
        if self.finding is not None and self.finding.validation_status is None:
            data["finding"].pop("validation_status", None)
        if self.blocker is None:
            data.pop("blocker", None)
        if data.get("reproduction") and data["reproduction"].get("command"):
            data["reproduction"]["command"].pop("purpose", None)
        payload = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(payload).hexdigest()


class FixPreparationRequestV1(ContractModel):
    version: Literal["1"] = "1"
    organization_id: str | None = None
    scan_id: str
    finding_id: str
    repository_id: str | None = None
    candidate: FixCandidateV1
    checks: list[CommandSpec] = []
    # Accepted for old callers; the agent loop is bounded by turns/time instead.
    max_repair_attempts: int | None = Field(default=None, ge=1)
    # Legacy shared override; role-specific limits take precedence when supplied.
    max_agent_turns: int | None = Field(default=None, ge=1, le=10000)
    max_repair_turns: int | None = Field(default=None, ge=1, le=10000)
    max_review_turns: int | None = Field(default=None, ge=1, le=10000)
    timeout_seconds: int = Field(default=7200, ge=30, le=14400)
    max_budget_usd: float | None = Field(default=None, gt=0, allow_inf_nan=False)
    network_allowed: bool = False
    # Accept old empty requests, but never look up or forward host credentials.
    credentials_allowed: list[str] = Field(default=[], max_length=0, exclude=True)

    @property
    def repair_turn_limit(self) -> int:
        return min(self.max_repair_turns or self.max_agent_turns or 300, 300)

    @property
    def review_turn_limit(self) -> int:
        return self.max_review_turns or self.max_agent_turns or 250


class CheckResult(ContractModel):
    """Recorded native shell execution; the reviewer interprets its meaning."""

    name: str
    argv: list[str]
    status: CheckStatus
    exit_code: int | None = None
    duration_seconds: float = Field(ge=0)
    output: str = ""
    required: bool = True
    cwd: str = "."
    workspace_root: str | None = None
    environment_id: str | None = None


class VerifierResult(ContractModel):
    decision: VerificationDecision
    summary: str
    gaps: list[str] = []
    notes: list[str] = []
    blocker: PreparationBlocker | None = None
    review_basis: Literal["execution", "code_review"] | None = None
    source_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    turns_used: int = Field(default=0, ge=0)


class RepairOutcome(ContractModel):
    status: RepairStatus
    summary: str = Field(min_length=1)
    gaps: list[str] = []
    notes: list[str] = []
    turns_used: int = Field(default=0, ge=0)
    blocker: PreparationBlocker | None = None
    command_results: list[CheckResult] = []
    source_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class FixPreparationAttempt(ContractModel):
    attempt: int = Field(ge=1)
    repair: RepairOutcome
    checks: list[CheckResult] = []
    verifier: VerifierResult | None = None
    workspace_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class FileManifestEntry(ContractModel):
    path: str
    operation: Literal["add", "modify", "delete"]
    original_sha256: str | None = None
    resulting_sha256: str | None = None
    artifact_ref: str | None = None

    _relative_path = field_validator("path")(_validate_relative_path)


class FixPreparationResultV1(ContractModel):
    version: Literal["1"] = "1"
    validation_mode: Literal["agent_review", "single_agent"] = "single_agent"
    completion: RepairOutcome | None = None
    prepared_source_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    state: PreparationState
    stop_reason: str
    source_identity: SourceIdentity | None
    candidate: FixCandidateV1
    candidate_digest: str
    final_file_manifest: list[FileManifestEntry] = []
    artifact_ref: str | None = None
    changed_files: list[str] = []
    diff_summary: str = ""
    checks: list[CheckResult] = []
    verifier: VerifierResult | None = None
    attempt_history: list[FixPreparationAttempt] = []
    gaps: list[str] = []
    blocker: PreparationBlocker | None = None
    attempts: int = Field(default=0, ge=0)
    elapsed_seconds: float = Field(default=0, ge=0)
    cost_usd: float | None = Field(default=None, ge=0)


def candidate_from_legacy_report(
    report: Mapping[str, object],
    *,
    source_identity: SourceIdentity | None = None,
) -> FixCandidateV1 | None:
    raw_blocker = report.get("fix_candidate_blocker")
    blocker = FixCandidateBlocker.model_validate(raw_blocker) if raw_blocker is not None else None
    raw_locations = report.get("code_locations")
    if not isinstance(raw_locations, list) and blocker is None:
        return None
    location_values = cast("list[object]", raw_locations) if isinstance(raw_locations, list) else []

    locations: list[CandidateLocation] = []
    edits: list[FixEdit] = []
    for raw_value in location_values:
        if not isinstance(raw_value, dict):
            continue
        raw = cast("dict[str, object]", raw_value)
        file_path = raw.get("file")
        start_line = raw.get("start_line")
        end_line = raw.get("end_line")
        if not isinstance(file_path, str) or type(start_line) is not int:
            continue
        if type(end_line) is not int:
            end_line = start_line
        common = {
            "file": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "snippet": raw.get("snippet") if isinstance(raw.get("snippet"), str) else None,
            "label": raw.get("label") if isinstance(raw.get("label"), str) else None,
        }
        try:
            locations.append(CandidateLocation.model_validate(common))
            before = raw.get("fix_before")
            after = raw.get("fix_after")
            if isinstance(before, str) and isinstance(after, str):
                edits.append(FixEdit.model_validate({**common, "before": before, "after": after}))
        except ValueError:
            continue

    if not locations and blocker is None:
        return None

    invariant = str(
        report.get("remediation_steps") or report.get("technical_analysis") or ""
    ).strip()
    if not invariant:
        invariant = "Resolve the reported security finding without changing legitimate behavior."

    reported_checks: list[ReportedCheck] = []
    verification = str(report.get("fix_verification") or "").strip()
    if verification:
        reported_checks.append(
            ReportedCheck(name="reporting-agent verification", result=verification, executed=False)
        )

    reproduction = str(report.get("poc_description") or report.get("evidence") or "").strip()
    return FixCandidateV1(
        source_identity=source_identity,
        blocker=blocker,
        security_invariant=invariant,
        finding_locations=locations,
        draft_edits=edits,
        reproduction=ReproductionSpec(instructions=reproduction) if reproduction else None,
        finding=FindingContext(
            validation_status=cast(
                "Literal['confirmed', 'unconfirmed'] | None", report.get("validation_status")
            ),
            title=str(report.get("title") or ""),
            description=str(report.get("description") or report.get("technical_analysis") or ""),
            evidence=str(report.get("evidence") or report.get("poc_description") or ""),
            remediation=str(report.get("remediation_steps") or ""),
        ),
        reported_checks=reported_checks,
        known_gaps=["The reporting-agent verification is not independent."],
    )
