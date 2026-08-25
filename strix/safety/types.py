"""Shared safety-review data types."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field


if TYPE_CHECKING:
    from strix.safety.inspection import InspectionRunner


SafetyRisk = Literal["low", "medium", "high", "critical"]


class SafetyVerdict(BaseModel):
    """Strict final output returned by the safety model."""

    model_config = ConfigDict(extra="forbid")

    decision: Literal["allow", "block", "defer"]
    risk: SafetyRisk
    categories: list[str] = Field(default_factory=list, max_length=12)
    reason: str = Field(min_length=1, max_length=1000)
    confidence: float = Field(ge=0, le=1)


@dataclass(frozen=True, slots=True)
class SafetyDecision:
    allowed: bool
    source: Literal["off", "deterministic", "reviewer", "review_error", "human", "system"]
    reason: str
    categories: tuple[str, ...] = ()
    case_id: str | None = None
    risk: SafetyRisk | None = None
    deferred: bool = False


@dataclass(frozen=True, slots=True)
class SafetyApprovalRequest:
    request_id: str
    case_id: str
    tool_call_id: str
    agent_id: str
    tool_name: str
    action: str
    digest: str
    reason: str
    categories: tuple[str, ...]
    risk: SafetyRisk


SafetyApprovalOutcome = bool | Literal["cancelled"]
SafetyApprovalCallback = Callable[[SafetyApprovalRequest], Awaitable[SafetyApprovalOutcome]]
WorkspaceEvidenceCollector = Callable[[tuple[str, ...]], Awaitable[tuple[str, bool]]]


@dataclass(slots=True)
class InspectionContext:
    evidence_dir: str
    runner: InspectionRunner
    collect_workspace: WorkspaceEvidenceCollector | None = None
    used: bool = False
    attempts: int = 0
    incomplete: bool = False
