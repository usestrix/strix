"""Pydantic models for the unified attack-surface inventory.

All inventory state is serializable and deterministic. The models separate:

- ``EndpointObservation`` — raw input from a single source (collector output).
- ``Endpoint`` — deduplicated, canonical endpoint in the ranked surface map.
- ``Param`` / ``ParamObservation`` — parameter hypotheses with provenance.
- ``ReachabilityAnnotation`` — white-box P4 seam output.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


ParamLocation = Literal["query", "path", "header", "body", "cookie", "form"]
ParamClassName = Literal["object-id", "url", "html", "file", "amount", "role", "state", "unknown"]
ReachabilityStatus = Literal["reachable", "unreachable", "unknown"]
SourceTag = Literal[
    "sitemap",
    "js",
    "ffuf",
    "katana",
    "arjun",
    "httpx",
    "code",
]


class ParamObservation(BaseModel):
    """A parameter seen by a single collector."""

    name: str
    location: ParamLocation = "query"
    provenance: list[str] = Field(default_factory=list)
    example_values: list[str] = Field(default_factory=list)

    @field_validator("provenance", "example_values", mode="before")
    @classmethod
    def _ensure_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(v) for v in value]


class ParamClassEvidence(BaseModel):
    """Agent-proposed parameter class with recorded evidence."""

    class_name: ParamClassName = "unknown"
    evidence: str = ""


class Param(BaseModel):
    """A parameter attached to a deduplicated endpoint."""

    name: str
    location: ParamLocation = "query"
    provenance: set[str] = Field(default_factory=set)
    example_values: set[str] = Field(default_factory=set)
    class_evidence: ParamClassEvidence | None = None

    model_config = {"frozen": False}


class ReachabilityAnnotation(BaseModel):
    """P4 reachability seam output for a flagged sink."""

    status: ReachabilityStatus = "unknown"
    path: list[str] | None = None

    @field_validator("path", mode="before")
    @classmethod
    def _ensure_path_list(cls, value: Any) -> list[str] | None:
        if value is None:
            return None
        return [str(v) for v in value]


class EndpointObservation(BaseModel):
    """Raw observation from exactly one source."""

    method: str
    raw_url: str
    params: dict[str, ParamObservation] = Field(default_factory=dict)
    source: SourceTag
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    scope_rules: list[str] | None = None
    reachability: ReachabilityAnnotation | None = None

    @field_validator("method", mode="after")
    @classmethod
    def _upper_method(cls, value: str) -> str:
        return value.upper()

    @field_validator("source", mode="before")
    @classmethod
    def _validate_source(cls, value: Any) -> str:
        allowed = {"sitemap", "js", "ffuf", "katana", "arjun", "httpx", "code"}
        if str(value) not in allowed:
            raise ValueError(f"source must be one of {allowed}")
        return str(value)


class Endpoint(BaseModel):
    """Canonical endpoint in the ranked surface map."""

    key: str
    method: str
    url: str
    sources: set[str] = Field(default_factory=set)
    params: dict[str, Param] = Field(default_factory=dict)
    signals: list[str] = Field(default_factory=list)
    score: float = 0.0
    reachability: ReachabilityAnnotation | None = None
    normalization_rules: list[str] = Field(default_factory=list)

    model_config = {"frozen": False}


class RankedSurfaceMap(BaseModel):
    """Per-target ranked attack-surface inventory."""

    target_id: str
    endpoints: dict[str, Endpoint] = Field(default_factory=dict)
    created_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def sorted_endpoints(self) -> list[Endpoint]:
        """Return endpoints descending by score, then key."""
        return sorted(self.endpoints.values(), key=lambda e: (-e.score, e.key))
