"""Target Complexity Index (TCI) calculation for dynamic vulnerability scanning.

TCI is a normalized score (0.0 .. 100.0) derived from target fingerprint data
(open ports, protocols, auth patterns, API surface, tech stack, WAF/CDN presence,
data sensitivity, and patch posture). Configurable weights allow customizing
the relative importance of each dimension.
"""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


logger = logging.getLogger(__name__)


SUPPORTED_TARGET_TYPES: frozenset[str] = frozenset({"web_app", "api", "whitebox", "infra", "cloud"})

TARGET_TYPE_ALIASES: dict[str, str] = {
    # web
    "web_app": "web_app",
    "web_application": "web_app",
    "web": "web_app",
    "url": "web_app",
    "domain": "web_app",
    "hostname": "web_app",
    # api
    "api": "api",
    "api_spec": "api",
    "openapi": "api",
    "swagger": "api",
    "rest": "api",
    "graphql": "api",
    # whitebox / code
    "whitebox": "whitebox",
    "local_code": "whitebox",
    "code": "whitebox",
    "source_code": "whitebox",
    "repository": "whitebox",
    "repo": "whitebox",
    # infra
    "infra": "infra",
    "infrastructure": "infra",
    "network": "infra",
    "ip": "infra",
    "ip_address": "infra",
    "host": "infra",
    # cloud
    "cloud": "cloud",
    "aws": "cloud",
    "azure": "cloud",
    "gcp": "cloud",
}


def normalize_target_type(target_type: str | None) -> str:
    """Normalize and validate a target type string to canonical form.

    Raises:
        ValueError: If target_type is unrecognized.
    """
    if not target_type:
        return "web_app"
    clean = target_type.strip().lower()
    canonical = TARGET_TYPE_ALIASES.get(clean)
    if canonical is None:
        valid_options = ", ".join(sorted(SUPPORTED_TARGET_TYPES))
        msg = f"Unknown target type '{target_type}'. Supported canonical types: {valid_options}."
        raise ValueError(msg)
    return canonical


def _dedup_clean_strings(values: list[str]) -> list[str]:
    """Clean and deduplicate list of strings preserving insertion order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in values:
        if isinstance(item, str):
            clean = item.strip().lower()
            if clean and clean not in seen:
                seen.add(clean)
                result.append(clean)
    return result


class TCILevel(StrEnum):
    """Complexity tiers based on TCI score."""

    LOW = "low"
    MODERATE = "moderate"
    COMPLEX = "complex"
    CRITICAL = "critical"


class ApiSurface(BaseModel):
    """API surface metrics for a target."""

    model_config = ConfigDict(extra="allow")

    endpoints_count: int = Field(default=0, ge=0)
    parameters_count: int = Field(default=0, ge=0)
    api_types: list[str] = Field(default_factory=list)
    has_spec: bool = False
    dynamic_routes: bool = False

    @field_validator("api_types", mode="after")
    @classmethod
    def _dedup_api_types(cls, v: list[str]) -> list[str]:
        return _dedup_clean_strings(v)


class TargetFingerprint(BaseModel):
    """Structured fingerprint of a target's observable characteristics."""

    model_config = ConfigDict(extra="allow")

    target: str = ""
    target_type: str = "web_app"
    open_ports: list[int] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    auth_patterns: list[str] = Field(default_factory=list)
    api_surface: ApiSurface = Field(default_factory=ApiSurface)
    frontend_technologies: list[str] = Field(default_factory=list)
    backend_technologies: list[str] = Field(default_factory=list)
    waf_cdn: list[str] = Field(default_factory=list)
    data_sensitivity: str = "standard"
    patch_posture: str = "unknown"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target_type", mode="after")
    @classmethod
    def _validate_target_type(cls, v: str) -> str:
        return normalize_target_type(v)

    @field_validator("open_ports", mode="after")
    @classmethod
    def _dedup_ports(cls, v: list[int]) -> list[int]:
        return sorted({p for p in v if isinstance(p, int) and p > 0})

    @field_validator(
        "protocols",
        "auth_patterns",
        "frontend_technologies",
        "backend_technologies",
        "waf_cdn",
        mode="after",
    )
    @classmethod
    def _dedup_string_lists(cls, v: list[str]) -> list[str]:
        return _dedup_clean_strings(v)

    @field_validator("api_surface", mode="before")
    @classmethod
    def _coerce_api_surface(cls, v: Any) -> ApiSurface:
        if isinstance(v, dict):
            return ApiSurface(**v)
        if isinstance(v, ApiSurface):
            return v
        return ApiSurface()


class TCIWeights(BaseModel):
    """Configurable weights for TCI scoring dimensions.

    Weights are non-negative and automatically normalized so they sum to 1.0.
    """

    model_config = ConfigDict(extra="forbid")

    ports_protocols: float = Field(default=0.15, ge=0.0)
    auth: float = Field(default=0.20, ge=0.0)
    api_surface: float = Field(default=0.20, ge=0.0)
    tech_stack: float = Field(default=0.15, ge=0.0)
    waf_defense: float = Field(default=0.10, ge=0.0)
    data_sensitivity: float = Field(default=0.10, ge=0.0)
    patch_posture: float = Field(default=0.10, ge=0.0)

    def normalized_weights(self) -> dict[str, float]:
        """Return dimension weights normalized to sum to 1.0."""
        raw = {
            "ports_protocols": self.ports_protocols,
            "auth": self.auth,
            "api_surface": self.api_surface,
            "tech_stack": self.tech_stack,
            "waf_defense": self.waf_defense,
            "data_sensitivity": self.data_sensitivity,
            "patch_posture": self.patch_posture,
        }
        total = sum(raw.values())
        if total <= 0:
            count = len(raw)
            return dict.fromkeys(raw, 1.0 / count)
        return {k: v / total for k, v in raw.items()}


class TCIResult(BaseModel):
    """Result of Target Complexity Index calculation."""

    model_config = ConfigDict(extra="allow")

    score: float = Field(ge=0.0, le=100.0)
    level: TCILevel
    sub_scores: dict[str, float]
    weights: dict[str, float]
    breakdown: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        """Convert result to a plain serializable dict."""
        return {
            "score": self.score,
            "level": self.level.value,
            "sub_scores": self.sub_scores,
            "weights": self.weights,
            "breakdown": self.breakdown,
        }


# Standard web and infrastructure port definitions for scoring
_STANDARD_WEB_PORTS = frozenset({80, 443})
_NON_STANDARD_WEB_PORTS = frozenset(
    {
        8080,
        8443,
        3000,
        5000,
        8000,
        8008,
        8888,
        9000,
        9443,
    }
)
_INFRA_PORTS = frozenset(
    {
        21,
        22,
        23,
        25,
        53,
        110,
        143,
        445,
        1433,
        1521,
        3306,
        3389,
        5432,
        5900,
        6379,
        8081,
        9200,
        11211,
        27017,
    }
)


def calc_ports_protocols_score(ports: list[int], protocols: list[str]) -> tuple[float, str]:
    """Score ports and protocols attack surface (0..100)."""
    score = 0.0
    notes: list[str] = []

    clean_ports = sorted({p for p in ports if isinstance(p, int) and p > 0})
    clean_protocols = _dedup_clean_strings(protocols)

    if not clean_ports and not clean_protocols:
        return 10.0, "No open ports or protocols reported (baseline web assumption)"

    web_ports = [p for p in clean_ports if p in _STANDARD_WEB_PORTS]
    non_std_web = [p for p in clean_ports if p in _NON_STANDARD_WEB_PORTS]
    infra_ports = [p for p in clean_ports if p in _INFRA_PORTS]
    other_ports = [
        p
        for p in clean_ports
        if p not in _STANDARD_WEB_PORTS
        and p not in _NON_STANDARD_WEB_PORTS
        and p not in _INFRA_PORTS
    ]

    if web_ports:
        score += 20.0
        notes.append(f"Standard web ports: {web_ports}")

    if non_std_web:
        added = min(35.0, len(non_std_web) * 15.0)
        score += added
        notes.append(f"Non-standard web ports (+{added:.0f}): {non_std_web}")

    if infra_ports:
        added = min(40.0, len(infra_ports) * 20.0)
        score += added
        notes.append(f"Infra/database ports (+{added:.0f}): {infra_ports}")

    if other_ports:
        added = min(25.0, len(other_ports) * 10.0)
        score += added
        notes.append(f"Other ports (+{added:.0f}): {other_ports}")

    # Protocol diversity
    proto_bonus = 0.0
    for proto in clean_protocols:
        if proto in ("grpc", "grpc-web"):
            proto_bonus += 20.0
        elif proto in ("ws", "wss", "websocket"):
            proto_bonus += 15.0
        elif proto not in ("http", "https"):
            proto_bonus += 10.0
    if proto_bonus > 0:
        proto_bonus = min(30.0, proto_bonus)
        score += proto_bonus
        notes.append(f"Protocols (+{proto_bonus:.0f}): {clean_protocols}")

    final_score = max(10.0, min(100.0, score))
    return final_score, "; ".join(notes) or "Standard port exposure"


_AUTH_BASE_SCORES: dict[str, float] = {
    "basic": 25.0,
    "basic_auth": 25.0,
    "api_key": 35.0,
    "apikey": 35.0,
    "token": 35.0,  # nosec B105
    "session": 45.0,
    "cookie": 45.0,
    "session_cookie": 45.0,
    "jwt": 60.0,
    "bearer": 60.0,
    "oauth": 75.0,
    "oauth2": 75.0,
    "oidc": 75.0,
    "sso": 75.0,
    "saml": 85.0,
    "mtls": 85.0,
    "client_cert": 85.0,
}


def calc_auth_score(auth_patterns: list[str]) -> tuple[float, str]:
    """Score authentication complexity (0..100)."""
    clean_patterns = _dedup_clean_strings(auth_patterns)
    if not clean_patterns:
        return 0.0, "No authentication mechanisms detected"

    max_base = 0.0
    matched: list[str] = []
    bonus = 0.0
    has_mfa = False
    has_rbac = False

    for pattern in clean_patterns:
        score = _AUTH_BASE_SCORES.get(pattern)
        if score is not None:
            max_base = max(max_base, score)
            matched.append(pattern)
        elif any(k in pattern for k in ("mfa", "2fa", "totp")):
            has_mfa = True
            matched.append("mfa")
        elif any(k in pattern for k in ("rbac", "abac", "multi_role", "tenant", "multi_tenant")):
            has_rbac = True
            matched.append("rbac/multi-tenant")
        else:
            max_base = max(max_base, 30.0)
            matched.append(pattern)

    if has_mfa:
        bonus += 15.0
    if has_rbac:
        bonus += 15.0

    # Multi-pattern complexity
    distinct_mechanisms = len(set(matched))
    if distinct_mechanisms > 1:
        bonus += min(20.0, (distinct_mechanisms - 1) * 10.0)

    final_score = min(100.0, max_base + bonus)
    desc = f"Auth patterns ({', '.join(clean_patterns)}): base={max_base:.0f}, bonus={bonus:.0f}"
    return final_score, desc


def _score_endpoint_count(count: int, has_api_types: bool) -> tuple[float, str | None]:
    if count <= 0:
        desc = (
            "API detected with uncounted endpoints"
            if has_api_types
            else "Minimal/static API surface"
        )
        return (15.0 if has_api_types else 10.0), desc
    thresholds = (
        (5, 25.0, f"{count} endpoints (small)"),
        (20, 45.0, f"{count} endpoints (moderate)"),
        (50, 65.0, f"{count} endpoints (broad)"),
        (150, 85.0, f"{count} endpoints (large)"),
    )
    for limit, score, desc in thresholds:
        if count <= limit:
            return score, desc
    return 95.0, f"{count} endpoints (enterprise-scale)"


def calc_api_surface_score(api_surface: ApiSurface | dict[str, Any]) -> tuple[float, str]:
    """Score API surface magnitude and diversity (0..100)."""
    surface = ApiSurface(**api_surface) if isinstance(api_surface, dict) else api_surface

    notes: list[str] = []
    clean_api_types = _dedup_clean_strings(surface.api_types)
    base_score, count_note = _score_endpoint_count(surface.endpoints_count, bool(clean_api_types))
    if count_note:
        notes.append(count_note)

    score = base_score

    # API Types diversity (deduplicated)
    for atype in clean_api_types:
        if atype in ("graphql", "grpc"):
            score += 20.0
            notes.append(atype.upper())
        elif atype in ("ws", "websocket"):
            score += 15.0
            notes.append("WebSocket")
        elif atype == "soap":
            score += 15.0
            notes.append("SOAP")

    # Parameters & Schema
    if surface.parameters_count > 50:
        score += 15.0
        notes.append(f"{surface.parameters_count} parameters")
    elif surface.parameters_count > 15:
        score += 10.0
        notes.append(f"{surface.parameters_count} parameters")

    if surface.has_spec:
        score += 10.0
        notes.append("Formal API specification discovered")

    if surface.dynamic_routes:
        score += 10.0
        notes.append("Dynamic/parameterized routing")

    final_score = min(100.0, max(10.0, score))
    return final_score, "; ".join(notes)


_SPA_FRAMEWORKS = frozenset(
    {
        "react",
        "vue",
        "angular",
        "nextjs",
        "nuxt",
        "svelte",
        "spa",
        "solid",
    }
)
_BACKEND_FRAMEWORKS = frozenset(
    {
        "django",
        "fastapi",
        "flask",
        "express",
        "rails",
        "spring",
        "springboot",
        "nestjs",
        "laravel",
        "aspnet",
        "gin",
        "echo",
        "fiber",
    }
)
_DB_ENGINES = frozenset(
    {
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "mongodb",
        "redis",
        "elasticsearch",
        "cassandra",
        "oracle",
        "mssql",
        "sqlite",
    }
)


def calc_tech_stack_score(
    frontend: list[str],
    backend: list[str],
) -> tuple[float, str]:
    """Score technology stack heterogeneity and modern complexity (0..100)."""
    clean_fe = _dedup_clean_strings(frontend)
    clean_be = _dedup_clean_strings(backend)

    score = 15.0  # baseline
    notes: list[str] = []

    has_spa = any(f in _SPA_FRAMEWORKS or "react" in f or "vue" in f for f in clean_fe)
    if has_spa:
        score += 30.0
        notes.append(f"Modern SPA frontend: {clean_fe}")
    elif clean_fe:
        score += 15.0
        notes.append(f"Frontend: {clean_fe}")

    matched_be = list(
        dict.fromkeys(
            b
            for b in clean_be
            if b in _BACKEND_FRAMEWORKS or any(k in b for k in _BACKEND_FRAMEWORKS)
        )
    )
    if len(matched_be) > 1:
        score += 35.0
        notes.append(f"Polyglot/microservice backend: {clean_be}")
    elif matched_be:
        score += 25.0
        notes.append(f"Backend framework: {matched_be}")
    elif clean_be:
        score += 15.0
        notes.append(f"Backend: {clean_be}")

    matched_db = list(dict.fromkeys(b for b in clean_be if b in _DB_ENGINES))
    if matched_db:
        db_pts = min(20.0, len(matched_db) * 10.0)
        score += db_pts
        notes.append(f"Databases: {matched_db}")

    final_score = min(100.0, score)
    return final_score, "; ".join(notes) or "Minimal tech stack"


_WAF_PROVIDERS = frozenset(
    {
        "cloudflare",
        "aws_waf",
        "akamai",
        "imperva",
        "fastly",
        "incapsula",
        "f5",
        "modsecurity",
        "barracuda",
        "sucuri",
    }
)


def calc_waf_defense_score(waf_cdn: list[str]) -> tuple[float, str]:
    """Score defensive posture and WAF presence (0..100)."""
    clean_defenses = _dedup_clean_strings(waf_cdn)
    if not clean_defenses:
        return 0.0, "No WAF or edge security detected"

    has_waf = any(d in _WAF_PROVIDERS or "waf" in d for d in clean_defenses)
    count = len(clean_defenses)

    if has_waf:
        score = 75.0 + min(25.0, (count - 1) * 15.0)
        return min(100.0, score), f"Active WAF/defense: {', '.join(clean_defenses)}"

    score = 40.0 + min(20.0, (count - 1) * 10.0)
    return min(100.0, score), f"CDN/edge proxy present: {', '.join(clean_defenses)}"


def calc_data_sensitivity_score(sensitivity: str) -> tuple[float, str]:
    """Score target data and workflow sensitivity (0..100)."""
    clean = (sensitivity or "").lower().strip()
    if clean in ("low", "public", "static", "marketing"):
        return 15.0, "Public or marketing content"
    if clean in ("standard", "medium", "internal"):
        return 45.0, "Standard application workflow / internal service"
    if clean in ("high", "confidential", "admin", "admin_panel"):
        return 75.0, "High-privilege admin panel or confidential business workflow"
    if clean in ("critical", "pii", "financial", "payment", "pci", "healthcare", "hipaa"):
        return 95.0, "Critical compliance scope (PII, financial, or healthcare data)"
    return 45.0, f"Unspecified sensitivity ({sensitivity}), defaulting to standard"


def calc_patch_posture_score(posture: str) -> tuple[float, str]:
    """Score target freshness and legacy vulnerability likelihood (0..100)."""
    clean = (posture or "").lower().strip()
    if clean in ("modern", "hardened", "latest"):
        return 20.0, "Modern, actively maintained and hardened posture"
    if clean in ("current", "stable"):
        return 35.0, "Current stable release cycle"
    if clean in ("unknown", ""):
        return 50.0, "Patch posture unknown / uninspected"
    if clean in ("patch_lag", "outdated", "deprecated"):
        return 75.0, "Known patch lag or deprecated components detected"
    if clean in ("legacy", "vulnerable", "eol", "end_of_life"):
        return 95.0, "Legacy stack or end-of-life framework version"
    return 50.0, f"Unrecognized posture ({posture}), defaulting to moderate"


def calculate_tci(
    fingerprint: TargetFingerprint | dict[str, Any],
    weights: TCIWeights | None = None,
) -> TCIResult:
    """Calculate the Target Complexity Index (0..100) from a target fingerprint.

    Args:
        fingerprint: Target fingerprint model or dictionary of observables.
        weights: Configurable weights. If None, default balanced weights are used.

    Returns:
        TCIResult containing score (0.0..100.0), tier level, sub-scores,
        weights, and descriptive breakdown.
    """
    if isinstance(fingerprint, TargetFingerprint):
        fp = fingerprint
    else:
        fp = TargetFingerprint(**fingerprint)

    w = weights or TCIWeights()
    norm_w = w.normalized_weights()

    s_ports, b_ports = calc_ports_protocols_score(fp.open_ports, fp.protocols)
    s_auth, b_auth = calc_auth_score(fp.auth_patterns)
    s_api, b_api = calc_api_surface_score(fp.api_surface)
    s_tech, b_tech = calc_tech_stack_score(fp.frontend_technologies, fp.backend_technologies)
    s_waf, b_waf = calc_waf_defense_score(fp.waf_cdn)
    s_sens, b_sens = calc_data_sensitivity_score(fp.data_sensitivity)
    s_patch, b_patch = calc_patch_posture_score(fp.patch_posture)

    sub_scores = {
        "ports_protocols": round(s_ports, 1),
        "auth": round(s_auth, 1),
        "api_surface": round(s_api, 1),
        "tech_stack": round(s_tech, 1),
        "waf_defense": round(s_waf, 1),
        "data_sensitivity": round(s_sens, 1),
        "patch_posture": round(s_patch, 1),
    }

    breakdown = {
        "ports_protocols": b_ports,
        "auth": b_auth,
        "api_surface": b_api,
        "tech_stack": b_tech,
        "waf_defense": b_waf,
        "data_sensitivity": b_sens,
        "patch_posture": b_patch,
    }

    composite = sum(sub_scores[k] * norm_w[k] for k in sub_scores)
    final_score = round(max(0.0, min(100.0, composite)), 1)

    if final_score <= 30.0:
        level = TCILevel.LOW
    elif final_score <= 60.0:
        level = TCILevel.MODERATE
    elif final_score <= 80.0:
        level = TCILevel.COMPLEX
    else:
        level = TCILevel.CRITICAL

    return TCIResult(
        score=final_score,
        level=level,
        sub_scores=sub_scores,
        weights={k: round(v, 4) for k, v in norm_w.items()},
        breakdown=breakdown,
    )


class TargetComplexityIndex:
    """Namespace and helper class for Target Complexity Index (TCI) operations."""

    @staticmethod
    def calculate(
        fingerprint: TargetFingerprint | dict[str, Any],
        weights: TCIWeights | None = None,
    ) -> TCIResult:
        """Calculate TCI from fingerprint with optional weights."""
        return calculate_tci(fingerprint, weights)
