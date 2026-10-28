"""Registry for vulnerability scanning modules with priority, quotas, and safe_mode hints."""

from __future__ import annotations

import logging
import threading
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from strix.core.tci import TargetFingerprint, normalize_target_type


logger = logging.getLogger(__name__)


class PriorityTier(StrEnum):
    """Scan module priority tiers."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting (higher is higher priority)."""
        ranks = {
            PriorityTier.CRITICAL: 4,
            PriorityTier.HIGH: 3,
            PriorityTier.MEDIUM: 2,
            PriorityTier.LOW: 1,
        }
        return ranks.get(self, 0)


class ScanModule(BaseModel):
    """Specification of a security testing module."""

    model_config = ConfigDict(extra="allow")

    name: str
    description: str
    category: str
    target_types: list[str] = Field(default_factory=lambda: ["web_app", "api"])
    default_priority: PriorityTier = PriorityTier.MEDIUM
    safe_mode_default: bool = True
    default_timeout_s: float = 300.0
    default_quota: int = 50
    skills: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    intrusive: bool = False
    min_tci: float = 0.0

    # Applicability conditions
    requires_auth: bool = False
    requires_api: bool = False
    requires_graphql: bool = False
    requires_jwt: bool = False
    requires_oauth: bool = False


class ModuleRegistry:
    """Registry managing available scan modules and metadata overrides."""

    def __init__(self, populate_defaults: bool = True) -> None:
        self._lock = threading.RLock()
        self._modules: dict[str, ScanModule] = {}
        if populate_defaults:
            self._load_builtins()

    def register(self, module: ScanModule) -> None:
        """Register or replace a scan module."""
        with self._lock:
            self._modules[module.name] = module
            logger.debug("Registered scan module: %s (%s)", module.name, module.category)

    def unregister(self, name: str) -> bool:
        """Unregister a scan module by name. Returns True if removed."""
        with self._lock:
            return self._modules.pop(name, None) is not None

    def get(self, name: str) -> ScanModule | None:
        """Retrieve a scan module by name."""
        with self._lock:
            return self._modules.get(name)

    def get_or_raise(self, name: str) -> ScanModule:
        """Retrieve a scan module by name or raise KeyError."""
        with self._lock:
            mod = self._modules.get(name)
            if mod is None:
                msg = f"Unknown scan module: '{name}'"
                raise KeyError(msg)
            return mod

    def list_all(self) -> list[ScanModule]:
        """Return all registered modules."""
        with self._lock:
            return list(self._modules.values())

    def list_by_category(self, category: str) -> list[ScanModule]:
        """Return modules matching the given category."""
        clean = category.lower().strip()
        with self._lock:
            return [m for m in self._modules.values() if m.category.lower() == clean]

    def list_by_tag(self, tag: str) -> list[ScanModule]:
        """Return modules carrying the given tag."""
        clean = tag.lower().strip()
        with self._lock:
            return [m for m in self._modules.values() if clean in (t.lower() for t in m.tags)]

    def update_metadata(
        self,
        name: str,
        *,
        priority: PriorityTier | str | None = None,
        quota: int | None = None,
        safe_mode: bool | None = None,
        timeout_s: float | None = None,
        description: str | None = None,
    ) -> ScanModule:
        """Update priority, quotas, safe_mode hints or timeouts on a registered module.

        Args:
            name: Name of the module to update.
            priority: Updated priority tier.
            quota: Updated execution quota.
            safe_mode: Updated safe_mode default.
            timeout_s: Updated timeout in seconds.
            description: Updated description.

        Returns:
            The updated ScanModule instance.
        """
        with self._lock:
            current = self.get_or_raise(name)
            data = current.model_dump()

            if priority is not None:
                p_tier = PriorityTier(priority) if isinstance(priority, str) else priority
                data["default_priority"] = p_tier
            if quota is not None:
                data["default_quota"] = quota
            if safe_mode is not None:
                data["safe_mode_default"] = safe_mode
            if timeout_s is not None:
                data["default_timeout_s"] = timeout_s
            if description is not None:
                data["description"] = description

            updated = ScanModule(**data)
            self._modules[name] = updated
            logger.info("Updated metadata for scan module: %s", name)
            return updated

    def find_applicable(
        self,
        fingerprint: TargetFingerprint | dict[str, Any],
    ) -> list[ScanModule]:
        """Find modules applicable to a given target fingerprint.

        Filters out irrelevant modules based on tech stack, target type,
        and missing prerequisite capabilities (e.g. omitting JWT checks when
        no JWT authentication pattern was observed).
        """
        fp = (
            fingerprint
            if isinstance(fingerprint, TargetFingerprint)
            else TargetFingerprint(**fingerprint)
        )
        canonical_target_type = normalize_target_type(fp.target_type)

        with self._lock:
            candidates = list(self._modules.values())

        applicable: list[ScanModule] = []
        has_auth = bool(fp.auth_patterns)
        has_jwt = any("jwt" in p.lower() for p in fp.auth_patterns)
        has_oauth = any(
            any(tok in p.lower() for tok in ("oauth", "oauth2", "oidc", "sso", "saml"))
            for p in fp.auth_patterns
        )
        has_api = (
            canonical_target_type == "api"
            or fp.api_surface.endpoints_count > 0
            or bool(fp.api_surface.api_types)
        )
        has_graphql = any("graphql" in t.lower() for t in fp.api_surface.api_types) or any(
            "graphql" in p.lower() for p in fp.protocols
        )

        for mod in candidates:
            # Target type check
            if (
                canonical_target_type
                and mod.target_types
                and canonical_target_type not in mod.target_types
            ):
                continue

            # Feature conditions
            if mod.requires_auth and not has_auth:
                continue
            if mod.requires_jwt and not has_jwt:
                continue
            if mod.requires_oauth and not has_oauth:
                continue
            if mod.requires_api and not has_api:
                continue
            if mod.requires_graphql and not has_graphql:
                continue

            applicable.append(mod)

        return applicable

    def _load_builtins(self) -> None:
        """Register the built-in vulnerability scanning modules."""
        builtins: list[ScanModule] = [
            ScanModule(
                name="auth-enum",
                description=(
                    "Authentication surface enumeration, credential exposure, "
                    "and brute-force resistance"
                ),
                category="authentication",
                target_types=["web_app", "api"],
                default_priority=PriorityTier.HIGH,
                safe_mode_default=True,
                default_timeout_s=300.0,
                default_quota=60,
                skills=[
                    "vulnerabilities/authentication_jwt",
                    "vulnerabilities/weak_password_detection",
                ],
                tags=["auth", "credentials", "owasp-a07"],
                requires_auth=True,
            ),
            ScanModule(
                name="id_or",
                description=(
                    "Insecure Direct Object Reference (IDOR) and broken object-level "
                    "authorization testing"
                ),
                category="authorization",
                target_types=["web_app", "api"],
                default_priority=PriorityTier.HIGH,
                safe_mode_default=True,
                default_timeout_s=360.0,
                default_quota=80,
                skills=[
                    "vulnerabilities/idor",
                    "vulnerabilities/broken_function_level_authorization",
                ],
                prerequisites=["auth-enum"],
                tags=["authz", "idor", "owasp-a01"],
                requires_auth=True,
            ),
            ScanModule(
                name="sqli-fuzz",
                description=(
                    "SQL injection detection, parameter boundary fuzzing, and blind "
                    "SQLi verification"
                ),
                category="injection",
                target_types=["web_app", "api", "whitebox"],
                default_priority=PriorityTier.HIGH,
                safe_mode_default=False,
                default_timeout_s=300.0,
                default_quota=50,
                skills=["vulnerabilities/sql_injection", "tooling/sqlmap"],
                tags=["injection", "database", "owasp-a03"],
                intrusive=True,
            ),
            ScanModule(
                name="xss-test",
                description=(
                    "Cross-site scripting (reflected, stored, and DOM-based) payload evaluation"
                ),
                category="injection",
                target_types=["web_app"],
                default_priority=PriorityTier.MEDIUM,
                safe_mode_default=True,
                default_timeout_s=240.0,
                default_quota=40,
                skills=["vulnerabilities/xss", "vulnerabilities/browser_security"],
                tags=["xss", "client-side", "owasp-a03"],
            ),
            ScanModule(
                name="ssrf-probe",
                description=(
                    "Server-Side Request Forgery probing against internal metadata and "
                    "private network endpoints"
                ),
                category="injection",
                target_types=["web_app", "api", "cloud"],
                default_priority=PriorityTier.HIGH,
                safe_mode_default=True,
                default_timeout_s=300.0,
                default_quota=50,
                skills=["vulnerabilities/ssrf"],
                tags=["ssrf", "network", "owasp-a10"],
            ),
            ScanModule(
                name="rce-eval",
                description="Remote code execution and command injection verification",
                category="injection",
                target_types=["web_app", "api", "infra", "whitebox"],
                default_priority=PriorityTier.CRITICAL,
                safe_mode_default=True,
                default_timeout_s=360.0,
                default_quota=40,
                skills=["vulnerabilities/rce", "vulnerabilities/argument_injection"],
                tags=["rce", "command-injection", "critical"],
                intrusive=True,
            ),
            ScanModule(
                name="api-route-fuzz",
                description=(
                    "API route discovery, undocumented endpoint enumeration, and schema "
                    "mismatch testing"
                ),
                category="recon",
                target_types=["web_app", "api"],
                default_priority=PriorityTier.HIGH,
                safe_mode_default=False,
                default_timeout_s=300.0,
                default_quota=100,
                skills=["custom/api_spec_testing", "tooling/ffuf", "tooling/katana"],
                tags=["recon", "api", "discovery"],
            ),
            ScanModule(
                name="jwt-analyze",
                description=(
                    "JWT signature verification, algorithm confusion (none/HS256), "
                    "and claim tampering"
                ),
                category="authentication",
                target_types=["web_app", "api"],
                default_priority=PriorityTier.HIGH,
                safe_mode_default=True,
                default_timeout_s=240.0,
                default_quota=40,
                skills=["vulnerabilities/authentication_jwt"],
                prerequisites=["auth-enum"],
                tags=["jwt", "tokens", "auth"],
                requires_auth=True,
                requires_jwt=True,
            ),
            ScanModule(
                name="oauth-audit",
                description=(
                    "OAuth2/OIDC flow tampering, redirect URI validation, and state "
                    "parameter verification"
                ),
                category="authentication",
                target_types=["web_app", "api"],
                default_priority=PriorityTier.MEDIUM,
                safe_mode_default=True,
                default_timeout_s=240.0,
                default_quota=40,
                skills=["protocols/oauth"],
                tags=["oauth", "oidc", "auth"],
                requires_auth=True,
                requires_oauth=True,
            ),
            ScanModule(
                name="graphql-audit",
                description=(
                    "GraphQL schema introspection, batch query abuse, and nested "
                    "circular complexity checks"
                ),
                category="api",
                target_types=["web_app", "api"],
                default_priority=PriorityTier.MEDIUM,
                safe_mode_default=True,
                default_timeout_s=300.0,
                default_quota=50,
                skills=["protocols/graphql"],
                tags=["graphql", "api"],
                requires_graphql=True,
            ),
            ScanModule(
                name="traversal-test",
                description=(
                    "Directory/path traversal, local and remote file inclusion (LFI/RFI) validation"
                ),
                category="injection",
                target_types=["web_app", "api", "whitebox"],
                default_priority=PriorityTier.HIGH,
                safe_mode_default=True,
                default_timeout_s=240.0,
                default_quota=50,
                skills=["vulnerabilities/path_traversal_lfi_rfi"],
                tags=["lfi", "rfi", "traversal"],
                intrusive=True,
            ),
            ScanModule(
                name="business-logic",
                description=(
                    "Business workflow flaws, race conditions, price/quantity tampering, "
                    "and state bypasses"
                ),
                category="logic",
                target_types=["web_app", "api"],
                default_priority=PriorityTier.MEDIUM,
                safe_mode_default=True,
                default_timeout_s=360.0,
                default_quota=60,
                skills=[
                    "vulnerabilities/business_logic",
                    "vulnerabilities/race_conditions",
                ],
                prerequisites=["auth-enum"],
                tags=["logic", "workflow"],
                requires_auth=True,
            ),
            ScanModule(
                name="mass-assignment",
                description=(
                    "Object property injection and mass assignment on REST update/create endpoints"
                ),
                category="api",
                target_types=["web_app", "api"],
                default_priority=PriorityTier.MEDIUM,
                safe_mode_default=True,
                default_timeout_s=240.0,
                default_quota=40,
                skills=["vulnerabilities/mass_assignment"],
                tags=["api", "mass-assignment"],
                requires_api=True,
            ),
            ScanModule(
                name="cors-misconfig",
                description=(
                    "Cross-Origin Resource Sharing (CORS) origin reflection and "
                    "null-origin validation"
                ),
                category="recon",
                target_types=["web_app", "api"],
                default_priority=PriorityTier.LOW,
                safe_mode_default=True,
                default_timeout_s=180.0,
                default_quota=30,
                skills=["vulnerabilities/browser_security"],
                tags=["cors", "headers"],
            ),
            ScanModule(
                name="info-disclosure",
                description=(
                    "Information disclosure via verbose stack traces, debug headers, "
                    "and exposed files"
                ),
                category="recon",
                target_types=["web_app", "api", "infra"],
                default_priority=PriorityTier.LOW,
                safe_mode_default=True,
                default_timeout_s=180.0,
                default_quota=40,
                skills=["vulnerabilities/information_disclosure"],
                tags=["recon", "disclosure"],
            ),
            ScanModule(
                name="csrf-audit",
                description="Cross-Site Request Forgery and anti-CSRF token defense verification",
                category="authorization",
                target_types=["web_app"],
                default_priority=PriorityTier.LOW,
                safe_mode_default=True,
                default_timeout_s=180.0,
                default_quota=30,
                skills=["vulnerabilities/csrf"],
                tags=["csrf", "authz"],
                requires_auth=True,
            ),
        ]

        for mod in builtins:
            self._modules[mod.name] = mod


# Default singleton registry
default_registry = ModuleRegistry(populate_defaults=True)


def get_module(name: str) -> ScanModule | None:
    """Retrieve a module from the default registry."""
    return default_registry.get(name)


def register_module(module: ScanModule) -> None:
    """Register a module in the default registry."""
    default_registry.register(module)


def list_modules() -> list[ScanModule]:
    """List all modules in the default registry."""
    return default_registry.list_all()
