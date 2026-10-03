"""Authorized-scope policy for Strix 2.

A run's authorized targets — web origins, network hosts/CIDRs, cloud accounts and
API bases — are declared in ``scope.yaml`` and loaded into a :class:`ScopePolicy`.
Every domain tool and MCP wrapper checks a target against the policy before acting,
and intrusive (state-changing) actions are gated behind ``allow_intrusive``.

This package is intentionally self-contained (no imports from ``strix`` internals)
so it stays trivially rebaseable and unit-testable. Phase 0 ships the schema, a
fail-closed loader, and a pure evaluator; Phase 1 wires ``evaluate`` into the tool
boundary.
"""

from __future__ import annotations

from strix.scope.enforcement import (
    enforce_arguments,
    enforce_target,
    extract_targets,
    get_active_policy,
    load_active_policy,
    set_active_policy,
)
from strix.scope.loader import (
    DEFAULT_SCOPE_FILENAMES,
    ScopeConfigError,
    load_scope_policy,
)
from strix.scope.schema import (
    ApiScope,
    CloudScope,
    ExclusionScope,
    NetworkScope,
    ScopeDecision,
    ScopePolicy,
    WebScope,
)


__all__ = [
    "DEFAULT_SCOPE_FILENAMES",
    "ApiScope",
    "CloudScope",
    "ExclusionScope",
    "NetworkScope",
    "ScopeConfigError",
    "ScopeDecision",
    "ScopePolicy",
    "WebScope",
    "enforce_arguments",
    "enforce_target",
    "extract_targets",
    "get_active_policy",
    "load_active_policy",
    "load_scope_policy",
    "set_active_policy",
]
