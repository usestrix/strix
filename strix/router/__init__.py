"""Strix 2 Phase 5 — per-role model routing (opt-in).

Pick a cheaper model for cheap work (recon / enumeration / mapping child agents)
while the root orchestrator and exploitation/validation children keep the main
model. The precedent is ``DedupeSettings`` (a separate model for the dedup judge).
Disabled by default, so upstream/default behavior is unchanged.
"""

from strix.router.router import (
    RouterSettings,
    load_router_settings,
    resolve_agent_model,
    role_for_skills,
    select_model,
)


__all__ = [
    "RouterSettings",
    "load_router_settings",
    "resolve_agent_model",
    "role_for_skills",
    "select_model",
]
