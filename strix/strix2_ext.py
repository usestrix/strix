"""Strix 2 extension bootstrap.

One place to wire Strix 2's additive capabilities into a run without scattering
edits through the upstream startup path. Called once at the top of
``run_strix_scan`` (the single upstream edit); everything else it touches is a
new module. Idempotent — safe to call again on resume or in tests.

This foundation registers the scope agent tools and loads the scope policy. Later
areas (the candidate/lead tier, domain skills, the recon cache, ...) extend this
through the same seams (``register_agent_tools`` / ``register_skill_dir``).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from strix.agents.factory import register_agent_tools
from strix.scope.enforcement import load_active_policy
from strix.tools.scope.tools import check_scope, scope_status


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

_STRIX2_TOOLS = (
    check_scope,
    scope_status,
)


def install_strix2_extensions(run_dir: Path | None = None) -> None:
    """Register Strix 2 tools and load the scope policy for the run.

    Idempotent. The scope policy is resolved from ``scope.yaml`` /
    ``$STRIX_SCOPE_CONFIG`` (with ``--allow-intrusive`` via ``STRIX_ALLOW_INTRUSIVE``)
    and set active for the run; absent, enforcement stays inactive.
    """
    load_active_policy()
    register_agent_tools(*_STRIX2_TOOLS)
    logger.info("Strix 2 extensions installed (scope tools registered, run_dir=%s)", run_dir)
