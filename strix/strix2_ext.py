"""Strix 2 extension bootstrap.

One place to wire Strix 2's additive capabilities into a run without scattering
edits through the upstream startup path. Called once at the top of
``run_strix_scan`` (the single upstream edit); everything else it touches is a
new module. Idempotent — safe to call again on resume or in tests.

Registers the candidate + scope + finding-annotation agent tools and binds the
candidate and finding-annotation stores to the run directory, plus loads the scope
policy. Later areas (domain skills, the recon cache, ...) extend this through the
same seams (``register_agent_tools`` / ``register_skill_dir``).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from strix.agents.factory import register_agent_tools
from strix.candidates.store import reset_candidate_store
from strix.findings2.store import reset_annotation_store
from strix.scope.enforcement import load_active_policy
from strix.tools.candidates.tools import (
    create_candidate,
    dismiss_candidate,
    list_candidates,
    promote_candidate,
)
from strix.tools.findings2.tools import annotate_finding, list_finding_annotations
from strix.tools.scope.tools import check_scope, scope_status


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

_STRIX2_TOOLS = (
    create_candidate,
    list_candidates,
    promote_candidate,
    dismiss_candidate,
    check_scope,
    scope_status,
    annotate_finding,
    list_finding_annotations,
)


def install_strix2_extensions(run_dir: Path | None = None) -> None:
    """Register Strix 2 tools, bind per-run stores, and load the scope policy.

    Idempotent. The scope policy is resolved from ``scope.yaml`` /
    ``$STRIX_SCOPE_CONFIG`` (with ``--allow-intrusive`` via ``STRIX_ALLOW_INTRUSIVE``)
    and set active for the run; absent, enforcement stays inactive.
    """
    reset_candidate_store(run_dir)
    reset_annotation_store(run_dir)
    load_active_policy()
    register_agent_tools(*_STRIX2_TOOLS)
    logger.info("Strix 2 extensions installed (tools registered, run_dir=%s)", run_dir)
