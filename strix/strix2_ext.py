"""Strix 2 extension bootstrap.

One place to wire Strix 2's additive capabilities into a run without scattering
edits through the upstream startup path. Called once at the top of
``run_strix_scan`` (the single upstream edit); everything else it touches is a
new module. Idempotent — safe to call again on resume or in tests.

Registers the candidate + scope + finding-annotation + recon-cache agent tools,
binds the candidate and finding-annotation stores to the run directory, binds the
cross-run recon cache to its shared root, loads the scope policy, and registers the
Strix 2 skill directory (``strix/skills2``) via ``register_skill_dir`` so its
playbooks are selectable. Future domain tools/skills plug in here through the same
seams (``register_agent_tools`` / ``register_skill_dir``).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from strix.agents.factory import register_agent_tools
from strix.bounty.bootstrap import activate_bounty_from_env
from strix.cache.store import reset_recon_cache
from strix.candidates.store import reset_candidate_store
from strix.findings2.store import reset_annotation_store
from strix.scope.enforcement import load_active_policy
from strix.skills import register_skill_dir
from strix.tools.bounty.tools import bounty_scope_status, check_duplicate
from strix.tools.cache.tools import recon_cache_get, recon_cache_put, recon_cache_stats
from strix.tools.candidates.tools import (
    create_candidate,
    dismiss_candidate,
    list_candidates,
    promote_candidate,
)
from strix.tools.findings2.tools import annotate_finding, list_finding_annotations
from strix.tools.scope.tools import check_scope, scope_status
from strix.utils.resource_paths import get_strix_resource_path


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
    recon_cache_get,
    recon_cache_put,
    recon_cache_stats,
    bounty_scope_status,
    check_duplicate,
)


def install_strix2_extensions(run_dir: Path | None = None) -> None:
    """Register Strix 2 tools, bind per-run stores, and load the scope policy.

    Idempotent. The scope policy is resolved from ``scope.yaml`` /
    ``$STRIX_SCOPE_CONFIG`` (with ``--allow-intrusive`` via ``STRIX_ALLOW_INTRUSIVE``)
    and set active for the run; absent, enforcement stays inactive. The recon cache
    is bound to its shared, cross-run root (not ``run_dir``) and is never cleared here.
    """
    reset_candidate_store(run_dir)
    reset_annotation_store(run_dir)
    reset_recon_cache()
    load_active_policy()
    # Bind the bug-bounty context + known reports from the environment, if a bounty
    # program was wired by the CLI. No-op for an ordinary run.
    activate_bounty_from_env()
    register_agent_tools(*_STRIX2_TOOLS)
    register_skill_dir(get_strix_resource_path("skills2"))
    logger.info("Strix 2 extensions installed (tools registered, run_dir=%s)", run_dir)
