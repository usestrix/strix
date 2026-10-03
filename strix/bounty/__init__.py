"""Bug-bounty mode for Strix 2.

A thin, additive layer on top of the authorized-scope engine and the two-tier
finding model. It loads a HackerOne / Bugcrowd program into a platform-neutral
:class:`BountyProgram`, compiles its scope into a fail-closed
:class:`~strix.scope.schema.ScopePolicy`, turns the program's rules of engagement
into a go/no-go :class:`RoeGate` plus a constraint block for the agents, and dedupes
against known/disclosed reports so the engagement targets novel issues with
submission-ready evidence.

The engine that does the actual testing is unchanged: bounty mode only decides where
a run may go (scope), how it may behave (ROE), and what is already known (dedupe).
"""

from __future__ import annotations

from strix.bounty.compile import CompiledScope, classify_asset, compile_to_scope
from strix.bounty.dedupe import (
    KnownReport,
    KnownReportsStore,
    get_known_reports,
    render_dedupe_md,
    reset_known_reports,
    similarity,
)
from strix.bounty.roe import (
    DEFAULT_AUTOMATED_POLICY,
    AutomatedPolicy,
    RoeGate,
    evaluate_roe,
)
from strix.bounty.schema import (
    AssetType,
    BountyPlatform,
    BountyProgram,
    RulesOfEngagement,
    ScopeAsset,
)


__all__ = [
    "DEFAULT_AUTOMATED_POLICY",
    "AssetType",
    "AutomatedPolicy",
    "BountyPlatform",
    "BountyProgram",
    "CompiledScope",
    "KnownReport",
    "KnownReportsStore",
    "RoeGate",
    "RulesOfEngagement",
    "ScopeAsset",
    "classify_asset",
    "compile_to_scope",
    "evaluate_roe",
    "get_known_reports",
    "render_dedupe_md",
    "reset_known_reports",
    "similarity",
]
