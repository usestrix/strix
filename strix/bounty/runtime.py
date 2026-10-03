"""The active bug-bounty context for a run.

Bounty mode binds one :class:`BountyContext` at run start (the program, its compiled
scope, and the ROE gate) so the bounty agent tools can report the engagement's scope
and rules without re-loading anything. It mirrors the module-level singletons used by
the scope policy and the candidate store. Known/disclosed reports are bound
separately via :func:`strix.bounty.dedupe.reset_known_reports`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from strix.bounty.compile import CompiledScope
    from strix.bounty.roe import RoeGate
    from strix.bounty.schema import BountyProgram


@dataclass(frozen=True)
class BountyContext:
    """Everything bounty mode resolved for the run, bound once and read-only."""

    program: BountyProgram
    gate: RoeGate
    compiled: CompiledScope


_active: BountyContext | None = None


def get_bounty_context() -> BountyContext | None:
    return _active


def set_bounty_context(context: BountyContext | None) -> None:
    global _active  # noqa: PLW0603
    _active = context
