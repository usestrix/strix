"""Redacted append-only safety decision audit."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path

    from strix.safety.types import SafetyDecision


class SafetyAudit:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()

    async def record(
        self,
        *,
        agent_id: str,
        tool_call_id: str,
        tool_name: str,
        decision: SafetyDecision,
        summary: dict[str, Any],
        execution_status: str = "not_started",
    ) -> None:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "agent_id": agent_id,
            "tool_call_id": tool_call_id,
            "tool_name": tool_name,
            "case_id": decision.case_id,
            "allowed": decision.allowed,
            "decision_source": decision.source,
            "reason": decision.reason,
            "categories": list(decision.categories),
            "risk": decision.risk,
            "deferred": decision.deferred,
            "execution_status": execution_status,
            "summary": summary,
        }
        async with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
