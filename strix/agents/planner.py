"""Adaptive ScanPlanner: Maps TCI and fingerprints to dynamic scan plans."""

from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from strix.core.tci import TargetFingerprint, calculate_tci
from strix.modules.registry import ModuleRegistry, PriorityTier, ScanModule, default_registry


logger = logging.getLogger(__name__)


# Phase weights for tactical ordering
_PHASE_ORDER: dict[str, int] = {
    "recon": 0,
    "authentication": 1,
    "authorization": 2,
    "injection": 3,
    "api": 3,
    "logic": 4,
    "infrastructure": 5,
}


class ScanPlanStep(BaseModel):
    """An individual step in a dynamic scan plan."""

    model_config = ConfigDict(extra="allow")

    step: int = Field(ge=1)
    module: str
    priority: str
    safe_mode: bool
    timeout_s: float = 300.0
    quota: int = 50
    skills: list[str] = Field(default_factory=list)
    reason: str = ""

    def to_dict(self, *, compact: bool = True) -> dict[str, Any]:
        """Convert step to dictionary.

        When compact=True (default), outputs the standard wire format:
        {"step": 1, "module": "auth-enum", "priority": "high", "safe_mode": true}
        """
        payload: dict[str, Any] = {
            "step": self.step,
            "module": self.module,
            "priority": self.priority,
            "safe_mode": self.safe_mode,
        }
        if not compact:
            payload.update(
                {
                    "timeout_s": self.timeout_s,
                    "quota": self.quota,
                    "skills": self.skills,
                    "reason": self.reason,
                }
            )
        return payload


class ScanPlan(BaseModel):
    """Context-aware scan plan generated from target fingerprint and TCI."""

    model_config = ConfigDict(extra="allow")

    target: str
    fingerprint: dict[str, Any]
    tci: float
    tci_level: str
    plan: list[ScanPlanStep]
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self, *, compact: bool = True) -> dict[str, Any]:
        """Convert plan to serializable dictionary."""
        return {
            "target": self.target,
            "fingerprint": self.fingerprint,
            "tci": self.tci,
            "plan": [step.to_dict(compact=compact) for step in self.plan],
        }

    def to_json(self, *, compact: bool = True, indent: int | None = 2) -> str:
        """Convert plan to JSON string."""
        return json.dumps(self.to_dict(compact=compact), indent=indent, default=str)

    def get_step(self, step_number: int) -> ScanPlanStep | None:
        """Retrieve step by 1-based step index."""
        for s in self.plan:
            if s.step == step_number:
                return s
        return None

    def get_step_by_module(self, module_name: str) -> ScanPlanStep | None:
        """Retrieve step by module name."""
        clean = module_name.lower().strip()
        for s in self.plan:
            if s.module.lower() == clean:
                return s
        return None

    def get_steps_by_priority(self, priority: str) -> list[ScanPlanStep]:
        """Retrieve steps matching a priority tier."""
        clean = priority.lower().strip()
        return [s for s in self.plan if s.priority.lower() == clean]

    def module_names(self) -> list[str]:
        """Return ordered list of module names."""
        return [s.module for s in self.plan]

    def total_quota(self) -> int:
        """Sum total quota allocated across all steps."""
        return sum(s.quota for s in self.plan)

    def estimated_duration_s(self) -> float:
        """Sum total duration estimate across all steps."""
        return sum(s.timeout_s for s in self.plan)


class ScanPlanner:
    """Generates context-aware, tactical scan plans from Target Complexity Index."""

    def __init__(
        self,
        registry: ModuleRegistry | None = None,
    ) -> None:
        self.registry = registry or default_registry

    def generate_plan(
        self,
        target: str,
        fingerprint: TargetFingerprint | dict[str, Any],
        *,
        scan_mode: str = "deep",
        safe_mode_override: bool | None = None,
        priority_filter: list[str] | None = None,
        max_steps: int | None = None,
        module_overrides: dict[str, dict[str, Any]] | None = None,
        include_prerequisites: bool = True,
    ) -> ScanPlan:
        """Generate an adaptive scan plan.

        Args:
            target: Target URL, hostname, or checkout path.
            fingerprint: Target observables (ports, auth, api, waf, etc.).
            scan_mode: Scan mode ('quick', 'standard', 'deep', 'diff').
            safe_mode_override: Explicit safe_mode flag for all steps.
            priority_filter: Allowed priority tiers (e.g. ['critical', 'high']).
            max_steps: Maximum number of steps to schedule.
            module_overrides: Per-module overrides for priority, safe_mode, quota, timeout_s.
            include_prerequisites: Whether to automatically include missing required
                prerequisite modules from applicable pool (default: True). If False or
                if requirements cannot be met on the target, dependent modules are dropped.

        Returns:
            Structured ScanPlan with ordered, prioritized steps.
        """
        fp = (
            fingerprint
            if isinstance(fingerprint, TargetFingerprint)
            else TargetFingerprint(**(fingerprint or {}))
        )
        if not fp.target and target:
            fp.target = target

        # 1. Compute Target Complexity Index
        tci_res = calculate_tci(fp)
        tci_score = tci_res.score
        tci_level = tci_res.level.value

        # 2. Select applicable modules based on target context
        applicable = self.registry.find_applicable(fp)
        applicable_by_name = {m.name: m for m in applicable}
        overrides_dict = module_overrides or {}

        # 3. Calculate final effective priorities BEFORE filtering (reflects overrides)
        effective_priorities: dict[str, PriorityTier] = {}
        for mod in applicable:
            effective_priorities[mod.name] = self._resolve_module_priority(
                mod, fp, tci_score, overrides_dict.get(mod.name, {})
            )

        # 4. Filter candidates by scan_mode using effective priority
        selected = self._filter_by_scan_mode(applicable, scan_mode, effective_priorities)

        # 5. Filter by priority if requested using effective priority
        if priority_filter:
            allowed_p = {p.lower().strip() for p in priority_filter}
            selected = [
                m
                for m in selected
                if effective_priorities.get(m.name, m.default_priority).value.lower() in allowed_p
            ]

        # 6. Resolve prerequisites: include required steps or drop unsatisfied modules
        candidates = self._resolve_prerequisites(
            selected, applicable_by_name, include_prerequisites=include_prerequisites
        )

        # 7. Build and adapt plan steps
        steps = self._build_steps(
            candidates=candidates,
            fp=fp,
            tci_score=tci_score,
            safe_mode_override=safe_mode_override,
            module_overrides=overrides_dict,
            effective_priorities=effective_priorities,
        )

        # 8. Apply max_steps limit if specified
        if max_steps is not None:
            if max_steps < 0:
                raise ValueError("max_steps must be non-negative")
            steps = steps[:max_steps]
            # Renumber sequentially
            for idx, step in enumerate(steps, start=1):
                step.step = idx

        fp_dict = fp.model_dump(exclude={"metadata"})

        return ScanPlan(
            target=target or fp.target,
            fingerprint=fp_dict,
            tci=tci_score,
            tci_level=tci_level,
            plan=steps,
            metadata={
                "scan_mode": scan_mode,
                "total_steps": len(steps),
                "total_quota": sum(s.quota for s in steps),
                "estimated_duration_s": sum(s.timeout_s for s in steps),
                "tci_breakdown": tci_res.breakdown,
            },
        )

    def _resolve_prerequisites(
        self,
        selected: list[ScanModule],
        applicable_by_name: dict[str, ScanModule],
        include_prerequisites: bool,
    ) -> list[ScanModule]:
        """Include required prerequisites or drop modules whose requirements cannot be met."""
        selected_by_name = {m.name: m for m in selected}

        if include_prerequisites:
            added_any = True
            while added_any:
                added_any = False
                for m in list(selected_by_name.values()):
                    for req in m.prerequisites:
                        if req not in selected_by_name and req in applicable_by_name:
                            selected_by_name[req] = applicable_by_name[req]
                            added_any = True

        removed_any = True
        while removed_any:
            removed_any = False
            for name, m in list(selected_by_name.items()):
                missing = [req for req in m.prerequisites if req not in selected_by_name]
                if missing:
                    logger.warning(
                        "Dropping module '%s' from plan: prerequisite(s) %s cannot be met",
                        name,
                        missing,
                    )
                    del selected_by_name[name]
                    removed_any = True

        return list(selected_by_name.values())

    def _resolve_module_priority(
        self,
        mod: ScanModule,
        fp: TargetFingerprint,
        tci_score: float,
        overrides: dict[str, Any],
    ) -> PriorityTier:
        override = overrides.get("priority")
        if override is not None:
            if isinstance(override, PriorityTier):
                return override
            try:
                return PriorityTier(str(override).lower())
            except ValueError:
                logger.warning("Invalid priority override '%s' for module '%s'", override, mod.name)
        elevated_str = self._elevate_priority(mod, fp, tci_score)
        try:
            return PriorityTier(elevated_str.lower())
        except ValueError:
            return mod.default_priority

    def _filter_by_scan_mode(
        self,
        candidates: list[ScanModule],
        scan_mode: str,
        effective_priorities: dict[str, PriorityTier] | None = None,
    ) -> list[ScanModule]:
        mode = scan_mode.lower().strip()

        def get_p(m: ScanModule) -> PriorityTier:
            if effective_priorities and m.name in effective_priorities:
                return effective_priorities[m.name]
            return m.default_priority

        if mode == "quick":
            return [m for m in candidates if get_p(m) in (PriorityTier.CRITICAL, PriorityTier.HIGH)]
        if mode == "standard":
            return [
                m
                for m in candidates
                if get_p(m) in (PriorityTier.CRITICAL, PriorityTier.HIGH, PriorityTier.MEDIUM)
            ]
        return candidates

    def _resolve_safe_mode(
        self,
        mod: ScanModule,
        fp: TargetFingerprint,
        tci_score: float,
        safe_mode_override: bool | None,
        overrides: dict[str, Any],
    ) -> bool:
        if safe_mode_override is not None:
            return safe_mode_override
        if "safe_mode" in overrides:
            return bool(overrides["safe_mode"])
        if bool(fp.waf_cdn) or tci_score >= 65.0:
            return True
        return mod.safe_mode_default

    def _resolve_quota(
        self,
        mod: ScanModule,
        tci_score: float,
        overrides: dict[str, Any],
    ) -> int:
        quota_val = overrides.get("quota")
        if quota_val is not None:
            return int(quota_val)
        if tci_score >= 65.0:
            return round(mod.default_quota * 1.5)
        if tci_score <= 30.0:
            return max(15, round(mod.default_quota * 0.6))
        return mod.default_quota

    def _resolve_timeout(
        self,
        mod: ScanModule,
        tci_score: float,
        overrides: dict[str, Any],
    ) -> float:
        timeout_val = overrides.get("timeout_s")
        if timeout_val is not None:
            return float(timeout_val)
        if tci_score >= 65.0:
            return round(mod.default_timeout_s * 1.25, 1)
        if tci_score <= 30.0:
            return max(60.0, round(mod.default_timeout_s * 0.7, 1))
        return mod.default_timeout_s

    def _build_steps(
        self,
        candidates: list[ScanModule],
        fp: TargetFingerprint,
        tci_score: float,
        safe_mode_override: bool | None,
        module_overrides: dict[str, dict[str, Any]],
        effective_priorities: dict[str, PriorityTier] | None = None,
    ) -> list[ScanPlanStep]:
        ordered_modules = self._order_modules(candidates)
        steps: list[ScanPlanStep] = []

        for idx, mod in enumerate(ordered_modules, start=1):
            overrides = module_overrides.get(mod.name, {})

            if effective_priorities and mod.name in effective_priorities:
                priority = effective_priorities[mod.name].value.lower()
            else:
                priority_val = overrides.get("priority")
                priority = (
                    str(priority_val).lower()
                    if priority_val is not None
                    else self._elevate_priority(mod, fp, tci_score)
                )

            safe_mode = self._resolve_safe_mode(mod, fp, tci_score, safe_mode_override, overrides)
            quota = self._resolve_quota(mod, tci_score, overrides)
            timeout_s = self._resolve_timeout(mod, tci_score, overrides)
            reason = self._build_step_reason(mod, fp, tci_score, safe_mode)

            steps.append(
                ScanPlanStep(
                    step=idx,
                    module=mod.name,
                    priority=priority,
                    safe_mode=safe_mode,
                    timeout_s=timeout_s,
                    quota=quota,
                    skills=list(mod.skills),
                    reason=reason,
                )
            )

        return steps

    def _elevate_priority(
        self,
        mod: ScanModule,
        fp: TargetFingerprint,
        tci_score: float,
    ) -> str:
        base = mod.default_priority.value.lower()
        if tci_score >= 70.0 and mod.name in ("id_or", "business-logic"):
            return "high" if base == "medium" else base
        has_db = any("sql" in b or "db" in b for b in fp.backend_technologies)
        if has_db and mod.name == "sqli-fuzz":
            return "high"
        return base

    def _build_step_reason(
        self,
        mod: ScanModule,
        fp: TargetFingerprint,
        tci_score: float,
        safe_mode: bool,
    ) -> str:
        notes: list[str] = [f"Phase: {mod.category}"]
        if safe_mode and bool(fp.waf_cdn):
            notes.append("safe_mode enabled due to WAF/CDN presence")
        elif safe_mode and tci_score >= 65.0:
            notes.append("safe_mode enabled due to high target complexity")
        if mod.prerequisites:
            notes.append(f"requires {', '.join(mod.prerequisites)}")
        return "; ".join(notes)

    def _order_modules(self, modules: list[ScanModule]) -> list[ScanModule]:
        """Order modules tactically by phase and prerequisite dependencies.

        Detects circular dependencies and reports them clearly with ValueError.
        """
        by_name = {m.name: m for m in modules}

        def sort_key(m: ScanModule) -> tuple[int, int, int, str]:
            phase = _PHASE_ORDER.get(m.category.lower(), 99)
            p_rank = -m.default_priority.rank
            prereq_depth = len(m.prerequisites)
            return (phase, prereq_depth, p_rank, m.name)

        sorted_mods = sorted(modules, key=sort_key)

        ordered: list[ScanModule] = []
        placed: set[str] = set()
        visiting: set[str] = set()

        def place(m: ScanModule) -> bool:
            if m.name in placed:
                return True
            if m.name in visiting:
                msg = f"Circular prerequisite dependency detected involving module '{m.name}'"
                raise ValueError(msg)
            visiting.add(m.name)
            try:
                for req in m.prerequisites:
                    if req not in by_name:
                        logger.warning(
                            "Cannot place module '%s': prerequisite '%s' cannot be met",
                            m.name,
                            req,
                        )
                        return False
                    if not place(by_name[req]):
                        return False
                ordered.append(m)
                placed.add(m.name)
                return True
            finally:
                visiting.remove(m.name)

        for mod in sorted_mods:
            place(mod)

        return ordered
