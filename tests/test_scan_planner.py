"""Tests for adaptive ScanPlanner and plan generation from TCI."""

from __future__ import annotations

import json

import pytest

from strix.agents.planner import ScanPlan, ScanPlanner
from strix.core.tci import ApiSurface, TargetFingerprint, calculate_tci
from strix.modules.registry import PriorityTier, ScanModule


def test_planner_generates_exact_payload_schema() -> None:
    planner = ScanPlanner()
    target = "https://api.example.local"
    fp = {
        "target_type": "api",
        "open_ports": [443],
        "protocols": ["https"],
        "auth_patterns": ["jwt"],
        "api_surface": {
            "endpoints_count": 30,
            "api_types": ["rest"],
        },
        "waf_cdn": ["cloudflare"],
        "data_sensitivity": "high",
    }

    plan = planner.generate_plan(target, fp, scan_mode="deep")

    assert isinstance(plan, ScanPlan)
    assert plan.target == target
    assert isinstance(plan.tci, float)
    assert plan.tci > 0.0
    assert len(plan.plan) > 0

    wire_dict = plan.to_dict(compact=True)
    assert wire_dict["target"] == target
    assert wire_dict["tci"] == plan.tci
    assert isinstance(wire_dict["fingerprint"], dict)
    assert isinstance(wire_dict["plan"], list)

    for item in wire_dict["plan"]:
        assert "step" in item
        assert "module" in item
        assert "priority" in item
        assert "safe_mode" in item
        assert isinstance(item["step"], int)
        assert isinstance(item["module"], str)
        assert isinstance(item["safe_mode"], bool)

    # Validate JSON serialization round-trip
    serialized = plan.to_json(compact=True)
    parsed = json.loads(serialized)
    assert parsed["target"] == target
    assert parsed["tci"] == plan.tci
    assert len(parsed["plan"]) == len(plan.plan)


def test_tactical_ordering_and_prerequisites() -> None:
    planner = ScanPlanner()
    target = "https://app.local"
    fp = TargetFingerprint(
        target=target,
        auth_patterns=["session_cookie"],
        api_surface=ApiSurface(endpoints_count=15),
        backend_technologies=["django", "postgres"],
    )

    plan = planner.generate_plan(target, fp, scan_mode="deep")
    mod_order = plan.module_names()

    # auth-enum must be scheduled before id_or and business-logic
    if "auth-enum" in mod_order and "id_or" in mod_order:
        auth_idx = mod_order.index("auth-enum")
        idor_idx = mod_order.index("id_or")
        assert auth_idx < idor_idx

    if "auth-enum" in mod_order and "business-logic" in mod_order:
        auth_idx = mod_order.index("auth-enum")
        logic_idx = mod_order.index("business-logic")
        assert auth_idx < logic_idx


def test_waf_activates_safe_mode() -> None:
    planner = ScanPlanner()
    target = "https://protected.local"

    # Target behind Cloudflare WAF
    fp_waf = TargetFingerprint(
        target=target,
        auth_patterns=["basic"],
        waf_cdn=["cloudflare_waf"],
    )
    plan_waf = planner.generate_plan(target, fp_waf)

    # Intrusive modules should have safe_mode=True
    sqli_step = plan_waf.get_step_by_module("sqli-fuzz")
    if sqli_step:
        assert sqli_step.safe_mode is True

    # Target without WAF and low complexity
    fp_clean = TargetFingerprint(
        target=target,
        auth_patterns=["basic"],
        waf_cdn=[],
        data_sensitivity="low",
    )
    plan_clean = planner.generate_plan(target, fp_clean)
    sqli_clean_step = plan_clean.get_step_by_module("sqli-fuzz")
    if sqli_clean_step:
        # sqli-fuzz default is False when no WAF and low complexity
        assert sqli_clean_step.safe_mode is False


def test_quick_mode_filters_priorities() -> None:
    planner = ScanPlanner()
    target = "https://quick.local"
    fp = TargetFingerprint(
        target=target,
        auth_patterns=["jwt"],
        api_surface=ApiSurface(endpoints_count=10),
    )

    plan_quick = planner.generate_plan(target, fp, scan_mode="quick")
    for step in plan_quick.plan:
        assert step.priority in ("critical", "high")


def test_max_steps_constraint() -> None:
    planner = ScanPlanner()
    target = "https://limited.local"
    fp = TargetFingerprint(
        target=target,
        auth_patterns=["jwt", "oauth2"],
        api_surface=ApiSurface(endpoints_count=20, api_types=["rest", "graphql"]),
    )

    plan = planner.generate_plan(target, fp, scan_mode="deep", max_steps=3)
    assert len(plan.plan) == 3
    assert [s.step for s in plan.plan] == [1, 2, 3]


def test_module_overrides_application() -> None:
    planner = ScanPlanner()
    target = "https://overrides.local"
    fp = TargetFingerprint(
        target=target,
        auth_patterns=["jwt"],
    )

    overrides = {
        "auth-enum": {
            "priority": "critical",
            "safe_mode": False,
            "quota": 99,
            "timeout_s": 555.0,
        }
    }

    plan = planner.generate_plan(
        target,
        fp,
        module_overrides=overrides,
    )
    step = plan.get_step_by_module("auth-enum")
    assert step is not None
    assert step.priority == "critical"
    assert step.safe_mode is False
    assert step.quota == 99
    assert step.timeout_s == 555.0


def test_plan_helpers_and_aggregation() -> None:
    planner = ScanPlanner()
    target = "https://helpers.local"
    fp = TargetFingerprint(
        target=target,
        auth_patterns=["jwt"],
        api_surface=ApiSurface(endpoints_count=10),
    )

    plan = planner.generate_plan(target, fp)

    step1 = plan.get_step(1)
    assert step1 is not None
    assert step1.step == 1

    assert plan.get_step(999) is None

    high_steps = plan.get_steps_by_priority("high")
    assert isinstance(high_steps, list)

    assert plan.total_quota() > 0
    assert plan.estimated_duration_s() > 0.0

    # Non-compact serialization contains extended fields
    full_dict = step1.to_dict(compact=False)
    assert "timeout_s" in full_dict
    assert "quota" in full_dict
    assert "skills" in full_dict
    assert "reason" in full_dict


def test_priority_filter_prerequisite_resolution() -> None:
    """Issue 2: priority_filter keeps business-logic and includes auth-enum prerequisite."""
    planner = ScanPlanner()
    target = "https://app.local"
    # Target with low complexity so business-logic is medium priority
    fp = TargetFingerprint(
        target=target,
        auth_patterns=["session_cookie"],
        data_sensitivity="low",
    )

    # By default, include_prerequisites=True: auth-enum is included before business-logic
    plan_with_prereq = planner.generate_plan(
        target,
        fp,
        priority_filter=["medium"],
        include_prerequisites=True,
    )
    names = plan_with_prereq.module_names()
    assert "business-logic" in names
    assert "auth-enum" in names
    assert names.index("auth-enum") < names.index("business-logic")

    # With include_prerequisites=False: business-logic dropped when requirement cannot be met
    plan_without_prereq = planner.generate_plan(
        target,
        fp,
        priority_filter=["medium"],
        include_prerequisites=False,
    )
    assert "business-logic" not in plan_without_prereq.module_names()


def test_priority_elevation_before_mode_filtering() -> None:
    """Issue 5: high TCI targets elevate business-logic before quick mode filtering."""
    planner = ScanPlanner()
    target = "https://complex.example.com"
    # High complexity target (TCI >= 70)
    fp_complex = TargetFingerprint(
        target=target,
        open_ports=[443, 8080, 8443, 5432],
        protocols=["https", "grpc"],
        auth_patterns=["jwt", "oauth2", "mfa", "rbac"],
        api_surface=ApiSurface(endpoints_count=60, api_types=["rest", "graphql"], has_spec=True),
        backend_technologies=["fastapi", "spring", "postgres", "redis"],
        waf_cdn=["cloudflare_waf", "aws_waf"],
        data_sensitivity="financial",
        patch_posture="legacy",
    )
    tci = calculate_tci(fp_complex).score
    assert tci >= 70.0

    # Quick mode keeps business-logic because its final effective priority was elevated to high
    plan_quick = planner.generate_plan(target, fp_complex, scan_mode="quick")
    names = plan_quick.module_names()
    assert "business-logic" in names
    step = plan_quick.get_step_by_module("business-logic")
    assert step is not None
    assert step.priority == "high"

    # User override elevates a medium module so quick mode keeps it
    plan_override = planner.generate_plan(
        target,
        fp_complex,
        scan_mode="quick",
        module_overrides={"cors-misconfig": {"priority": "high"}},
    )
    assert "cors-misconfig" in plan_override.module_names()


def test_circular_prerequisite_detection() -> None:
    """Issue 9: circular prerequisites report ValueError clearly instead of RecursionError."""
    planner = ScanPlanner()

    # 2-module cycle: A -> B -> A
    mod_a = ScanModule(
        name="cycle-a",
        description="Module A",
        category="injection",
        default_priority=PriorityTier.MEDIUM,
        prerequisites=["cycle-b"],
    )
    mod_b = ScanModule(
        name="cycle-b",
        description="Module B",
        category="injection",
        default_priority=PriorityTier.MEDIUM,
        prerequisites=["cycle-a"],
    )

    with pytest.raises(ValueError, match="Circular prerequisite dependency detected"):
        planner._order_modules([mod_a, mod_b])

    # 3-module cycle: X -> Y -> Z -> X
    mod_x = ScanModule(
        name="cycle-x",
        description="Module X",
        category="api",
        prerequisites=["cycle-y"],
    )
    mod_y = ScanModule(
        name="cycle-y",
        description="Module Y",
        category="api",
        prerequisites=["cycle-z"],
    )
    mod_z = ScanModule(
        name="cycle-z",
        description="Module Z",
        category="api",
        prerequisites=["cycle-x"],
    )

    with pytest.raises(ValueError, match="Circular prerequisite dependency detected"):
        planner._order_modules([mod_x, mod_y, mod_z])
