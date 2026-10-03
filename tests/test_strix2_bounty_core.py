"""Tests for the bug-bounty core: scope exclusions, compile, and the ROE gate."""

from __future__ import annotations

from strix.bounty import (
    BountyProgram,
    RulesOfEngagement,
    ScopeAsset,
    classify_asset,
    compile_to_scope,
    evaluate_roe,
)
from strix.scope.schema import ScopePolicy


# --- scope exclusions (deny-first) -------------------------------------------


def test_exclusion_host_overrides_wildcard() -> None:
    p = ScopePolicy.model_validate(
        {
            "web": {"domains": ["*.example.com"]},
            "exclusions": {"hosts": ["admin.example.com"]},
        }
    )
    assert p.evaluate("https://app.example.com").allowed
    denied = p.evaluate("https://admin.example.com/login")
    assert not denied.allowed
    assert "exclusion" in denied.reason


def test_exclusion_url_prefix_carves_out_a_path() -> None:
    p = ScopePolicy.model_validate(
        {
            "web": {"domains": ["example.com"]},
            "exclusions": {"urls": ["https://example.com/billing"]},
        }
    )
    assert p.evaluate("https://example.com/search").allowed
    assert not p.evaluate("https://example.com/billing/invoices").allowed
    # Path-boundary: /billings must NOT be caught by the /billing exclusion.
    assert p.evaluate("https://example.com/billings").allowed


def test_exclusion_cidr_denies_a_host_in_range() -> None:
    p = ScopePolicy.model_validate(
        {
            "network": {"cidrs": ["10.0.0.0/16"]},
            "exclusions": {"cidrs": ["10.0.5.0/24"]},
        }
    )
    assert p.evaluate("10.0.1.9").allowed
    assert not p.evaluate("10.0.5.9").allowed


def test_no_exclusions_is_unchanged_behavior() -> None:
    p = ScopePolicy.model_validate({"web": {"domains": ["example.com"]}})
    assert p.evaluate("https://example.com").allowed
    assert not p.evaluate("https://evil.com").allowed


# --- classify_asset ----------------------------------------------------------


def test_classify_heuristics_without_explicit_type() -> None:
    assert classify_asset(ScopeAsset(identifier="*.example.com")) == ("web", "*.example.com")
    assert classify_asset(ScopeAsset(identifier="example.com")) == ("web", "example.com")
    assert classify_asset(ScopeAsset(identifier="10.0.0.0/24")) == ("cidr", "10.0.0.0/24")
    assert classify_asset(ScopeAsset(identifier="203.0.113.7")) == ("network_host", "203.0.113.7")
    assert classify_asset(ScopeAsset(identifier="aws:123456789012")) == ("aws", "123456789012")
    # A URL with a path is treated as an API base; a bare origin as a web host.
    assert classify_asset(ScopeAsset(identifier="https://api.example.com/v1")) == (
        "api",
        "https://api.example.com/v1",
    )
    assert classify_asset(ScopeAsset(identifier="https://www.example.com")) == (
        "web",
        "www.example.com",
    )


def test_classify_explicit_type_wins() -> None:
    # An explicit wildcard type keeps the host even though it has no star.
    assert classify_asset(ScopeAsset(identifier="example.com", asset_type="api")) == (
        "api",
        "https://example.com",
    )
    assert classify_asset(ScopeAsset(identifier="my-app", asset_type="android")) == ("skip", None)


# --- compile_to_scope --------------------------------------------------------


def _program(**roe_kwargs: object) -> BountyProgram:
    return BountyProgram(
        platform="hackerone",
        handle="acme",
        name="Acme VDP",
        in_scope=[
            ScopeAsset(identifier="*.acme.com", asset_type="wildcard"),
            ScopeAsset(identifier="https://api.acme.com/v2", asset_type="api"),
            ScopeAsset(identifier="198.51.100.0/24", asset_type="cidr"),
            ScopeAsset(identifier="aws:123456789012", asset_type="cloud_aws"),
            ScopeAsset(identifier="com.acme.app", asset_type="android"),
        ],
        out_of_scope=[
            ScopeAsset(identifier="blog.acme.com", asset_type="domain"),
            ScopeAsset(identifier="https://acme.com/corp", asset_type="url"),
        ],
        roe=RulesOfEngagement(**roe_kwargs),  # type: ignore[arg-type]
    )


def test_compile_maps_each_domain_and_collects_unmapped() -> None:
    compiled = compile_to_scope(_program())
    p = compiled.policy
    assert p.web.domains == ["*.acme.com"]
    assert p.api.base_urls == ["https://api.acme.com/v2"]
    assert p.network.cidrs == ["198.51.100.0/24"]
    assert p.cloud.aws_account_ids == ["123456789012"]
    # The Android app cannot be gated by the network scope engine.
    assert compiled.unmapped == ["com.acme.app"]
    assert p.exclusions.hosts == ["blog.acme.com"]
    assert p.exclusions.urls == ["https://acme.com/corp"]


def test_compiled_scope_enforces_in_and_out_of_scope() -> None:
    p = compile_to_scope(_program()).policy
    assert p.evaluate("https://shop.acme.com").allowed
    assert p.evaluate("https://api.acme.com/v2/users/1").allowed
    assert p.evaluate("198.51.100.5").allowed
    assert p.evaluate("aws:123456789012").allowed
    # Out-of-scope carve-outs and anything unlisted are denied.
    assert not p.evaluate("https://blog.acme.com").allowed
    assert not p.evaluate("https://acme.com/corp/secret").allowed
    assert not p.evaluate("https://notacme.com").allowed


def test_intrusive_policy_auto_follows_the_program() -> None:
    off = compile_to_scope(_program(state_changing_poc_allowed=False), intrusive_policy="auto")
    assert off.policy.allow_intrusive is False
    on = compile_to_scope(_program(state_changing_poc_allowed=True), intrusive_policy="auto")
    assert on.policy.allow_intrusive is True
    # "never" forces it off even when the program would allow it.
    never = compile_to_scope(_program(state_changing_poc_allowed=True), intrusive_policy="never")
    assert never.policy.allow_intrusive is False


# --- evaluate_roe ------------------------------------------------------------


def test_roe_refuses_when_automation_prohibited_by_default() -> None:
    program = _program(automated_testing_allowed=False)
    gate = evaluate_roe(program)  # default policy = refuse
    assert gate.proceed is False
    assert gate.mode == "refused"
    assert gate.active_tools_allowed is False
    assert any("PROHIBITS" in w for w in gate.warnings)


def test_roe_recon_only_proceeds_without_active_tools() -> None:
    program = _program(automated_testing_allowed=False)
    gate = evaluate_roe(program, automated_policy="recon_only")
    assert gate.proceed is True
    assert gate.mode == "recon_only"
    assert gate.active_tools_allowed is False
    assert "Recon-only mode" in gate.render_constraints_md()


def test_roe_warn_and_proceed_runs_with_active_tools() -> None:
    program = _program(automated_testing_allowed=False)
    gate = evaluate_roe(program, automated_policy="warn_and_proceed")
    assert gate.proceed is True
    assert gate.mode == "warn_and_proceed"
    assert gate.active_tools_allowed is True


def test_roe_normal_run_when_allowed_and_constraints_present() -> None:
    program = _program(
        automated_testing_allowed=True,
        rate_limit_rps=5,
        prohibited_actions=["DoS", "social engineering"],
        ineligible_vuln_types=["self-XSS", "missing SPF"],
    )
    gate = evaluate_roe(program)
    assert gate.proceed is True
    assert gate.mode == "normal"
    block = gate.render_constraints_md()
    assert "5" in block and "DoS" in block and "self-XSS" in block


def test_roe_warns_when_automation_unstated() -> None:
    gate = evaluate_roe(_program())  # automated_testing_allowed defaults to None
    assert gate.proceed is True
    assert gate.mode == "normal"
    assert any("does not state" in w for w in gate.warnings)
