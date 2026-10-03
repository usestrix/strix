"""Tests for the Strix 2 authorized-scope policy (schema, loader, evaluator)."""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.scope import ScopeConfigError, ScopePolicy, load_scope_policy


def _policy(**overrides: object) -> ScopePolicy:
    base: dict[str, object] = {
        "allow_intrusive": False,
        "web": {"domains": ["example.com", "*.staging.example.com"]},
        "api": {"base_urls": ["https://api.example.com/v1"]},
        "network": {"hosts": ["10.0.0.5", "host.internal"], "cidrs": ["10.0.0.0/24"]},
        "cloud": {"aws_account_ids": ["123456789012"]},
    }
    base.update(overrides)
    return ScopePolicy.model_validate(base)


# --- web / api ---------------------------------------------------------------

def test_exact_and_wildcard_web_domains_are_in_scope() -> None:
    p = _policy()
    assert p.evaluate("https://example.com/login").allowed
    assert p.evaluate("https://a.staging.example.com").allowed  # wildcard subdomain
    assert p.evaluate("https://staging.example.com").allowed  # wildcard covers apex


def test_unlisted_domain_is_refused() -> None:
    p = _policy()
    decision = p.evaluate("https://evil.com")
    assert not decision.allowed
    assert "not in web/api/network scope" in decision.reason


def test_lookalike_domain_is_not_matched_by_wildcard() -> None:
    p = _policy()
    assert not p.evaluate("https://notexample.com").allowed


def test_api_base_url_prefix_match() -> None:
    p = _policy()
    assert p.evaluate("https://api.example.com/v1/users/1").allowed
    # Same host but outside the authorized base path, and host not in web.domains.
    assert not p.evaluate("https://api.example.com/v2/admin").allowed


def test_api_base_url_requires_path_boundary() -> None:
    # Regression (surfaced by dogfooding the baseline scan): a plain startswith let
    # the authorized prefix ".../v1" also match ".../v1extra". The match must break
    # on a path/query/fragment boundary.
    p = _policy()  # api.base_urls = ["https://api.example.com/v1"]
    assert p.evaluate("https://api.example.com/v1").allowed
    assert p.evaluate("https://api.example.com/v1/users/1").allowed
    assert p.evaluate("https://api.example.com/v1?q=1").allowed
    assert not p.evaluate("https://api.example.com/v1extra/admin").allowed


def test_api_base_url_without_path_rejects_lookalike_host() -> None:
    # A base URL with no path must not match a look-alike host by string prefix.
    p = _policy(api={"base_urls": ["https://api.example.com"]}, web={"domains": []})
    assert p.evaluate("https://api.example.com/anything").allowed
    assert not p.evaluate("https://api.example.com.evil.com/x").allowed


# --- network -----------------------------------------------------------------

def test_ip_in_cidr_and_exact_host() -> None:
    p = _policy()
    assert p.evaluate("10.0.0.42").allowed  # inside 10.0.0.0/24
    assert p.evaluate("10.0.0.5").allowed  # exact host
    assert not p.evaluate("10.0.1.1").allowed  # outside the CIDR


def test_port_allowlist_is_enforced_when_set() -> None:
    p = _policy(network={"cidrs": ["10.0.0.0/24"], "ports": [80, 443]})
    assert p.evaluate("http://10.0.0.7:443").allowed
    denied = p.evaluate("http://10.0.0.7:22")
    assert not denied.allowed
    assert "port 22" in denied.reason


# --- cloud -------------------------------------------------------------------

def test_cloud_account_forms_all_resolve() -> None:
    p = _policy()
    assert p.evaluate("aws:123456789012").allowed
    assert p.evaluate("123456789012").allowed  # bare 12-digit id
    assert p.evaluate("arn:aws:s3:::bucket").kind == "cloud"  # classified as cloud
    assert p.evaluate("arn:aws:iam::123456789012:role/admin").allowed  # account id from ARN
    assert not p.evaluate("aws:999999999999").allowed


# --- intrusive gate ----------------------------------------------------------

def test_intrusive_action_refused_unless_allowed_even_when_in_scope() -> None:
    p = _policy()
    in_scope = "https://example.com"
    assert p.evaluate(in_scope).allowed
    denied = p.evaluate(in_scope, intrusive=True)
    assert not denied.allowed
    assert "allow_intrusive" in denied.reason

    p_intrusive = _policy(allow_intrusive=True)
    assert p_intrusive.evaluate(in_scope, intrusive=True).allowed


def test_empty_target_is_denied() -> None:
    assert not _policy().evaluate("").allowed


# --- loader ------------------------------------------------------------------

def test_missing_scope_file_returns_none(tmp_path: Path) -> None:
    assert load_scope_policy(search_from=tmp_path) is None


def test_explicit_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(ScopeConfigError):
        load_scope_policy(tmp_path / "nope.yaml")


def test_loads_valid_yaml(tmp_path: Path) -> None:
    (tmp_path / "scope.yaml").write_text(
        "name: t\nallow_intrusive: true\nweb:\n  domains: [example.com]\n",
        encoding="utf-8",
    )
    policy = load_scope_policy(search_from=tmp_path)
    assert policy is not None
    assert policy.allow_intrusive is True
    assert policy.evaluate("https://example.com").allowed


def test_malformed_scope_fails_closed(tmp_path: Path) -> None:
    # A present-but-wrong authorization document must raise, never authorize.
    (tmp_path / "scope.yaml").write_text("web:\n  domains: not-a-list\n", encoding="utf-8")
    with pytest.raises(ScopeConfigError):
        load_scope_policy(search_from=tmp_path)


def test_unknown_top_level_key_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "scope.yaml").write_text("allow_everything: true\n", encoding="utf-8")
    with pytest.raises(ScopeConfigError):
        load_scope_policy(search_from=tmp_path)


def test_bad_aws_account_id_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "scope.yaml").write_text(
        "cloud:\n  aws_account_ids: ['12345']\n", encoding="utf-8"
    )
    with pytest.raises(ScopeConfigError):
        load_scope_policy(search_from=tmp_path)


def test_shipped_template_is_valid() -> None:
    # The repo-root scope.yaml template must always parse and validate.
    repo_root = Path(__file__).resolve().parents[1]
    policy = load_scope_policy(repo_root / "scope.yaml")
    assert policy is not None
    assert policy.allow_intrusive is False
