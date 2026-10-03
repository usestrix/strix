"""Tests for the Strix 2 MCP wrapper harness (scope gating + result shape)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from strix.mcp_servers.base import ScopeGuard, build_server, error, ok, result
from strix.scope.enforcement import get_active_policy, set_active_policy
from strix.scope.schema import ScopePolicy


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _reset() -> Iterator[None]:
    saved = get_active_policy()
    set_active_policy(None)
    try:
        yield
    finally:
        set_active_policy(saved)


def _policy(**overrides: object) -> ScopePolicy:
    base: dict[str, object] = {
        "web": {"domains": ["example.com"]},
        "network": {"cidrs": ["10.0.0.0/24"]},
        "cloud": {"aws_account_ids": ["123456789012"]},
    }
    base.update(overrides)
    return ScopePolicy.model_validate(base)


# --- result helpers ----------------------------------------------------------

def test_ok_and_error_carry_success_flag() -> None:
    good = json.loads(ok(account="123456789012", buckets=["a"]))
    assert good["success"] is True
    assert good["account"] == "123456789012"
    assert good["buckets"] == ["a"]

    bad = json.loads(error("boom", refused="no_scope"))
    assert bad["success"] is False
    assert bad["error"] == "boom"
    assert bad["refused"] == "no_scope"


def test_result_is_json_and_serializes_unknown_types() -> None:
    # default=str keeps a non-JSON value (e.g. a set) from raising.
    text = result(success=True, weird={1, 2})
    assert json.loads(text)["success"] is True


# --- ScopeGuard.check: fail-closed for the new domains -----------------------

def test_check_fails_closed_without_a_policy() -> None:
    guard = ScopeGuard()  # no policy loaded
    denial = guard.check("aws:123456789012", domain="cloud")
    assert denial is not None
    body = json.loads(denial)
    assert body["success"] is False
    assert body["refused"] == "no_scope"


def test_check_allows_in_scope_target() -> None:
    set_active_policy(_policy())
    guard = ScopeGuard()
    assert guard.check("aws:123456789012", domain="cloud") is None


def test_check_denies_out_of_scope_target() -> None:
    set_active_policy(_policy())
    guard = ScopeGuard()
    denial = guard.check("aws:999999999999", domain="cloud")
    assert denial is not None
    assert json.loads(denial)["refused"] == "out_of_scope"


def test_check_intrusive_gate() -> None:
    set_active_policy(_policy())
    guard = ScopeGuard()
    denied = guard.check("aws:123456789012", domain="cloud", intrusive=True)
    assert denied is not None
    assert "out of scope" in json.loads(denied)["error"].lower()

    set_active_policy(_policy(allow_intrusive=True))
    assert guard.check("aws:123456789012", domain="cloud", intrusive=True) is None


def test_check_reads_policy_live() -> None:
    guard = ScopeGuard()
    assert guard.check("aws:123456789012", domain="cloud") is not None  # no policy yet
    set_active_policy(_policy())
    assert guard.check("aws:123456789012", domain="cloud") is None  # now loaded


# --- build_server ------------------------------------------------------------

def test_build_server_returns_named_fastmcp() -> None:
    server = build_server("strix-test", "an instruction line")
    assert server.name == "strix-test"
