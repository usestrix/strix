"""Tests for Strix 2 runtime scope enforcement (extraction, checks, loading)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.scope.enforcement import (
    enforce_arguments,
    enforce_shell_command,
    enforce_target,
    extract_targets,
    get_active_policy,
    load_active_policy,
    set_active_policy,
)
from strix.scope.schema import ScopePolicy


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

_ALLOW_INTRUSIVE_ENV = "STRIX_ALLOW_INTRUSIVE"
_SCOPE_CONFIG_ENV = "STRIX_SCOPE_CONFIG"


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    saved = get_active_policy()
    monkeypatch.delenv(_ALLOW_INTRUSIVE_ENV, raising=False)
    monkeypatch.delenv(_SCOPE_CONFIG_ENV, raising=False)
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


# --- extraction --------------------------------------------------------------

def test_extract_high_confidence_targets() -> None:
    args = {
        "url": "https://example.com/x",
        "note": "reach 10.0.0.5 and arn:aws:s3:::b for acct 123456789012",
        "nested": {"list": ["http://10.0.0.9:8080/p"]},
    }
    found = extract_targets(args)
    assert "https://example.com/x" in found
    assert "10.0.0.5" in found
    assert "arn:aws:s3:::b" in found
    assert "123456789012" in found
    assert "http://10.0.0.9:8080/p" in found


def test_extraction_ignores_ambiguous_hostnames() -> None:
    # A bare hostname is not high-confidence (would false-positive); skipped.
    assert extract_targets({"host": "some.internal.thing"}) == []


# --- enforce_target ----------------------------------------------------------

def test_no_policy_means_no_enforcement() -> None:
    assert enforce_target("https://evil.com") is None  # inactive → allow


def test_out_of_scope_target_is_denied() -> None:
    set_active_policy(_policy())
    assert enforce_target("https://example.com") is None  # in scope → allow
    denial = enforce_target("https://evil.com")
    assert denial is not None
    assert not denial.allowed


def test_intrusive_gate_denies_until_allowed() -> None:
    set_active_policy(_policy())
    denied = enforce_target("https://example.com", intrusive=True)
    assert denied is not None and "allow_intrusive" in denied.reason
    set_active_policy(_policy(allow_intrusive=True))
    assert enforce_target("https://example.com", intrusive=True) is None


# --- enforce_arguments -------------------------------------------------------

def test_enforce_arguments_flags_out_of_scope_ip() -> None:
    set_active_policy(_policy())
    assert enforce_arguments({"target": "10.0.0.5"}) is None  # in CIDR
    denial = enforce_arguments({"target": "8.8.8.8"})
    assert denial is not None and not denial.allowed


def test_enforce_arguments_allows_when_no_target_present() -> None:
    set_active_policy(_policy())
    assert enforce_arguments({"query": "SELECT 1"}) is None


def test_enforce_arguments_noop_without_policy() -> None:
    assert enforce_arguments({"target": "8.8.8.8"}) is None


# --- enforce_shell_command (exec boundary) -----------------------------------

def test_shell_command_noop_without_policy() -> None:
    assert enforce_shell_command("nmap 8.8.8.8") is None  # inactive → allow


def test_shell_command_ignores_non_network_commands() -> None:
    set_active_policy(_policy())
    # 8.8.8.8 appears, but grep is not a network tool → not scope-checked here.
    assert enforce_shell_command("grep 8.8.8.8 /workspace/out.txt") is None


def test_shell_command_allows_in_scope_network_target() -> None:
    set_active_policy(_policy())
    assert enforce_shell_command("nmap -sV 10.0.0.5") is None  # in 10.0.0.0/24
    assert enforce_shell_command("curl https://example.com/x") is None


def test_shell_command_denies_out_of_scope_target() -> None:
    set_active_policy(_policy())
    denied = enforce_shell_command("nmap -sV 8.8.8.8")
    assert denied is not None and not denied.allowed
    assert enforce_shell_command("curl https://evil.com") is not None


def test_shell_command_checks_chained_and_piped_commands() -> None:
    set_active_policy(_policy())
    assert enforce_shell_command("naabu -host 8.8.8.8 | tee out.txt") is not None
    assert enforce_shell_command("cd /tmp && nuclei -u https://evil.com") is not None


def test_shell_command_allows_when_no_target_extracted() -> None:
    set_active_policy(_policy())
    assert enforce_shell_command("nmap --version") is None  # no host to check


# --- load_active_policy ------------------------------------------------------

def _write_scope(tmp_path: Path) -> Path:
    (tmp_path / "scope.yaml").write_text(
        "name: t\nweb:\n  domains: [example.com]\n", encoding="utf-8"
    )
    return tmp_path


def test_load_active_policy_from_dir(tmp_path: Path) -> None:
    _write_scope(tmp_path)
    policy = load_active_policy(search_from=str(tmp_path))
    assert policy is not None
    assert get_active_policy() is policy
    assert policy.allow_intrusive is False


def test_load_active_policy_absent_is_inactive(tmp_path: Path) -> None:
    assert load_active_policy(search_from=str(tmp_path)) is None
    assert get_active_policy() is None


def test_allow_intrusive_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_scope(tmp_path)
    monkeypatch.setenv(_ALLOW_INTRUSIVE_ENV, "1")
    policy = load_active_policy(search_from=str(tmp_path))
    assert policy is not None and policy.allow_intrusive is True


def test_allow_intrusive_arg_override(tmp_path: Path) -> None:
    _write_scope(tmp_path)
    policy = load_active_policy(search_from=str(tmp_path), allow_intrusive=True)
    assert policy is not None and policy.allow_intrusive is True
