"""Tests for Strix 2 Phase 5: the per-role model router and the no-progress guard."""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.guard import NoProgressDetector
from strix.router import (
    RouterSettings,
    load_router_settings,
    resolve_agent_model,
    role_for_skills,
    select_model,
)


if TYPE_CHECKING:
    import pytest


# --- role classification -----------------------------------------------------

def test_role_for_skills_recon_vs_default() -> None:
    assert role_for_skills(["reconnaissance/asset_discovery"]) == "recon"
    assert role_for_skills(["tooling/subfinder"]) == "recon"
    assert role_for_skills(["network/network_pentest"]) == "default"  # pentest keeps frontier
    assert role_for_skills(["cloud/aws_pentest"]) == "default"
    assert role_for_skills([]) == "default"
    assert role_for_skills(None) == "default"


# --- select_model ------------------------------------------------------------

def test_select_model_disabled_returns_default() -> None:
    off = RouterSettings(enabled=False, recon_model="openai/cheap")
    assert select_model("recon", settings=off, default="main") == "main"


def test_select_model_routes_recon_when_enabled() -> None:
    on = RouterSettings(enabled=True, recon_model="openai/cheap")
    assert select_model("recon", settings=on, default="main") == "openai/cheap"
    assert select_model("default", settings=on, default="main") == "main"


def test_select_model_recon_without_model_falls_back() -> None:
    on = RouterSettings(enabled=True, recon_model=None)
    assert select_model("recon", settings=on, default="main") == "main"


# --- resolve_agent_model -----------------------------------------------------

def test_resolve_root_always_default() -> None:
    on = RouterSettings(enabled=True, recon_model="openai/cheap")
    assert resolve_agent_model(["reconnaissance/x"], is_root=True, settings=on) is None


def test_resolve_recon_child_when_enabled() -> None:
    on = RouterSettings(enabled=True, recon_model="openai/cheap")
    assert resolve_agent_model(["reconnaissance/x"], settings=on) == "openai/cheap"
    assert resolve_agent_model(["cloud/aws_pentest"], settings=on) is None  # keeps default


def test_resolve_disabled_returns_default() -> None:
    off = RouterSettings(enabled=False, recon_model="openai/cheap")
    assert resolve_agent_model(["reconnaissance/x"], settings=off) is None


def test_router_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX2_ROUTER", "1")
    monkeypatch.setenv("STRIX2_RECON_MODEL", "openai/ds/deepseek-chat")
    settings = load_router_settings()
    assert settings.enabled is True
    assert settings.recon_model == "openai/ds/deepseek-chat"


# --- no-progress detector ----------------------------------------------------

def test_repeated_identical_call_flags_stall() -> None:
    d = NoProgressDetector(repeat_threshold=3)
    assert d.record("exec_command", {"command": "nmap x"}) is None
    assert d.record("exec_command", {"command": "nmap x"}) is None
    signal = d.record("exec_command", {"command": "nmap x"})
    assert signal is not None
    assert signal.kind == "repeated_call"
    assert signal.count == 3


def test_different_calls_do_not_flag() -> None:
    d = NoProgressDetector(repeat_threshold=3)
    assert d.record("exec_command", {"command": "a"}) is None
    assert d.record("exec_command", {"command": "b"}) is None
    assert d.record("exec_command", {"command": "c"}) is None


def test_no_coverage_growth_flags_stall() -> None:
    d = NoProgressDetector(repeat_threshold=99, stall_window=3)
    # distinct calls (so repeat never fires), coverage frozen at 5
    assert d.record("t", {"i": 0}, coverage_count=5) is None  # baseline
    assert d.record("t", {"i": 1}, coverage_count=5) is None  # streak 1
    assert d.record("t", {"i": 2}, coverage_count=5) is None  # streak 2
    signal = d.record("t", {"i": 3}, coverage_count=5)  # streak 3
    assert signal is not None
    assert signal.kind == "no_coverage"


def test_coverage_growth_resets_streak() -> None:
    d = NoProgressDetector(repeat_threshold=99, stall_window=2)
    d.record("t", {"i": 0}, coverage_count=1)
    d.record("t", {"i": 1}, coverage_count=1)  # streak 1
    d.record("t", {"i": 2}, coverage_count=2)  # growth → reset
    assert d.record("t", {"i": 3}, coverage_count=2) is None  # streak 1 again, under window


def test_reset_clears_state() -> None:
    d = NoProgressDetector(repeat_threshold=2)
    d.record("t", {"a": 1})
    d.reset()
    assert d.record("t", {"a": 1}) is None  # re-armed
