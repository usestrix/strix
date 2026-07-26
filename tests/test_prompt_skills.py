"""Tests for skill resolution in strix.agents.prompt."""

from __future__ import annotations

from strix.agents.prompt import _resolve_skills


def test_whitebox_pulls_in_source_aware_skills() -> None:
    skills = _resolve_skills(requested=[], is_root=True, scan_mode="deep", is_whitebox=True)

    assert "coordination/source_aware_whitebox" in skills
    assert "custom/source_aware_sast" in skills


def test_blackbox_omits_source_aware_skills() -> None:
    skills = _resolve_skills(requested=[], is_root=True, scan_mode="deep", is_whitebox=False)

    assert "coordination/source_aware_whitebox" not in skills
    assert "custom/source_aware_sast" not in skills


def test_resolve_skills_preserves_request_order_and_dedupes() -> None:
    skills = _resolve_skills(
        requested=["vulnerabilities/xss", "custom/source_aware_sast"],
        is_root=False,
        scan_mode="quick",
        is_whitebox=True,
    )

    assert skills[0] == "vulnerabilities/xss"
    assert skills.count("custom/source_aware_sast") == 1
    assert "scan_modes/quick" in skills
    assert "coordination/root_agent" not in skills
