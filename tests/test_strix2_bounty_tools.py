"""Tests for the bug-bounty agent tools, skill discovery, and tool registration."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.bounty import (
    BountyProgram,
    RulesOfEngagement,
    ScopeAsset,
    compile_to_scope,
    evaluate_roe,
)
from strix.bounty.dedupe import KnownReport, reset_known_reports
from strix.bounty.runtime import BountyContext, set_bounty_context
from strix.skills import get_available_skills, load_skills, register_skill_dir
from strix.strix2_ext import _STRIX2_TOOLS
from strix.tools.bounty.tools import (
    _duplicate_payload,
    _status_payload,
    bounty_scope_status,
    check_duplicate,
)
from strix.utils.resource_paths import get_strix_resource_path


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _reset_bounty_globals() -> Iterator[None]:
    yield
    set_bounty_context(None)
    reset_known_reports(None)


def _context() -> BountyContext:
    program = BountyProgram(
        platform="hackerone",
        handle="acme",
        name="Acme",
        in_scope=[
            ScopeAsset(identifier="*.acme.com", asset_type="wildcard"),
            ScopeAsset(identifier="com.acme.app", asset_type="android"),
        ],
        out_of_scope=[ScopeAsset(identifier="blog.acme.com", asset_type="domain")],
        roe=RulesOfEngagement(automated_testing_allowed=True, rate_limit_rps=5),
    )
    return BountyContext(
        program=program,
        gate=evaluate_roe(program),
        compiled=compile_to_scope(program),
    )


def test_status_payload_without_context() -> None:
    set_bounty_context(None)
    payload = _status_payload()
    assert payload["bounty_active"] is False


def test_status_payload_with_context() -> None:
    set_bounty_context(_context())
    reset_known_reports([KnownReport(title="old SSRF")])
    payload = _status_payload()
    assert payload["bounty_active"] is True
    assert payload["handle"] == "acme"
    assert payload["scope"]["web_domains"] == ["*.acme.com"]
    assert payload["scope"]["exclusions"]["hosts"] == ["blog.acme.com"]
    assert payload["unmapped_in_scope_assets"] == ["com.acme.app"]
    assert payload["known_report_count"] == 1
    assert any("rate limit" in c for c in payload["rules_of_engagement"]["constraints"])


def test_duplicate_payload_novel_without_store() -> None:
    reset_known_reports(None)
    payload = _duplicate_payload("some finding", "", "")
    assert payload["verdict"] == "novel"
    assert "manually" in payload["note"]


def test_duplicate_payload_with_store() -> None:
    reset_known_reports([KnownReport(title="SQL injection in product search", asset="acme.com")])
    payload = _duplicate_payload("SQLi in product search", "acme.com", "SQL injection")
    assert payload["verdict"] == "likely_duplicate"


def test_bounty_skill_is_discoverable_and_loadable() -> None:
    register_skill_dir(get_strix_resource_path("skills2"))
    available = get_available_skills().get("bounty", [])
    assert "bounty_hunting" in {skill["name"] for skill in available}
    body = load_skills(["bounty/bounty_hunting"])
    assert "check_duplicate" in body["bounty_hunting"]
    assert "bounty_scope_status" in body["bounty_hunting"]


def test_bounty_tools_are_registered_in_ext() -> None:
    assert bounty_scope_status in _STRIX2_TOOLS
    assert check_duplicate in _STRIX2_TOOLS
