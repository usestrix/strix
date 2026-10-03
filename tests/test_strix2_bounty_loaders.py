"""Tests for the bug-bounty program loaders (fromfile + HackerOne/Bugcrowd parsers)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.bounty import compile_to_scope
from strix.bounty.loaders import (
    BountyLoadError,
    apply_roe_overrides,
    bugcrowd,
    hackerone,
    load_program,
    load_program_file,
)


_FIXTURES = Path(__file__).parent / "fixtures" / "bounty"


# --- HackerOne parser --------------------------------------------------------


def test_parse_hackerone_fixture() -> None:
    payload = json.loads((_FIXTURES / "hackerone_acme.json").read_text(encoding="utf-8"))
    program = hackerone.parse_program(payload)

    assert program.platform == "hackerone"
    assert program.handle == "acme"
    identifiers = {a.identifier for a in program.in_scope}
    assert "*.acme.com" in identifiers
    assert "https://api.acme.com/v2" in identifiers
    assert "198.51.100.0/24" in identifiers
    assert "com.acme.app" in identifiers  # android, kept in scope but unmappable
    # The ineligible wildcard is routed to out-of-scope.
    assert [a.identifier for a in program.out_of_scope] == ["blog.acme.com"]
    # Free-text policy is preserved for the operator to turn into real ROE.
    assert program.roe.notes and "rate limits" in program.roe.notes


def test_hackerone_program_compiles_and_enforces() -> None:
    payload = json.loads((_FIXTURES / "hackerone_acme.json").read_text(encoding="utf-8"))
    compiled = compile_to_scope(hackerone.parse_program(payload))
    assert "com.acme.app" in compiled.unmapped
    p = compiled.policy
    assert p.evaluate("https://shop.acme.com").allowed
    assert not p.evaluate("https://blog.acme.com").allowed


def test_parse_hackerone_without_handle_raises() -> None:
    with pytest.raises(BountyLoadError):
        hackerone.parse_program({"data": {"attributes": {}}})


def test_parse_hackerone_bare_object_shape() -> None:
    # The live /hackers/programs/{handle} endpoint returns the program object at the
    # TOP LEVEL (no {"data": ...} wrapper). Verified against the real API 2026-10-03.
    payload = json.loads((_FIXTURES / "hackerone_program_bare.json").read_text(encoding="utf-8"))
    program = hackerone.parse_program(payload)
    assert program.handle == "acme"
    assert [a.identifier for a in program.in_scope] == ["*.acme.com"]
    assert [a.identifier for a in program.out_of_scope] == ["excluded.acme.com"]
    p = compile_to_scope(program).policy
    assert p.evaluate("https://x.acme.com").allowed
    assert not p.evaluate("https://excluded.acme.com").allowed


# --- Bugcrowd parser ---------------------------------------------------------


def test_parse_bugcrowd_fixture() -> None:
    payload = json.loads((_FIXTURES / "bugcrowd_acme.json").read_text(encoding="utf-8"))
    program = bugcrowd.parse_program(payload)
    assert program.platform == "bugcrowd"
    assert program.handle == "acme-bb"
    wildcard = next(a for a in program.in_scope if a.identifier == "*.acme.com")
    assert wildcard.asset_type == "wildcard"  # website + star -> wildcard
    assert [a.identifier for a in program.out_of_scope] == ["blog.acme.com"]


def test_bugcrowd_parses_jsonapi_data_shape() -> None:
    payload = {
        "code": "acme-bb",
        "data": [
            {
                "type": "target",
                "attributes": {"name": "api.acme.io", "category": "api", "in_scope": True},
            },
            {
                "type": "target",
                "attributes": {"name": "old.acme.io", "category": "website", "in_scope": False},
            },
        ],
    }
    program = bugcrowd.parse_program(payload)
    assert [a.identifier for a in program.in_scope] == ["api.acme.io"]
    assert [a.identifier for a in program.out_of_scope] == ["old.acme.io"]


# --- fromfile + dispatcher ---------------------------------------------------


def test_load_program_file_yaml_with_full_roe() -> None:
    program = load_program_file(_FIXTURES / "program_fromfile.yaml")
    assert program.handle == "acme"
    assert program.roe.rate_limit_rps == 5
    assert program.roe.automated_testing_allowed is True
    assert "Self-XSS" in program.roe.ineligible_vuln_types
    # It compiles into an enforceable policy with the carve-outs as exclusions.
    p = compile_to_scope(program).policy
    assert p.evaluate("https://api.acme.com/v2/x").allowed
    assert not p.evaluate("https://acme.com/corporate/page").allowed


def test_load_program_dispatches_file_path_even_on_windows() -> None:
    # A path (including a Windows drive-letter path) must route to the file loader,
    # not be mistaken for a platform:handle spec.
    program = load_program(str(_FIXTURES / "program_fromfile.yaml"))
    assert program.platform == "hackerone"
    assert program.handle == "acme"


def test_load_program_platform_spec_requires_token() -> None:
    with pytest.raises(BountyLoadError, match="HackerOne"):
        load_program("hackerone:acme")
    with pytest.raises(BountyLoadError, match="Bugcrowd"):
        load_program("bc:acme-bb")


def test_apply_roe_overrides(tmp_path: Path) -> None:
    payload = json.loads((_FIXTURES / "hackerone_acme.json").read_text(encoding="utf-8"))
    program = hackerone.parse_program(payload)
    assert program.roe.automated_testing_allowed is None  # unstated from H1

    roe_file = tmp_path / "roe.yaml"
    roe_file.write_text(
        "automated_testing_allowed: false\nrate_limit_rps: 2\n", encoding="utf-8"
    )
    tightened = apply_roe_overrides(program, roe_file)
    assert tightened.roe.automated_testing_allowed is False
    assert tightened.roe.rate_limit_rps == 2
    # Original is untouched (copy semantics).
    assert program.roe.automated_testing_allowed is None


def test_bad_roe_override_type_raises(tmp_path: Path) -> None:
    program = load_program_file(_FIXTURES / "program_fromfile.yaml")
    roe_file = tmp_path / "roe.yaml"
    roe_file.write_text("rate_limit_rps: not-a-number\n", encoding="utf-8")
    with pytest.raises(BountyLoadError):
        apply_roe_overrides(program, roe_file)
