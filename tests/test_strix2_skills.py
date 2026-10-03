"""Tests for Strix 2's registered skill directory (the domain pentest playbooks)."""

from __future__ import annotations

import pytest

from strix.agents.prompt import render_system_prompt
from strix.skills import (
    get_available_skills,
    load_skills,
    register_skill_dir,
    registered_skill_dirs,
)
from strix.strix2_ext import install_strix2_extensions
from strix.utils.resource_paths import get_strix_resource_path


def _register() -> None:
    register_skill_dir(get_strix_resource_path("skills2"))


@pytest.mark.parametrize(
    ("category", "name", "must_contain"),
    [
        ("cloud", "aws_pentest", "aws_whoami"),
        ("network", "network_pentest", "create_candidate"),
        ("infra", "infra_pentest", "reachable"),
        ("api", "api_pentest", "http_exchange_ids"),
    ],
)
def test_strix2_skill_is_discoverable_and_loadable(
    category: str, name: str, must_contain: str
) -> None:
    _register()
    available = get_available_skills().get(category, [])
    assert name in {skill["name"] for skill in available}
    body = load_skills([f"{category}/{name}"])
    assert name in body
    assert must_contain in body[name]


def test_all_four_playbooks_present() -> None:
    _register()
    available = get_available_skills()
    present = {(cat, s["name"]) for cat, skills in available.items() for s in skills}
    assert {
        ("cloud", "aws_pentest"),
        ("network", "network_pentest"),
        ("infra", "infra_pentest"),
        ("api", "api_pentest"),
    } <= present


def test_install_registers_the_skill_dir() -> None:
    install_strix2_extensions(None)
    assert get_strix_resource_path("skills2") in registered_skill_dirs()


def test_root_prompt_includes_domain_delegation_guidance() -> None:
    _register()
    marker = "Strix 2 domain delegation"
    root = render_system_prompt(is_root=True)
    child = render_system_prompt(is_root=False)
    assert root  # rendered non-empty
    assert marker in root  # loaded for the root agent
    assert marker not in child  # not for child specialists
