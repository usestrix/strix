"""Action-safety guidance reaches the agent only when a safety mode is active."""

from __future__ import annotations

import pytest

from strix.agents.prompt import render_system_prompt


# Phrased as prohibitions, so they misdescribe the tools an `off`-mode agent actually has.
_SAFETY_ONLY_PHRASES = [
    "ACTION SAFETY POLICY",
    "browser session is assigned for you; do not override",
    "blocked as stale",
    "must be split into a creation call",
]


@pytest.mark.parametrize("phrase", _SAFETY_ONLY_PHRASES)
@pytest.mark.parametrize("context", [None, {}, {"safety_mode": "off"}])
def test_safety_guidance_is_absent_without_a_safety_mode(
    phrase: str,
    context: dict[str, str] | None,
) -> None:
    assert phrase not in render_system_prompt(system_prompt_context=context)


@pytest.mark.parametrize("phrase", _SAFETY_ONLY_PHRASES)
def test_safety_guidance_is_present_in_guarded_mode(phrase: str) -> None:
    assert phrase in render_system_prompt(system_prompt_context={"safety_mode": "guarded"})


def test_browser_skill_carries_no_safety_prohibitions() -> None:
    """The browser skill is always loaded, so mode-specific rules do not belong in it."""
    prompt = render_system_prompt(skills=["agent_browser"], system_prompt_context={})

    assert "agent-browser snapshot" in prompt
    for phrase in _SAFETY_ONLY_PHRASES:
        assert phrase not in prompt


def test_guarded_interactive_prompt_explains_human_deferral() -> None:
    prompt = render_system_prompt(
        interactive=True,
        system_prompt_context={
            "safety_mode": "guarded",
            "human_approval_available": True,
        },
    )

    assert "user approves or denies that action" in prompt
    assert "only the guarded action-safety reviewer may pause" in prompt


def test_guarded_autonomous_prompt_has_no_human_channel() -> None:
    prompt = render_system_prompt(system_prompt_context={"safety_mode": "guarded"})

    assert "No human approval channel exists" in prompt
    assert "NEVER wait for approval or authorization" in prompt


def test_interactive_without_approval_callback_still_fails_closed() -> None:
    prompt = render_system_prompt(
        interactive=True,
        system_prompt_context={"safety_mode": "guarded"},
    )

    assert "No human approval channel exists" in prompt
    assert "user approves or denies that action" not in prompt


def test_scope_allows_passive_external_research_without_expanding_targets() -> None:
    prompt = render_system_prompt(
        system_prompt_context={
            "authorized_targets": [{"type": "web", "value": "https://example.test"}],
            "scope_source": "scan",
            "authorization_source": "user",
        }
    )

    assert "certificate transparency services such as crt.sh" in prompt
    assert "does not make that service a testing target" in prompt
    assert "authorized domain includes its subdomains" in prompt
    assert "NEVER actively scan, fuzz, authenticate to, exploit, or mutate" in prompt
