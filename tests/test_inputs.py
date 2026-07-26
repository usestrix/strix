"""Tests for pure input builders in strix.core.inputs."""

from __future__ import annotations

from itertools import pairwise
from typing import Any

import pytest

from strix.core.inputs import (
    build_root_task,
    child_initial_input,
    make_model_settings,
    resolve_max_tokens,
)


def _child_kwargs(parent_history: list[Any]) -> dict[str, Any]:
    return {
        "name": "scout",
        "child_id": "agent-2",
        "parent_id": "agent-1",
        "task": "Audit the login flow.",
        "parent_history": parent_history,
    }


def test_child_initial_input_single_message_without_history() -> None:
    result = child_initial_input(**_child_kwargs([]))

    assert len(result) == 1
    assert result[0]["role"] == "user"
    content = result[0]["content"]
    assert "agent scout (agent-2)" in content
    assert "Audit the login flow." in content
    assert "Inherited context" not in content


def test_child_initial_input_single_message_with_history() -> None:
    history = [{"role": "assistant", "content": "previous work"}]
    result = child_initial_input(**_child_kwargs(history))

    assert len(result) == 1
    assert result[0]["role"] == "user"
    content = result[0]["content"]
    assert "Inherited context from parent" in content
    assert "previous work" in content
    assert "agent scout (agent-2)" in content
    assert "Audit the login flow." in content


@pytest.mark.parametrize(
    "parent_history",
    [[], [{"role": "assistant", "content": "previous work"}]],
)
def test_child_initial_input_no_consecutive_same_role(parent_history: list[Any]) -> None:
    result = child_initial_input(**_child_kwargs(parent_history))

    roles = [msg["role"] for msg in result]
    assert all(prev != nxt for prev, nxt in pairwise(roles))


def test_build_root_task_empty_config() -> None:
    assert build_root_task({}) == ""


def test_build_root_task_repository_target() -> None:
    config = {
        "targets": [
            {
                "type": "repository",
                "details": {
                    "target_repo": "https://example.com/repo.git",
                    "cloned_repo_path": "/workspace/repo",
                    "workspace_subdir": "repo",
                },
            },
        ],
    }
    task = build_root_task(config)

    assert "Repositories:" in task
    assert "/workspace/repo" in task
    assert "https://example.com/repo.git" in task


def test_build_root_task_web_application_with_instructions() -> None:
    config = {
        "targets": [
            {"type": "web_application", "details": {"target_url": "https://app.example.com"}},
        ],
        "user_instructions": "Focus on auth.",
    }
    task = build_root_task(config)

    assert "URLs:" in task
    assert "https://app.example.com" in task
    assert "Special instructions: Focus on auth." in task


def test_build_root_task_diff_scope() -> None:
    config = {
        "targets": [],
        "diff_scope": {
            "active": True,
            "repos": [
                {
                    "workspace_subdir": "repo",
                    "analyzable_files_count": 3,
                    "deleted_files_count": 2,
                },
            ],
        },
    }
    task = build_root_task(config)

    assert "Scope Constraints:" in task
    assert "3 changed file(s)" in task
    assert "2 deleted file(s)" in task


@pytest.mark.parametrize("model_name", ["openai/o3", "gpt-4o"])
def test_make_model_settings_forces_required_tool_choice_for_openai_models(
    model_name: str,
) -> None:
    settings = make_model_settings(
        "none",
        model_name=model_name,
        force_required_tool_choice=True,
    )

    assert settings.tool_choice == "required"


def test_make_model_settings_skips_required_tool_choice_for_non_openai_models() -> None:
    settings = make_model_settings(
        "none",
        model_name="anthropic/claude-3-7-sonnet-latest",
        force_required_tool_choice=True,
    )

    assert settings.tool_choice is None


def test_make_model_settings_forces_required_for_routed_openai_model() -> None:
    settings = make_model_settings(
        None,
        model_name="litellm/openai/gpt-4o",
        force_required_tool_choice=True,
    )

    assert settings.tool_choice == "required"


def test_make_model_settings_forces_required_for_anyllm_routed_openai_model() -> None:
    settings = make_model_settings(
        None,
        model_name="any-llm/openai/gpt-4o",
        force_required_tool_choice=True,
    )

    assert settings.tool_choice == "required"


def test_make_model_settings_sets_request_timeout() -> None:
    settings = make_model_settings(
        "none",
        model_name="gpt-4o",
        request_timeout=300.0,
    )

    assert settings.extra_args is not None
    assert settings.extra_args["timeout"] == 300.0


def test_make_model_settings_omits_timeout_when_unset() -> None:
    settings = make_model_settings("none", model_name="gpt-4o")

    assert settings.extra_args is None


def test_make_model_settings_timeout_survives_reasoning_resolve() -> None:
    # Reasoning is resolved via ModelSettings.resolve(); the timeout in extra_args
    # must not be dropped when a reasoning override is merged in.
    settings = make_model_settings(
        "high",
        model_name="openai/o3",
        request_timeout=120.0,
    )

    assert settings.extra_args is not None
    assert settings.extra_args["timeout"] == 120.0


@pytest.mark.parametrize(
    "model_name",
    [
        "openai/gpt-5.4",
        "gpt-4o",
        "gemini/gemini-1.5-flash",
        "ollama/llama3",
        "bedrock/us.amazon.nova-lite-v1:0",
    ],
)
def test_resolve_max_tokens_non_claude_is_untouched(model_name: str) -> None:
    # No ceiling is imposed on non-Claude models: None stays None (provider
    # default) and an explicit value passes through verbatim.
    assert resolve_max_tokens(model_name, None) is None
    assert resolve_max_tokens(model_name, 16000) == 16000


@pytest.mark.parametrize(
    "model_name",
    [
        "bedrock/global.anthropic.claude-opus-4-8",
        "bedrock/us.anthropic.claude-opus-4-8",
        "bedrock/global.anthropic.claude-sonnet-4-6",
    ],
)
def test_resolve_max_tokens_adaptive_claude_gets_default(model_name: str) -> None:
    # The models the fix targets: unset -> family default, well under their
    # (>=64k) ceiling so the value is the default itself, regardless of the
    # region/provider prefix on the model id.
    assert resolve_max_tokens(model_name, None) == 32000


def test_resolve_max_tokens_clamps_default_to_small_ceiling() -> None:
    # Older Claude tops out below the family default; the returned value must be
    # the model's own ceiling, never the larger default (which would 400).
    result = resolve_max_tokens("bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0", None)
    assert result is not None
    assert result <= 8192


def test_resolve_max_tokens_clamps_explicit_override_to_ceiling() -> None:
    # An over-large explicit value is clamped down to what the model accepts.
    assert resolve_max_tokens("bedrock/global.anthropic.claude-opus-4-8", 500_000) == 128_000


def test_resolve_max_tokens_unknown_claude_without_config_returns_none() -> None:
    # A Claude model absent from litellm's cost map has no known ceiling; rather
    # than guess a value that might exceed the real limit, fall back to None.
    assert resolve_max_tokens("claude-does-not-exist-9", None) is None


def test_resolve_max_tokens_unknown_claude_respects_explicit_config() -> None:
    # If the ceiling is unknown but the user set a value, honor it as-is.
    assert resolve_max_tokens("claude-does-not-exist-9", 12345) == 12345


@pytest.mark.parametrize("bad_value", ["0", "-1", "-4096"])
def test_llm_settings_rejects_nonpositive_max_tokens(
    monkeypatch: pytest.MonkeyPatch, bad_value: str
) -> None:
    # A nonpositive STRIX_MAX_TOKENS would yield empty output or a provider 400;
    # it must fail at settings-load rather than reach a request.
    from pydantic import ValidationError

    from strix.config.settings import LlmSettings

    monkeypatch.setenv("STRIX_MAX_TOKENS", bad_value)
    with pytest.raises(ValidationError):
        LlmSettings()


def test_llm_settings_accepts_positive_max_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    from strix.config.settings import LlmSettings

    monkeypatch.setenv("STRIX_MAX_TOKENS", "4096")
    assert LlmSettings().max_tokens == 4096
