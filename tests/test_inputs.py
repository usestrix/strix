"""Tests for pure input builders in strix.core.inputs."""

from __future__ import annotations

from itertools import pairwise
from typing import Any

import pytest

from strix.core.inputs import build_root_task, child_initial_input, make_model_settings


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

@pytest.mark.parametrize(
    "model_name",
    [
        "bedrock/anthropic.claude-sonnet-4-5-20250929-v1:0",
        "bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "litellm/bedrock/anthropic.claude-sonnet-4-5-20250929-v1:0",
        "any-llm/bedrock/converse/us.anthropic.claude-opus-4-5-v1:0",
    ],
)
def test_make_model_settings_omits_parallel_flag_for_bedrock_claude(model_name: str) -> None:
    # Regression for #644: forcing parallel_tool_calls=False makes LiteLLM emit a
    # tool_choice without a `type`, which Bedrock rejects and the scan never starts.
    settings = make_model_settings(None, model_name=model_name)

    assert settings.parallel_tool_calls is None


@pytest.mark.parametrize(
    "model_name",
    [
        "openai/gpt-5.4",
        "anthropic/claude-sonnet-4-6",  # direct Anthropic API, not Bedrock
        "bedrock/meta.llama3-1-70b-instruct-v1:0",  # non-Claude Bedrock model
        "vertex_ai/gemini-3-pro-preview",
    ],
)
def test_make_model_settings_forces_single_tool_call_elsewhere(model_name: str) -> None:
    settings = make_model_settings(None, model_name=model_name)

    assert settings.parallel_tool_calls is False
