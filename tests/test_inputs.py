"""Tests for pure input builders in strix.core.inputs."""

from __future__ import annotations

from itertools import pairwise
from typing import Any

import litellm
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


def _cache_points(model_name: str) -> Any:
    extra = make_model_settings(None, model_name=model_name).extra_args or {}
    return extra.get("cache_control_injection_points")


def test_make_model_settings_enables_prompt_cache_for_bedrock_claude() -> None:
    assert _cache_points("bedrock/global.anthropic.claude-opus-4-8") == [
        {"location": "message", "role": "system"},
        {"location": "tool_config"},
        {"location": "message", "index": -1},
    ]


@pytest.mark.parametrize(
    "model_name",
    [
        "anthropic/claude-sonnet-4-5",
        "openrouter/anthropic/claude-3.5-sonnet",
        "vertex_ai/claude-sonnet-4-5",
    ],
)
def test_make_model_settings_enables_prompt_cache_for_non_bedrock_claude(model_name: str) -> None:
    assert _cache_points(model_name) == [
        {"location": "message", "role": "system"},
        {"location": "message", "index": -1},
    ]


def test_tool_config_point_not_leaked_to_non_bedrock_claude() -> None:
    # LiteLLM only consumes tool_config on Bedrock; elsewhere it leaks onto the
    # wire and native Anthropic 400s.
    for model in ("anthropic/claude-sonnet-4-5", "openrouter/anthropic/claude-3.5-sonnet"):
        points = _cache_points(model) or []
        assert all(p.get("location") != "tool_config" for p in points)


def test_prompt_cache_can_be_disabled() -> None:
    assert (
        make_model_settings(
            None, model_name="anthropic/claude-sonnet-4-5", prompt_cache=False
        ).extra_args
        is None
    )


@pytest.mark.parametrize("model_name", ["gpt-5", "vertex_ai/gemini-2.5-pro", "openai/o3"])
def test_make_model_settings_no_prompt_cache_for_non_claude(model_name: str) -> None:
    assert make_model_settings(None, model_name=model_name).extra_args is None


def test_no_prompt_cache_for_unmapped_bedrock_claude_model(monkeypatch: Any) -> None:
    # A Bedrock Claude model LiteLLM hasn't mapped must run uncached, not crash.
    unmapped = "bedrock/global.anthropic.claude-brand-new-9"
    monkeypatch.setattr(litellm, "model_cost", {}, raising=False)
    if getattr(getattr(litellm, "utils", None), "supports_prompt_caching", None):
        monkeypatch.setattr(litellm.utils, "supports_prompt_caching", lambda *_a, **_k: False)

    assert make_model_settings(None, model_name=unmapped).extra_args is None


def test_prompt_cache_kept_for_non_bedrock_claude_even_if_unmapped(monkeypatch: Any) -> None:
    # Only Bedrock hard-rejects unknown cache fields, so only Bedrock is guarded.
    monkeypatch.setattr(litellm, "model_cost", {}, raising=False)
    if getattr(getattr(litellm, "utils", None), "supports_prompt_caching", None):
        monkeypatch.setattr(litellm.utils, "supports_prompt_caching", lambda *_a, **_k: False)

    for model in ("anthropic/claude-brand-new-9", "openrouter/anthropic/claude-brand-new"):
        assert _cache_points(model) == [
            {"location": "message", "role": "system"},
            {"location": "message", "index": -1},
        ]


def test_conversation_tail_breakpoint_moves_with_appended_transcript() -> None:
    # LiteLLM must place the index=-1 cache_control on the last message however
    # long the transcript grows.
    hook_mod = pytest.importorskip("litellm.integrations.anthropic_cache_control_hook")
    apply = hook_mod.AnthropicCacheControlHook._apply_message_injections
    points = _cache_points("bedrock/global.anthropic.claude-opus-4-8")
    msg_points = [p for p in points if p.get("location") == "message"]

    def last_msg_cache_control(n_turns: int) -> Any:
        messages: list[dict[str, Any]] = [{"role": "system", "content": "stable prompt"}]
        for i in range(n_turns):
            messages.append({"role": "assistant", "content": f"turn {i} action"})
            messages.append({"role": "user", "content": f"turn {i} tool result"})
        processed = apply(msg_points, messages, 4)
        last = processed[-1]
        content = last.get("content")
        if isinstance(content, list):
            return content[-1].get("cache_control")
        return last.get("cache_control")

    assert last_msg_cache_control(2) == {"type": "ephemeral"}
    assert last_msg_cache_control(20) == {"type": "ephemeral"}


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


def test_make_model_settings_sets_extra_headers() -> None:
    settings = make_model_settings(
        "none",
        model_name="openai/some-model",
        extra_headers={"X-Feature-Key": "svc", "X-Tenant": "acme"},
    )

    assert settings.extra_headers == {"X-Feature-Key": "svc", "X-Tenant": "acme"}


def test_make_model_settings_omits_extra_headers_when_unset() -> None:
    assert make_model_settings("none", model_name="gpt-4o").extra_headers is None


def test_make_model_settings_extra_headers_survive_reasoning_resolve() -> None:
    settings = make_model_settings(
        "high",
        model_name="openai/o3",
        extra_headers={"X-Feature-Key": "svc"},
    )

    assert settings.extra_headers == {"X-Feature-Key": "svc"}


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
