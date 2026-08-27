"""Tests for pure input builders in strix.core.inputs."""

from __future__ import annotations

from itertools import pairwise
from typing import Any

import litellm
import pytest

from strix.agents.prompt import render_system_prompt
from strix.core.inputs import (
    build_root_task,
    build_scan_targets,
    build_scope_context,
    build_scope_target_labels,
    child_initial_input,
    make_model_settings,
)
from strix.interface.utils import build_target_summary_text


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


def test_max_reasoning_effort_sent_as_raw_body_field() -> None:
    # "max" is absent from the OpenAI SDK's Reasoning enum, and LiteLLM's DeepSeek
    # mapping collapses every effort to thinking-enabled, so it has to ride along
    # as a raw body field to reach the provider.
    settings = make_model_settings(
        "max", model_name="deepseek/deepseek-v4-flash", request_timeout=30
    )
    assert settings.reasoning is None
    assert settings.extra_args == {"timeout": 30, "extra_body": {"reasoning_effort": "max"}}


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


def test_build_root_task_web_target_injected_as_context() -> None:
    """The prompt leads and the configured target remains visible below it."""
    config = {
        "targets": [
            {"type": "web_application", "details": {"target_host": "app.example.com"}},
        ],
        "user_instructions": "Focus on auth.",
    }
    task = build_root_task(config)

    assert task.startswith("Focus on auth.")
    assert "Hosts:" in task
    assert "app.example.com" in task
    assert "configured targets and supporting material" in task
    assert "Special instructions:" not in task
    assert "SYSTEM-VERIFIED" not in task


def test_build_root_task_workspace_mount_is_not_a_target() -> None:
    """A target-less run gets a working directory, not an assessment scope."""
    config = {
        "targets": [],
        "user_instructions": "Find IDOR in the checkout flow.",
        "workspace_mount": "/Users/me/code/api",
        "workspace_subdir": "api",
    }
    task = build_root_task(config)

    assert "Working Directory:" in task
    assert "/workspace/api" in task
    assert "No scan target was set" in task
    assert task.startswith("Find IDOR in the checkout flow.")
    # It must not be presented as an asset to test.
    for label in ("Local Codebases:", "Repositories:", "Hosts:", "IP Addresses:"):
        assert label not in task


def test_build_scope_context_authorizes_nothing_without_targets() -> None:
    """A mounted workspace grants no authorized scope."""
    scope = build_scope_context(
        {"targets": [], "workspace_mount": "/Users/me/code/api", "workspace_subdir": "api"}
    )

    assert scope["authorized_targets"] == []
    assert scope["user_instruction_hosts_expand_scope"] is True
    assert build_target_summary_text([]).plain == "Target  task-defined scope"


def test_scope_prompt_authorizes_flag_and_instruction_hosts_with_subdomains() -> None:
    config: dict[str, Any] = {
        "targets": [
            {
                "type": "web_application",
                "details": {"target_host": "app.example.com"},
                "original": "app.example.com",
            }
        ],
        "user_instructions": (
            "Test https://app.example.com/search?q=test and "
            "https://app.example.com/blog/. Also test https://api.example.net/v1."
        ),
    }
    context = build_scope_context(config)

    prompt = render_system_prompt(scan_mode="quick", is_root=True, system_prompt_context=context)
    task = build_root_task(config)

    assert "SYSTEM-VERIFIED SCOPE" in prompt
    assert context["authorized_targets"] == [
        {"type": "web_host", "value": "app.example.com", "workspace_path": ""}
    ]
    assert "host: app.example.com (includes app.example.com and *.app.example.com)" in prompt
    assert prompt.count("host: app.example.com") == 1
    assert "https://app.example.com/search?q=test" not in prompt
    assert "https://app.example.com/search?q=test" in task
    assert "https://app.example.com/blog/" in task
    assert "https://api.example.net/v1" in task
    assert "Every network host explicitly named in the user's root scan task" in prompt
    assert "exact hostname and all of its descendant subdomains" in prompt
    assert "scheme, port, path, query, or fragment" in prompt
    assert "not `example.com`, sibling hosts such as `api.example.com`" in prompt

    assert build_scope_target_labels(config["targets"]) == [
        "host: app.example.com (includes *.app.example.com)"
    ]
    assert build_target_summary_text(config["targets"]).plain == (
        "Target  host: app.example.com (includes *.app.example.com)"
    )


def test_scope_prompt_authorizes_subdomains_for_each_configured_host() -> None:
    targets = [
        {
            "type": "web_application",
            "details": {"target_host": "fiuu.com"},
            "original": "fiuu.com",
        },
        {
            "type": "web_application",
            "details": {"target_host": "api.fiuu.com"},
            "original": "api.fiuu.com",
        },
    ]
    context = build_scope_context({"targets": targets})

    prompt = render_system_prompt(scan_mode="quick", is_root=True, system_prompt_context=context)

    assert context["authorized_targets"] == [
        {"type": "web_host", "value": "fiuu.com", "workspace_path": ""},
        {"type": "web_host", "value": "api.fiuu.com", "workspace_path": ""},
    ]
    assert "host: fiuu.com (includes fiuu.com and *.fiuu.com)" in prompt
    assert "host: api.fiuu.com (includes api.fiuu.com and *.api.fiuu.com)" in prompt


def test_scope_prompt_keeps_web_ip_targets_exact() -> None:
    context = build_scope_context(
        {
            "targets": [
                {
                    "type": "ip_address",
                    "details": {"target_ip": "192.0.2.10"},
                }
            ]
        }
    )

    prompt = render_system_prompt(scan_mode="quick", is_root=True, system_prompt_context=context)

    assert context["authorized_targets"] == [
        {"type": "ip_address", "value": "192.0.2.10", "workspace_path": ""}
    ]
    assert "ip_address: 192.0.2.10 (exact address)" in prompt
    assert "https://192.0.2.10:8443/admin" not in prompt


def test_scope_prompt_does_not_make_repository_origin_a_live_target() -> None:
    context = build_scope_context(
        {
            "targets": [
                {
                    "type": "repository",
                    "details": {"target_repo": "https://github.com/acme/app.git"},
                }
            ]
        }
    )

    prompt = render_system_prompt(scan_mode="quick", is_root=True, system_prompt_context=context)

    assert "repository: https://github.com/acme/app.git" in prompt
    assert "Repository hosting origins named only by configured repository targets" in prompt
    assert "are not live web targets" in prompt


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


def test_make_model_settings_disables_parallel_tool_calls_by_default() -> None:
    assert make_model_settings("none", model_name="gpt-4o").parallel_tool_calls is False


def test_make_model_settings_omits_parallel_tool_calls_without_tools() -> None:
    settings = make_model_settings("none", model_name="gpt-4o", has_tools=False)

    assert settings.parallel_tool_calls is None


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


def test_scan_targets_prefer_the_workspace_checkout_over_the_remote_url() -> None:
    config = {
        "targets": [
            {
                "type": "repository",
                "details": {
                    "target_repo": "https://github.com/acme/billing",
                    "workspace_subdir": "billing",
                },
            },
            {"type": "web_application", "details": {"target_host": "app.example.com"}},
        ]
    }

    assert build_scan_targets(config) == ["/workspace/billing", "app.example.com"]


def test_scan_targets_drop_empty_and_duplicate_entries() -> None:
    config = {
        "targets": [
            {"type": "web_application", "details": {"target_host": "app.example.com"}},
            {"type": "web_application", "details": {"target_host": "app.example.com"}},
            {"type": "ip_address", "details": {}},
        ]
    }

    assert build_scan_targets(config) == ["app.example.com"]


def test_openrouter_attribution_rides_on_the_request_headers() -> None:
    # litellm.headers is ignored once a request carries any header of its own,
    # so the attribution must be part of the per-request headers.
    headers = make_model_settings(
        None, model_name="openrouter/anthropic/claude-sonnet-4-5"
    ).extra_headers
    assert headers == {
        "HTTP-Referer": "https://strix.ai",
        "X-Title": "Strix",
        "X-OpenRouter-Categories": "cli-agent",
    }


def test_openrouter_attribution_absent_for_other_providers() -> None:
    assert make_model_settings(None, model_name="anthropic/claude-sonnet-4-5").extra_headers is None


def test_user_headers_override_openrouter_attribution() -> None:
    headers = make_model_settings(
        None,
        model_name="openrouter/anthropic/claude-sonnet-4-5",
        extra_headers={"X-Title": "Custom", "X-Tenant": "acme"},
    ).extra_headers
    assert headers is not None
    assert headers["X-Title"] == "Custom"
    assert headers["X-Tenant"] == "acme"
    assert headers["HTTP-Referer"] == "https://strix.ai"
