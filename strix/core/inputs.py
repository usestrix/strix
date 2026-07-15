"""Pure input builders for Strix scan runs."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from agents.model_settings import ModelSettings
from openai.types.shared import Reasoning

from strix.config.models import (
    DEFAULT_MODEL_RETRY,
    is_known_openai_bare_model,
    model_supports_reasoning,
    request_timeout_extra_args,
)
from strix.core.sessions import scrub_images_from_items


if TYPE_CHECKING:
    from strix.config.settings import ReasoningEffort


DEFAULT_MAX_TURNS = 500


def _accepts_required_tool_choice(model_name: str | None) -> bool:
    name = (model_name or "").strip().lower()
    for prefix in ("litellm/", "any-llm/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name.startswith("openai/") or is_known_openai_bare_model(name)


def build_root_task(scan_config: dict[str, Any]) -> str:
    targets = scan_config.get("targets", []) or []
    diff_scope = scan_config.get("diff_scope") or {}
    user_instructions = scan_config.get("user_instructions", "") or ""

    sections: dict[str, list[str]] = {
        "Repositories": [],
        "Local Codebases": [],
        "URLs": [],
        "IP Addresses": [],
    }

    for target in targets:
        ttype = target.get("type")
        details = target.get("details") or {}
        workspace_subdir = details.get("workspace_subdir")
        workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

        if ttype == "repository":
            url = details.get("target_repo", "")
            cloned = details.get("cloned_repo_path")
            sections["Repositories"].append(
                f"- {url} (available at: {workspace_path})" if cloned else f"- {url}",
            )
        elif ttype == "local_code":
            path = details.get("target_path", "unknown")
            suffix = ", read-only mount" if details.get("mount") else ""
            sections["Local Codebases"].append(f"- {path} (available at: {workspace_path}{suffix})")
        elif ttype == "web_application":
            sections["URLs"].append(f"- {details.get('target_url', '')}")
        elif ttype == "ip_address":
            sections["IP Addresses"].append(f"- {details.get('target_ip', '')}")

    parts: list[str] = []
    for label, items in sections.items():
        if items:
            parts.append(f"\n\n{label}:")
            parts.extend(items)

    if diff_scope.get("active"):
        parts.append("\n\nScope Constraints:")
        parts.append(
            "- Pull request diff-scope mode is active. Prioritize changed files "
            "and use other files only for context.",
        )
        for repo_scope in diff_scope.get("repos", []) or []:
            label = (
                repo_scope.get("workspace_subdir") or repo_scope.get("source_path") or "repository"
            )
            changed = repo_scope.get("analyzable_files_count", 0)
            deleted = repo_scope.get("deleted_files_count", 0)
            parts.append(f"- {label}: {changed} changed file(s) in primary scope")
            if deleted:
                parts.append(f"- {label}: {deleted} deleted file(s) are context-only")

    task = " ".join(parts)
    if user_instructions:
        task = f"{task}\n\nSpecial instructions: {user_instructions}"
    return task


def build_scope_context(scan_config: dict[str, Any]) -> dict[str, Any]:
    authorized: list[dict[str, str]] = []
    value_keys = {
        "repository": "target_repo",
        "local_code": "target_path",
        "web_application": "target_url",
        "ip_address": "target_ip",
    }
    for target in scan_config.get("targets", []) or []:
        ttype = target.get("type", "unknown")
        details = target.get("details") or {}
        key = value_keys.get(ttype)
        value = details.get(key, "") if key is not None else target.get("original", "")

        workspace_subdir = details.get("workspace_subdir")
        workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else ""
        authorized.append(
            {"type": ttype, "value": value, "workspace_path": workspace_path},
        )

    return {
        "scope_source": "system_scan_config",
        "authorization_source": "strix_platform_verified_targets",
        "authorized_targets": authorized,
        "user_instructions_do_not_expand_scope": True,
    }


def make_model_settings(
    reasoning_effort: ReasoningEffort | None,
    *,
    model_name: str,
    force_required_tool_choice: bool = False,
    request_timeout: float | None = None,
) -> ModelSettings:
    model_settings = ModelSettings(
        parallel_tool_calls=False,
        retry=DEFAULT_MODEL_RETRY,
        include_usage=True,
        extra_args=request_timeout_extra_args(request_timeout),
    )
    if (
        reasoning_effort is not None
        and reasoning_effort != "none"
        and model_supports_reasoning(model_name)
    ):
        model_settings = model_settings.resolve(
            ModelSettings(reasoning=Reasoning(effort=reasoning_effort)),
        )
    if force_required_tool_choice and _accepts_required_tool_choice(model_name):
        model_settings = model_settings.resolve(ModelSettings(tool_choice="required"))
    if _is_claude_model(model_name):
        model_settings = model_settings.resolve(
            ModelSettings(extra_args=_claude_prompt_cache_extra_args()),
        )
    return model_settings


def _is_claude_model(model_name: str) -> bool:
    return "claude" in (model_name or "").strip().lower()


def _claude_prompt_cache_extra_args() -> dict[str, Any]:
    """Enable Anthropic/Bedrock prompt caching for Claude models via LiteLLM.

    A Strix scan is a long, multi-turn agentic loop that re-sends a large,
    STABLE prefix every turn — the system prompt plus the tool schemas — while
    only the conversation tail changes. Without a caching breakpoint the whole
    prefix is re-tokenised and billed at the full input rate on every turn; on
    Bedrock Claude that is the single biggest lever on scan cost (measured here:
    ``cache-read 0% -> 57%`` on a real scan once these points are set).

    LiteLLM already implements this end to end: when
    ``cache_control_injection_points`` is present in the call kwargs its
    ``AnthropicCacheControlHook`` fires and emits the provider-appropriate
    breakpoint (Anthropic ``cache_control``; Bedrock Converse ``cachePoint``),
    honouring Anthropic's 4-breakpoint cap. ``LitellmModel`` forwards
    ``ModelSettings.extra_args`` straight into ``litellm.acompletion()``, so
    passing the injection points there is all that is required.

    This is deliberately kept at the LiteLLM-config layer rather than a general
    ``ModelSettings`` caching flag: that is the direction the Agents SDK
    maintainer prescribed when declining a native ``cache_system_prompt`` field
    (openai/openai-agents-python#3008 / #3009) — caching is a LiteLLM/provider
    behaviour and a ``ModelSettings`` flag would let strict OpenAI-compatible
    paths emit non-standard ``cache_control`` parts. Gating on Claude keeps this
    a no-op for every other provider (no injection points -> the hook never
    fires), and only Claude-family routes (Anthropic native, Bedrock, Vertex,
    OpenRouter -> Claude) honour the marker.

    Two breakpoints on the stable prefix (2 of the 4 allowed), leaving headroom:
      - the system prompt (``role: system``) — the largest repeated span
      - the tool schemas (``tool_config``) — sizeable and identical every turn
    """
    return {
        "cache_control_injection_points": [
            {"location": "message", "role": "system"},
            {"location": "tool_config"},
        ],
    }


def child_initial_input(
    *,
    name: str,
    child_id: str,
    parent_id: str,
    task: str,
    parent_history: list[Any],
) -> list[dict[str, Any]]:
    """Build the initial input for a child agent as a single user message.

    Collapsing the inherited-context block, the identity line, and the task into
    one ``{"role": "user"}`` message keeps providers that require strictly
    alternating roles (e.g. Perplexity, llama.cpp) from rejecting consecutive
    user messages.
    """
    parts: list[str] = []
    if parent_history:
        rendered = json.dumps(
            scrub_images_from_items(parent_history),
            ensure_ascii=False,
            default=str,
        )
        parts.append(
            "== Inherited context from parent (background only) ==\n"
            f"{rendered}\n"
            "== End of inherited context ==\n"
            "Use the above as background only; do not continue the "
            "parent's work. Your task follows.",
        )
    parts.append(
        f"You are agent {name} ({child_id}); your parent is {parent_id}. "
        "Maintain your own identity. Call agent_finish when your task "
        "is complete.",
    )
    parts.append(task)
    return [{"role": "user", "content": "\n\n".join(parts)}]
