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


# Output ceiling for Claude models when the user hasn't set one. Adaptive-thinking
# Claude on Bedrock Converse otherwise sends no maxTokens and truncates long tool
# calls mid-JSON (the arguments blob is cut a brace short → next-turn history replay
# 400s in litellm's openai→bedrock converter). Every current Claude tier accepts at
# least this much output; the value is clamped to the model's own ceiling below, so
# it is safe even on older Claude with a smaller limit.
_CLAUDE_DEFAULT_MAX_TOKENS = 32000


def resolve_max_tokens(model_name: str, configured: int | None) -> int | None:
    """Decide the output ceiling for a model.

    - Non-Claude models: return ``configured`` untouched (``None`` → provider
      default). We do not impose a ceiling on gpt/ollama/gemini/etc. — a local
      user on a small-context model must not be forced past its limit.
    - Claude models: use ``configured`` or a family default, then clamp to the
      model's known output ceiling so the value can never exceed what the
      provider accepts (older Claude tops out at 4096-8192).

    Gated on the Claude family rather than a version/tier list: the bug this
    guards (adaptive-thinking truncation) spans opus-4-6/4-8 and sonnet-4-6 today
    and will grow, while opus-4-1 is not adaptive — so tier is the wrong axis.
    """
    if not _is_claude_model(model_name):
        return configured

    ceiling = _model_output_ceiling(model_name)
    if configured is not None:
        # Respect an explicit user value; clamp only if we know the ceiling.
        return min(configured, ceiling) if ceiling else configured
    # No explicit value: only inject the family default when we know it fits the
    # model. If the ceiling is unknown (model missing from litellm's cost map),
    # fall back to None (provider default) rather than guess a value that could
    # exceed the true limit — the adaptive models that need the fix all have a
    # known ceiling, so nothing is lost.
    if ceiling is None:
        return None
    return min(_CLAUDE_DEFAULT_MAX_TOKENS, ceiling)


def _is_claude_model(model_name: str) -> bool:
    return "claude" in model_name.strip().lower()


def _model_output_ceiling(model_name: str) -> int | None:
    """Look up a model's max output tokens in litellm's cost map.

    litellm keys the same model under several names (``global.anthropic.claude-
    opus-4-8``, ``anthropic.claude-opus-4-8``, ``claude-opus-4-8``), and not every
    region/provider-prefixed variant is present for every model. Try the name as
    given, then progressively strip the SDK route prefix, an ``owner/`` segment,
    and leading dotted segments (region like ``global.``/``us.``, then provider
    like ``anthropic.``) so a prefixed name still resolves to the bare key.
    """
    import litellm

    name = model_name.strip().lower()
    for prefix in ("litellm/", "any-llm/", "openai/", "bedrock/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break

    candidates = [name]
    if "/" in name:
        candidates.append(name.rsplit("/", 1)[1])
    # Strip leading dotted segments one at a time: global.anthropic.claude-x
    # -> anthropic.claude-x -> claude-x. Each intermediate form is a real key
    # for some models, so try them all.
    for cand in list(candidates):
        rest = cand
        while "." in rest:
            rest = rest.split(".", 1)[1]
            candidates.append(rest)

    for cand in candidates:
        entry = litellm.model_cost.get(cand)
        if entry:
            ceiling = entry.get("max_output_tokens") or entry.get("max_tokens")
            if isinstance(ceiling, int):
                return ceiling
    return None


def make_model_settings(
    reasoning_effort: ReasoningEffort | None,
    *,
    model_name: str,
    force_required_tool_choice: bool = False,
    request_timeout: float | None = None,
    max_tokens: int | None = None,
) -> ModelSettings:
    model_settings = ModelSettings(
        parallel_tool_calls=False,
        retry=DEFAULT_MODEL_RETRY,
        include_usage=True,
        extra_args=request_timeout_extra_args(request_timeout),
        max_tokens=resolve_max_tokens(model_name, max_tokens),
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
    return model_settings


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
