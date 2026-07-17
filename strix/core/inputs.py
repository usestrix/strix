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
    if _is_claude_model(model_name) and not _bedrock_route_without_cache_support(model_name):
        # Merge into any existing extra_args rather than relying on resolve()'s
        # dict-merge semantics — makes it obvious at the call site that unrelated
        # LiteLLM options are preserved (make_model_settings currently builds
        # from scratch, so extra_args is None here today, but this keeps the
        # invariant local if that changes).
        merged_extra_args = {
            **(model_settings.extra_args or {}),
            **_claude_prompt_cache_extra_args(),
        }
        model_settings = model_settings.resolve(
            ModelSettings(extra_args=merged_extra_args),
        )
    return model_settings


def _is_claude_model(model_name: str) -> bool:
    return "claude" in (model_name or "").strip().lower()


def _litellm_name_candidates(model_name: str) -> list[str]:
    """Candidate LiteLLM model-map keys for ``model_name``, most→least specific.

    LiteLLM keys the same model under several names (``bedrock/global.anthropic.
    claude-opus-4-1``, ``anthropic.claude-opus-4-1``, ``claude-opus-4-1``) and not
    every provider/region-prefixed variant is present for every model. Strip the
    LiteLLM route prefix, then leading dotted segments (region, then provider) so
    a prefixed name still resolves to a bare key.
    """
    name = (model_name or "").strip().lower()
    for prefix in ("litellm/", "bedrock/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    candidates = [name]
    for cand in list(candidates):
        rest = cand
        while "." in rest:
            rest = rest.split(".", 1)[1]
            candidates.append(rest)
    return candidates


def _bedrock_route_without_cache_support(model_name: str) -> bool:
    """True for a BEDROCK Claude route that LiteLLM can't confirm supports prompt
    caching — the one case where injecting the cache marker HARD-CRASHES the run.

    Bedrock's Converse API rejects unknown request fields outright
    (``ValidationException: cache_control_injection_points: Extra inputs are not
    permitted``). LiteLLM's ``AnthropicCacheControlHook`` strips
    ``cache_control_injection_points`` from the outgoing call only for models it
    recognises as cache-capable via its (statically bundled) model map; for a
    model missing from that map the marker passes straight through and Bedrock
    500s the first call, failing the whole scan. This bites any Bedrock Claude
    model LiteLLM hasn't mapped yet — a just-released model, or ANY model when
    LiteLLM can't refresh its remote model map (e.g. behind a TLS-intercepting
    corporate proxy) and falls back to a stale local copy.

    Scope is deliberately narrow — ONLY Bedrock routes. Anthropic-native,
    Vertex, and OpenRouter Claude tolerate/ignore the marker (or LiteLLM maps
    them under keys we don't resolve), so gating those on confirmed support
    would DISABLE caching for genuinely-capable models — a caching regression,
    the opposite of this change's intent. So elsewhere we keep injecting by
    model family and only withhold on the provider that actually rejects.
    """
    name = (model_name or "").strip().lower()
    if not name.startswith("bedrock/") and "anthropic." not in name:
        # Not a Bedrock route (bedrock/... or a bare bedrock model id like
        # global.anthropic.claude-...); other providers don't hard-reject.
        return False

    import litellm

    checker = getattr(getattr(litellm, "utils", None), "supports_prompt_caching", None)
    for cand in _litellm_name_candidates(model_name):
        if checker is not None:
            try:
                if checker(cand):
                    return False  # confirmed cache-capable → safe to inject
            except Exception:  # noqa: BLE001 — unknown model raises; keep checking
                pass
        entry = litellm.model_cost.get(cand)
        if entry and entry.get("supports_prompt_caching"):
            return False
    return True  # Bedrock route, support unconfirmed → withhold to avoid the 500


def _claude_prompt_cache_extra_args() -> dict[str, Any]:
    """Enable Anthropic/Bedrock prompt caching for Claude models via LiteLLM.

    A Strix scan is a long, multi-turn agentic loop that re-sends a large,
    STABLE prefix every turn — the system prompt plus the tool schemas — AND an
    append-only conversation transcript that only grows. Without caching
    breakpoints the whole request is re-tokenised and billed at the full input
    rate on every turn; on Bedrock Claude that is the single biggest lever on
    scan cost (measured here: ``cache-read 0% -> 57%`` on a real scan once these
    points are set).

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

    Three breakpoints (3 of the 4 allowed), leaving headroom:
      - the system prompt (``role: system``) — the largest repeated span
      - the tool schemas (``tool_config``) — sizeable and identical every turn
      - the conversation tail (``index: -1``) — a ROLLING breakpoint on the last
        message, so the accumulated transcript caches incrementally

    The tail breakpoint matters more than it looks. The first two only cache the
    FIXED prefix; the transcript is append-only (prior turns are immutable, each
    turn just appends the new assistant/tool messages), so on a long scan the
    growing body is re-sent at full input price every turn and cache-read decays
    as a denominator effect even though the prefix keeps hitting. A breakpoint at
    ``index: -1`` re-caches the whole immutable prefix-so-far each turn and hits
    on the next; the hook resolves the negative index against the live message
    list. Measured on a 29-turn Bedrock scan, WITHOUT the tail point the cached
    prefix stayed pinned at ~56k tokens while per-turn input grew to ~256k and
    cache-read fell from 90% to 22%; adding it lifts modelled cache-read to ~96%
    and cuts full-price input ~16x on that scan.

    All three points degrade gracefully on older LiteLLM: an unrecognised
    location is simply not injected (no error), so a stale pin still gets
    whatever caching it supports — the system-prompt point (the widest support)
    and the tool_config + message-index points applied by LiteLLM's Bedrock
    Converse transform on versions that recognise them (verified on litellm
    1.90.1).
    """
    return {
        "cache_control_injection_points": [
            {"location": "message", "role": "system"},
            {"location": "tool_config"},
            {"location": "message", "index": -1},
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
