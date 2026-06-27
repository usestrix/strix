"""Request-body and header massaging for the Anthropic passthrough.

Pure functions (no I/O) so they are easy to unit-test. The proxy turns an
incoming Anthropic Messages request (produced by Strix via litellm's `anthropic/`
provider) into one that an Anthropic *subscription* OAuth token will accept, then
builds the forwarded headers.
"""
from __future__ import annotations

from .auth import (
    ANTHROPIC_OAUTH_BETA,
    ANTHROPIC_VERSION,
    CLAUDE_CODE_SYSTEM_PROMPT,
    CLAUDE_CODE_USER_AGENT,
)


def _normalize_system(system, identity: str) -> list:
    """Return a list of system blocks whose first block is the identity prompt."""
    if system is None:
        blocks: list = []
    elif isinstance(system, str):
        blocks = [{"type": "text", "text": system}] if system.strip() else []
    elif isinstance(system, list):
        blocks = list(system)
    else:
        blocks = [{"type": "text", "text": str(system)}]

    if (
        blocks
        and isinstance(blocks[0], dict)
        and blocks[0].get("type") == "text"
        and (blocks[0].get("text") or "").strip() == identity
    ):
        return blocks
    return [{"type": "text", "text": identity}] + blocks


def transform_body(
    body: dict,
    *,
    default_model: str = "claude-opus-4-8",
    max_tokens: int = 32000,
    inject_system_prompt: bool = True,
    strip_prefill: bool = True,
    inject_thinking: bool = False,
    effort: str = "high",
) -> dict:
    """Return a NEW request body adjusted for OAuth/subscription acceptance.

    Does not mutate the input.
    """
    out = dict(body)

    # Model: default when absent, otherwise pass through whatever Strix sent.
    if not out.get("model"):
        out["model"] = default_model

    # Anthropic requires max_tokens; default it when the caller omits it.
    if not out.get("max_tokens"):
        out["max_tokens"] = max_tokens

    # Subscription credential is only accepted when the request presents as
    # Claude Code: the first system block must be the Claude Code identity.
    if inject_system_prompt:
        out["system"] = _normalize_system(out.get("system"), CLAUDE_CODE_SYSTEM_PROMPT)

    # Opus 4.x returns 400 on a trailing assistant prefill turn.
    if strip_prefill:
        msgs = out.get("messages")
        if (
            isinstance(msgs, list)
            and msgs
            and isinstance(msgs[-1], dict)
            and msgs[-1].get("role") == "assistant"
        ):
            out["messages"] = msgs[:-1]

    # Optional: nudge adaptive thinking + effort for agentic performance.
    if inject_thinking and "thinking" not in out:
        out["thinking"] = {"type": "adaptive"}
        oc = dict(out.get("output_config") or {})
        oc.setdefault("effort", effort)
        out["output_config"] = oc
        # thinking is incompatible with a fixed temperature on Opus 4.x.
        out.pop("temperature", None)

    return out


def merge_anthropic_beta(incoming: str | None, required: str = ANTHROPIC_OAUTH_BETA) -> str:
    """Union the caller's anthropic-beta values with the required oauth beta."""
    vals: list[str] = []
    if incoming:
        vals.extend(p.strip() for p in incoming.split(",") if p.strip())
    if required and required not in vals:
        vals.append(required)
    seen: set[str] = set()
    out: list[str] = []
    for v in vals:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return ",".join(out)


def build_forward_headers(incoming_headers, token: str) -> dict:
    """Build the headers used to call api.anthropic.com with the OAuth token.

    Drops the incoming dummy x-api-key / authorization entirely and sets the
    OAuth Bearer + required beta/version headers. The `anthropic-beta` value is
    merged so any feature betas litellm added are preserved.
    """
    incoming_beta = None
    incoming_accept = None
    for k, v in (incoming_headers or {}).items():
        kl = k.lower()
        if kl == "anthropic-beta":
            incoming_beta = v
        elif kl == "accept":
            incoming_accept = v

    return {
        "Authorization": f"Bearer {token}",
        "anthropic-version": ANTHROPIC_VERSION,
        "anthropic-beta": merge_anthropic_beta(incoming_beta),
        "User-Agent": CLAUDE_CODE_USER_AGENT,
        "Content-Type": "application/json",
        "Accept": incoming_accept or "application/json",
        # Force identity so raw passthrough bytes aren't compressed.
        "Accept-Encoding": "identity",
    }
