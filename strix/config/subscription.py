"""Unified subscription-vs-API-key resolution.

Both subscription backends — ChatGPT (``codex``) and Claude Code — bill at a
flat rate, so a run on either reports ``auth_mode="subscription"`` and zero
per-token cost. Four call sites ask this question (report state, scan setup,
usage viewer, resumed-run detection); they all go through here so a third
subscription backend is a one-line change, not a four-place hunt.
"""

from __future__ import annotations

from strix.config import claude_code, codex


def auth_mode(model_name: str | None) -> str:
    """``"subscription"`` if the model runs on any flat-rate backend, else ``"api_key"``."""
    if codex.subscription_model(model_name) or claude_code.claude_code_model(model_name):
        return "subscription"
    return "api_key"


def is_subscription(model_name: str | None) -> bool:
    return auth_mode(model_name) == "subscription"
