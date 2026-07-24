"""`strix models` — list the models Strix can run.

A read-only discovery command, split into two sections:

- Subscription models — the live ChatGPT-plan catalog (a static preview when
  signed out). Select one with ``strix auth model <name>``.
- API-key models — the recommended frontier models; any other LiteLLM-supported
  model works too. Select one by setting ``STRIX_LLM`` and ``LLM_API_KEY``.

The model the config currently points at is marked in whichever section it
belongs to.
"""

from __future__ import annotations

from rich.console import Console

from strix.auth import codex
from strix.config import load_settings
from strix.config.models import RECOMMENDED_MODEL_NAMES


_USAGE = "Usage:\n  strix models"


def run_models(argv: list[str]) -> int:
    """Entry point for ``strix models``. Returns a process exit code."""
    console = Console()
    if argv and argv[0] in ("-h", "--help", "help"):
        console.print(_USAGE)
        return 0

    _print_subscription_models(console)
    console.print()
    _print_api_models(console)
    console.print()
    console.print(
        "[dim]Use a subscription model with [cyan]strix auth model <name>[/]; "
        "use an API model by setting [cyan]STRIX_LLM[/] and [cyan]LLM_API_KEY[/].[/]"
    )
    return 0


def _current_subscription_model() -> str | None:
    """The subscription model the config currently selects, or None if the switch
    isn't set to the subscription (or the saved slug is invalid)."""
    model = load_settings().llm.model
    if not codex.is_subscription(model):
        return None
    try:
        return codex.resolve_subscription_model(model)
    except codex.CodexAuthError:
        return None


def _print_subscription_models(console: Console) -> None:
    console.print(
        "[bold]Subscription models[/] [dim](ChatGPT plan · openai/subscription/<name>)[/]"
    )
    if codex.is_authenticated():
        # Live catalog; falls back to the static list if the fetch fails.
        models = codex.refresh_subscription_models()
        current = _current_subscription_model()
    else:
        models = codex.SUBSCRIPTION_MODELS
        current = None
        console.print("  [dim]Sign in with [cyan]strix auth login chatgpt[/] to use these.[/]")
    for slug in models:
        marker = "[green]●[/]" if slug == current else "[dim]○[/]"
        label = codex.subscription_model_label(slug)
        suffix = f"  [dim]({label})[/]" if label else ""
        console.print(f"  {marker} [bold]{slug}[/]{suffix}")


def _print_api_models(console: Console) -> None:
    console.print("[bold]API-key models[/] [dim](metered · set STRIX_LLM + LLM_API_KEY)[/]")
    active = load_settings().llm.model
    # Mark the active model only if it's an API-key model (not the subscription).
    active_api = "" if codex.is_subscription(active) else (active or "").strip().lower()
    for name in RECOMMENDED_MODEL_NAMES:
        marker = "[green]●[/]" if name.lower() == active_api else "[dim]○[/]"
        console.print(f"  {marker} [bold]{name}[/]")
    console.print(
        "  [dim]…or any other LiteLLM-supported model (openai/*, anthropic/*, gemini/*, …)[/]"
    )


__all__ = ["run_models"]
