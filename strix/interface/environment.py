"""Startup environment validation and Docker image management."""

import logging
import shutil
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import claude_code, codex, load_settings
from strix.interface.utils import (
    check_docker_connection,
    image_exists,
    process_pull_line,
)


logger = logging.getLogger(__name__)


def _validate_claude_code(console: Console, model: str | None) -> None:
    """Preflight for a ``claude-code/...`` run. Exits the process on any hard stop.

    The ``claude`` binary and its signed-in session must live on the **host**
    running Strix — not inside the target sandbox. This is the single most
    common way this backend confuses people, so preflight says it out loud.
    """
    if claude_code.binary_path() is None:
        console.print(
            f"[red]STRIX_LLM={model} needs the Claude Code CLI, which isn't on PATH.[/] "
            "Install it on this host, then run [cyan]claude /login[/] on your Pro/Max plan."
        )
        sys.exit(1)
    floor = ".".join(str(part) for part in claude_code.MIN_CLAUDE_VERSION)
    version_state = claude_code.version_state()
    if version_state == "too_old":
        console.print(
            f"[red]Your Claude Code CLI ({claude_code.version()}) is too old.[/] "
            f"Strix needs at least [cyan]{floor}[/]. Update it and retry."
        )
        sys.exit(1)
    if version_state == "unknown":
        console.print(
            "[red]Couldn't read a version from the Claude Code CLI on PATH.[/] "
            f"Strix needs [cyan]{floor}[/] or newer. Check that "
            "[cyan]claude --version[/] runs on this host."
        )
        sys.exit(1)

    state = claude_code.session_state()
    if state == "signed_out":
        console.print(
            f"[red]STRIX_LLM={model} uses your Claude subscription, but the Claude Code CLI "
            "isn't signed in.[/] Run [cyan]claude /login[/] (Pro/Max) first."
        )
        sys.exit(1)
    if state == "api_key":
        source = claude_code.api_key_source()
        # Naming the source matters: an ANTHROPIC_API_KEY left in the environment
        # overrides a perfectly good Pro/Max login, and `claude auth status`
        # still shows the claude.ai account, so the cause is not obvious.
        cause = (
            f"[cyan]{source}[/] is overriding your sign-in, so the"
            if source
            else "The Claude Code CLI is on an API key, not a subscription, so the"
        )
        console.print(
            f"[yellow]Warning:[/] {cause} scan will meter against that key rather "
            "than run at $0. Unset it, or run [cyan]claude /login[/] with your "
            "Pro/Max account, to use the subscription."
        )
    elif state == "unknown":
        console.print(
            "[yellow]Warning:[/] couldn't determine the Claude Code sign-in state; "
            "proceeding. If the scan fails to authenticate, run [cyan]claude /login[/]."
        )
    logger.info("Environment OK (Claude Code subscription)")


def validate_environment() -> None:
    logger.info("Validating environment")
    console = Console()
    missing_required_vars = []
    missing_optional_vars = []

    settings = load_settings()

    if codex.subscription_model(settings.llm.model):
        if not codex.is_authenticated():
            console.print(
                f"[red]STRIX_LLM={settings.llm.model} uses your ChatGPT subscription, "
                "but you're not signed in.[/] Run [cyan]strix auth login chatgpt[/] first."
            )
            sys.exit(1)
        logger.info("Environment OK (ChatGPT subscription)")
        return

    if claude_code.claude_code_model(settings.llm.model):
        _validate_claude_code(console, settings.llm.model)
        return

    if not settings.llm.model:
        missing_required_vars.append("STRIX_LLM")

    if not settings.llm.api_key:
        missing_optional_vars.append("LLM_API_KEY")

    if not settings.llm.api_base:
        missing_optional_vars.append("LLM_API_BASE")

    if not settings.integrations.perplexity_api_key:
        missing_optional_vars.append("PERPLEXITY_API_KEY")

    if missing_required_vars:
        error_text = Text()
        error_text.append("MISSING REQUIRED ENVIRONMENT VARIABLES", style="bold red")
        error_text.append("\n\n", style="white")

        for var in missing_required_vars:
            error_text.append(f"• {var}", style="bold yellow")
            error_text.append(" is not set\n", style="white")

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="dim white")
            for var in missing_optional_vars:
                error_text.append(f"• {var}", style="dim yellow")
                error_text.append(" is not set\n", style="dim white")

        error_text.append("\nRequired environment variables:\n", style="white")
        for var in missing_required_vars:
            if var == "STRIX_LLM":
                error_text.append("• ", style="white")
                error_text.append("STRIX_LLM", style="bold cyan")
                error_text.append(
                    " - Model name to use (e.g., 'openai/gpt-5.4' or "
                    "'anthropic/claude-opus-4-7')\n",
                    style="white",
                )

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="white")
            for var in missing_optional_vars:
                if var == "LLM_API_BASE":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_BASE", style="bold cyan")
                    error_text.append(
                        " - Custom API base URL if using local models (e.g., Ollama, LMStudio)\n",
                        style="white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("PERPLEXITY_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for Perplexity AI web search (enables real-time research)\n",
                        style="white",
                    )
                elif var == "STRIX_REASONING_EFFORT":
                    error_text.append("• ", style="white")
                    error_text.append("STRIX_REASONING_EFFORT", style="bold cyan")
                    error_text.append(
                        " - Reasoning effort level: none, minimal, low, medium, high, xhigh, "
                        "max (default: high)\n",
                        style="white",
                    )

        error_text.append("\nExample setup:\n", style="white")
        error_text.append("export STRIX_LLM='openai/gpt-5.4'\n", style="dim white")

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_BASE":
                    error_text.append(
                        "export LLM_API_BASE='http://localhost:11434'  "
                        "# needed for local models only\n",
                        style="dim white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append(
                        "export PERPLEXITY_API_KEY='your-perplexity-key-here'\n", style="dim white"
                    )
                elif var == "STRIX_REASONING_EFFORT":
                    error_text.append(
                        "export STRIX_REASONING_EFFORT='high'\n",
                        style="dim white",
                    )

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        logger.debug("Missing required env vars: %s", missing_required_vars)
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)
    logger.info(
        "Environment OK (optional missing: %s)",
        missing_optional_vars or "none",
    )


def check_docker_installed() -> None:
    if shutil.which("docker") is None:
        logger.debug("Docker CLI not found in PATH")
        console = Console()
        error_text = Text()
        error_text.append("DOCKER NOT INSTALLED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("The 'docker' CLI was not found in your PATH.\n", style="white")
        error_text.append(
            "Please install Docker and ensure the 'docker' command is available.\n\n", style="white"
        )

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)
    logger.debug("Docker CLI present")


def pull_docker_image() -> None:
    from docker.errors import DockerException

    console = Console()
    client = check_docker_connection()

    image = load_settings().runtime.image

    if image_exists(client, image):
        logger.debug("Docker image already present locally: %s", image)
        return

    logger.info("Pulling docker image: %s", image)
    console.print()
    console.print(f"[dim]Pulling image[/] {image}")
    console.print("[dim yellow]This only happens on first run and may take a few minutes...[/]")
    console.print()

    with console.status("[bold cyan]Downloading image layers...", spinner="dots") as status:
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(image, stream=True, decode=True):
                last_update = process_pull_line(line, layers_info, status, last_update)

        except DockerException as e:
            logger.debug("Failed to pull docker image %s", image, exc_info=True)
            console.print()
            error_text = Text()
            error_text.append("FAILED TO PULL IMAGE", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(f"Could not download: {image}\n", style="white")
            error_text.append(str(e), style="dim red")

            panel = Panel(
                error_text,
                title="[bold white]STRIX",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print(panel, "\n")
            sys.exit(1)

    logger.info("Docker image %s ready", image)
    success_text = Text()
    success_text.append("Docker image ready", style="#22c55e")
    console.print(success_text)
    console.print()
