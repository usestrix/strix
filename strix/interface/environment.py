"""Startup environment validation and Docker image management."""

import logging
import shutil
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import IntegrationSettings, claude_code, codex, load_settings
from strix.interface.utils import (
    check_docker_connection,
    image_exists,
    process_pull_line,
)
from strix.telemetry import report_error


logger = logging.getLogger(__name__)


def _missing_web_search_vars(integrations: IntegrationSettings) -> list[str]:
    """Mirror the web_search provider rules: which key(s) the selected provider needs."""
    if integrations.web_search_provider == "exa":
        return [] if integrations.exa_api_key else ["EXA_API_KEY"]
    if integrations.web_search_provider == "perplexity":
        return [] if integrations.perplexity_api_key else ["PERPLEXITY_API_KEY"]
    if integrations.exa_api_key or integrations.perplexity_api_key:
        return []
    return ["EXA_API_KEY", "PERPLEXITY_API_KEY"]


def _require_claude_binary(console: Console, model: str | None) -> None:
    """Exit unless the ``claude`` CLI is on this host's PATH."""
    if claude_code.binary_path() is not None:
        return
    console.print(
        f"[red]STRIX_LLM={model} needs the Claude Code CLI, which isn't on PATH.[/] "
        "Install it on this host, then run [cyan]claude /login[/] on your Pro/Max plan."
    )
    sys.exit(1)


def _require_supported_claude_version(console: Console) -> None:
    """Exit unless the installed ``claude`` meets :data:`claude_code.MIN_CLAUDE_VERSION`."""
    version_state = claude_code.version_state()
    if version_state == "ok":
        return
    floor = ".".join(str(part) for part in claude_code.MIN_CLAUDE_VERSION)
    if version_state == "too_old":
        console.print(
            f"[red]Your Claude Code CLI ({claude_code.version()}) is too old.[/] "
            f"Strix needs at least [cyan]{floor}[/]. Update it and retry."
        )
    else:
        # "update your CLI" is the wrong advice for a binary that did not run or
        # whose version string could not be read, so say what was actually wrong.
        console.print(
            "[red]Couldn't read a version from the Claude Code CLI on PATH.[/] "
            f"Strix needs [cyan]{floor}[/] or newer. Check that "
            "[cyan]claude --version[/] runs on this host."
        )
    sys.exit(1)


def _require_signed_in_claude(console: Console, model: str | None) -> str:
    """The Claude Code session state, exiting if it is signed out."""
    state = claude_code.session_state()
    if state != "signed_out":
        return state
    console.print(
        f"[red]STRIX_LLM={model} uses your Claude subscription, but the Claude Code CLI "
        "isn't signed in.[/] Run [cyan]claude /login[/] (Pro/Max) first."
    )
    sys.exit(1)


def _warn_when_claude_run_is_metered(console: Console, session_state: str) -> None:
    """Warn when the run will be accounted as metered instead of as a $0 subscription."""
    if session_state == "api_key":
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
    elif session_state == "unknown":
        # An unknown state is accounted as an API key, so this is not only about
        # authentication: the run will be reported as metered and can be stopped
        # by --max-budget even though it is spending subscription quota.
        console.print(
            "[yellow]Warning:[/] couldn't determine the Claude Code sign-in state, so this "
            "run will be reported as metered rather than as a $0 subscription. Check that "
            "[cyan]claude auth status[/] works on this host; if the scan then fails to "
            "authenticate, run [cyan]claude /login[/]."
        )


def _validate_claude_code(console: Console, model: str | None) -> None:
    """Preflight for a ``claude-code/...`` run. Exits the process on any hard stop.

    The ``claude`` binary and its signed-in session must live on the **host**
    running Strix, not inside the target sandbox. This is the single most common
    way this backend confuses people, so preflight says it out loud.
    """
    _require_claude_binary(console, model)
    _require_supported_claude_version(console)
    _warn_when_claude_run_is_metered(console, _require_signed_in_claude(console, model))
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
            report_error("subscription_not_signed_in")
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

    missing_optional_vars.extend(_missing_web_search_vars(settings.integrations))

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
                    " - Model name to use (e.g., 'openrouter/z-ai/glm-5.3' or "
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
                        " - API key for Perplexity AI web search (alternative to Exa)\n",
                        style="white",
                    )
                elif var == "EXA_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("EXA_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for Exa web search (enables real-time research)\n",
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
        error_text.append("export STRIX_LLM='openrouter/z-ai/glm-5.3'\n", style="dim white")

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
                elif var == "EXA_API_KEY":
                    error_text.append("export EXA_API_KEY='your-exa-key-here'\n", style="dim white")
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
        report_error("missing_required_config")
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
        report_error("docker_not_installed")
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
            report_error("image_pull_failed", e)
            sys.exit(1)

    logger.info("Docker image %s ready", image)
    success_text = Text()
    success_text.append("Docker image ready", style="#22c55e")
    console.print(success_text)
    console.print()
