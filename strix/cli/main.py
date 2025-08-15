#!/usr/bin/env python3
"""
Strix Agent Command Line Interface
"""

import argparse
import asyncio
import logging
import os
import secrets
import shutil
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import docker
import litellm
from docker.errors import DockerException
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.cli.app import run_strix_cli
from strix.cli.tracer import get_global_tracer
from strix.runtime.docker_runtime import STRIX_IMAGE


logging.getLogger().setLevel(logging.ERROR)


def format_token_count(count: float) -> str:
    count = int(count)
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    if count >= 1_000:
        return f"{count / 1_000:.1f}K"
    return str(count)


def validate_environment() -> None:
    console = Console()
    missing_required_vars = []
    missing_optional_vars = []

    if not os.getenv("STRIX_LLM"):
        missing_required_vars.append("STRIX_LLM")

    if not os.getenv("LLM_API_KEY"):
        missing_required_vars.append("LLM_API_KEY")

    if not os.getenv("PERPLEXITY_API_KEY"):
        missing_optional_vars.append("PERPLEXITY_API_KEY")

    if missing_required_vars:
        error_text = Text()
        error_text.append("❌ ", style="bold red")
        error_text.append("MISSING REQUIRED ENVIRONMENT VARIABLES", style="bold red")
        error_text.append("\n\n", style="white")

        for var in missing_required_vars:
            error_text.append(f"• {var}", style="bold yellow")
            error_text.append(" is not set\n", style="white")

        if missing_optional_vars:
            error_text.append(
                "\nOptional (but recommended) environment variables:\n", style="dim white"
            )
            for var in missing_optional_vars:
                error_text.append(f"• {var}", style="dim yellow")
                error_text.append(" is not set\n", style="dim white")

        error_text.append("\nRequired environment variables:\n", style="white")
        error_text.append("• ", style="white")
        error_text.append("STRIX_LLM", style="bold cyan")
        error_text.append(
            " - Model name to use with litellm (e.g., 'openai/gpt-5')\n",
            style="white",
        )
        error_text.append("• ", style="white")
        error_text.append("LLM_API_KEY", style="bold cyan")
        error_text.append(" - API key for the LLM provider\n", style="white")

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="white")
            error_text.append("• ", style="white")
            error_text.append("PERPLEXITY_API_KEY", style="bold cyan")
            error_text.append(
                " - API key for Perplexity AI web search (enables real-time research)\n",
                style="white",
            )

        error_text.append("\nExample setup:\n", style="white")
        error_text.append("export STRIX_LLM='openai/gpt-5'\n", style="dim white")
        error_text.append("export LLM_API_KEY='your-api-key-here'\n", style="dim white")
        if missing_optional_vars:
            error_text.append(
                "export PERPLEXITY_API_KEY='your-perplexity-key-here'", style="dim white"
            )

        panel = Panel(
            error_text,
            title="[bold red]🛡️  STRIX CONFIGURATION ERROR",
            title_align="center",
            border_style="red",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def _validate_llm_response(response: Any) -> None:
    if not response or not response.choices or not response.choices[0].message.content:
        raise RuntimeError("Invalid response from LLM")


def check_docker_installed() -> None:
    if shutil.which("docker") is None:
        console = Console()
        error_text = Text()
        error_text.append("❌ ", style="bold red")
        error_text.append("DOCKER NOT INSTALLED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("The 'docker' CLI was not found in your PATH.\n", style="white")
        error_text.append(
            "Please install Docker and ensure the 'docker' command is available.\n\n", style="white"
        )

        panel = Panel(
            error_text,
            title="[bold red]🛡️  STRIX STARTUP ERROR",
            title_align="center",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)


async def warm_up_llm() -> None:
    console = Console()

    try:
        model_name = os.getenv("STRIX_LLM", "openai/gpt-5")
        api_key = os.getenv("LLM_API_KEY")

        if api_key:
            litellm.api_key = api_key

        test_messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Reply with just 'OK'."},
        ]

        response = litellm.completion(
            model=model_name,
            messages=test_messages,
        )

        _validate_llm_response(response)

    except Exception as e:  # noqa: BLE001
        error_text = Text()
        error_text.append("❌ ", style="bold red")
        error_text.append("LLM CONNECTION FAILED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("Could not establish connection to the language model.\n", style="white")
        error_text.append("Please check your configuration and try again.\n", style="white")
        error_text.append(f"\nError: {e}", style="dim white")

        panel = Panel(
            error_text,
            title="[bold red]🛡️  STRIX STARTUP ERROR",
            title_align="center",
            border_style="red",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def generate_run_name() -> str:
    # fmt: off
    adjectives = [
        "stealthy", "sneaky", "crafty", "elite", "phantom", "shadow", "silent",
        "rogue", "covert", "ninja", "ghost", "cyber", "digital", "binary",
        "encrypted", "obfuscated", "masked", "cloaked", "invisible", "anonymous"
    ]
    nouns = [
        "exploit", "payload", "backdoor", "rootkit", "keylogger", "botnet", "trojan",
        "worm", "virus", "packet", "buffer", "shell", "daemon", "spider", "crawler",
        "scanner", "sniffer", "honeypot", "firewall", "breach"
    ]
    # fmt: on
    adj = secrets.choice(adjectives)
    noun = secrets.choice(nouns)
    number = secrets.randbelow(900) + 100
    return f"{adj}-{noun}-{number}"


def infer_target_type(target: str) -> tuple[str, dict[str, str]]:
    if not target or not isinstance(target, str):
        raise ValueError("Target must be a non-empty string")

    target = target.strip()

    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        if any(
            host in parsed.netloc.lower() for host in ["github.com", "gitlab.com", "bitbucket.org"]
        ):
            return "repository", {"target_repo": target}
        return "web_application", {"target_url": target}

    path = Path(target)
    try:
        if path.exists():
            if path.is_dir():
                return "local_code", {"target_path": str(path.absolute())}
            raise ValueError(f"Path exists but is not a directory: {target}")
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid path: {target} - {e!s}") from e

    if target.startswith("git@") or target.endswith(".git"):
        return "repository", {"target_repo": target}

    if "." in target and "/" not in target and not target.startswith("."):
        parts = target.split(".")
        if len(parts) >= 2 and all(p and p.strip() for p in parts):
            return "web_application", {"target_url": f"https://{target}"}

    raise ValueError(
        f"Invalid target: {target}\n"
        "Target must be one of:\n"
        "- A valid URL (http:// or https://)\n"
        "- A Git repository URL (https://github.com/... or git@github.com:...)\n"
        "- A local directory path\n"
        "- A domain name (e.g., example.com)"
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Strix Multi-Agent Cybersecurity Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Web application scan
  strix --target https://example.com

  # GitHub repository analysis
  strix --target https://github.com/user/repo
  strix --target git@github.com:user/repo.git

  # Local code analysis
  strix --target ./my-project

  # Domain scan
  strix --target example.com

  # Custom instructions
  strix --target example.com --instruction "Focus on authentication vulnerabilities"
        """,
    )

    parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="Target to scan (URL, repository, local directory path, or domain name)",
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="Custom instructions for the scan. This can be "
        "specific vulnerability types to focus on (e.g., 'Focus on IDOR and XSS'), "
        "testing approaches (e.g., 'Perform thorough authentication testing'), "
        "test credentials (e.g., 'Use the following credentials to access the app: "
        "admin:password123'), "
        "or areas of interest (e.g., 'Check login API endpoint for security issues')",
    )

    parser.add_argument(
        "--run-name",
        type=str,
        help="Custom name for this scan run",
    )

    args = parser.parse_args()

    try:
        args.target_type, args.target_dict = infer_target_type(args.target)
    except ValueError as e:
        parser.error(str(e))

    return args


def _build_stats_text(tracer: Any) -> Text:
    stats_text = Text()
    if not tracer:
        return stats_text

    vuln_count = len(tracer.vulnerability_reports)
    tool_count = tracer.get_real_tool_count()
    agent_count = len(tracer.agents)

    if vuln_count > 0:
        stats_text.append("🔍 Vulnerabilities Found: ", style="bold red")
        stats_text.append(str(vuln_count), style="bold yellow")
        stats_text.append(" • ", style="dim white")

    stats_text.append("🤖 Agents Used: ", style="bold cyan")
    stats_text.append(str(agent_count), style="bold white")
    stats_text.append(" • ", style="dim white")
    stats_text.append("🛠️ Tools Called: ", style="bold cyan")
    stats_text.append(str(tool_count), style="bold white")

    return stats_text


def _build_llm_stats_text(tracer: Any) -> Text:
    llm_stats_text = Text()
    if not tracer:
        return llm_stats_text

    llm_stats = tracer.get_total_llm_stats()
    total_stats = llm_stats["total"]

    if total_stats["requests"] > 0:
        llm_stats_text.append("📥 Input Tokens: ", style="bold cyan")
        llm_stats_text.append(format_token_count(total_stats["input_tokens"]), style="bold white")

        if total_stats["cached_tokens"] > 0:
            llm_stats_text.append(" • ", style="dim white")
            llm_stats_text.append("⚡ Cached: ", style="bold green")
            llm_stats_text.append(
                format_token_count(total_stats["cached_tokens"]), style="bold green"
            )

        llm_stats_text.append(" • ", style="dim white")
        llm_stats_text.append("📤 Output Tokens: ", style="bold cyan")
        llm_stats_text.append(format_token_count(total_stats["output_tokens"]), style="bold white")

        if total_stats["cost"] > 0:
            llm_stats_text.append(" • ", style="dim white")
            llm_stats_text.append("💰 Total Cost: $", style="bold cyan")
            llm_stats_text.append(f"{total_stats['cost']:.4f}", style="bold yellow")

    return llm_stats_text


def display_completion_message(args: argparse.Namespace, results_path: Path) -> None:
    console = Console()
    tracer = get_global_tracer()

    target_value = next(iter(args.target_dict.values())) if args.target_dict else args.target

    completion_text = Text()
    completion_text.append("🦉 ", style="bold white")
    completion_text.append("AGENT FINISHED", style="bold green")
    completion_text.append(" • ", style="dim white")
    completion_text.append("Security assessment completed", style="white")

    stats_text = _build_stats_text(tracer)

    llm_stats_text = _build_llm_stats_text(tracer)

    target_text = Text()
    target_text.append("🎯 Target: ", style="bold cyan")
    target_text.append(str(target_value), style="bold white")

    results_text = Text()
    results_text.append("📊 Results Saved To: ", style="bold cyan")
    results_text.append(str(results_path), style="bold yellow")

    if stats_text.plain:
        if llm_stats_text.plain:
            panel_content = Text.assemble(
                completion_text,
                "\n\n",
                target_text,
                "\n",
                stats_text,
                "\n",
                llm_stats_text,
                "\n",
                results_text,
            )
        else:
            panel_content = Text.assemble(
                completion_text, "\n\n", target_text, "\n", stats_text, "\n", results_text
            )
    elif llm_stats_text.plain:
        panel_content = Text.assemble(
            completion_text, "\n\n", target_text, "\n", llm_stats_text, "\n", results_text
        )
    else:
        panel_content = Text.assemble(completion_text, "\n\n", target_text, "\n", results_text)

    panel = Panel(
        panel_content,
        title="[bold green]🛡️  STRIX CYBERSECURITY AGENT",
        title_align="center",
        border_style="green",
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()


def _check_docker_connection() -> Any:
    try:
        return docker.from_env()
    except DockerException:
        console = Console()
        error_text = Text()
        error_text.append("❌ ", style="bold red")
        error_text.append("DOCKER NOT AVAILABLE", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("Cannot connect to Docker daemon.\n", style="white")
        error_text.append("Please ensure Docker is installed and running.\n\n", style="white")
        error_text.append("Try running: ", style="dim white")
        error_text.append("sudo systemctl start docker", style="dim cyan")

        panel = Panel(
            error_text,
            title="[bold red]🛡️  STRIX STARTUP ERROR",
            title_align="center",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)


def _image_exists(client: Any) -> bool:
    try:
        client.images.get(STRIX_IMAGE)
    except docker.errors.ImageNotFound:
        return False
    else:
        return True


def _update_layer_status(layers_info: dict[str, str], layer_id: str, layer_status: str) -> None:
    if "Pull complete" in layer_status or "Already exists" in layer_status:
        layers_info[layer_id] = "✓"
    elif "Downloading" in layer_status:
        layers_info[layer_id] = "↓"
    elif "Extracting" in layer_status:
        layers_info[layer_id] = "📦"
    elif "Waiting" in layer_status:
        layers_info[layer_id] = "⏳"
    else:
        layers_info[layer_id] = "•"


def _process_pull_line(
    line: dict[str, Any], layers_info: dict[str, str], status: Any, last_update: str
) -> str:
    if "id" in line and "status" in line:
        layer_id = line["id"]
        _update_layer_status(layers_info, layer_id, line["status"])

        completed = sum(1 for v in layers_info.values() if v == "✓")
        total = len(layers_info)

        if total > 0:
            update_msg = f"[bold cyan]Progress: {completed}/{total} layers complete"
            if update_msg != last_update:
                status.update(update_msg)
                return update_msg

    elif "status" in line and "id" not in line:
        global_status = line["status"]
        if "Pulling from" in global_status:
            status.update("[bold cyan]Fetching image manifest...")
        elif "Digest:" in global_status:
            status.update("[bold cyan]Verifying image...")
        elif "Status:" in global_status:
            status.update("[bold cyan]Finalizing...")

    return last_update


def pull_docker_image() -> None:
    console = Console()
    client = _check_docker_connection()

    if _image_exists(client):
        return

    console.print()
    console.print(f"[bold cyan]🐳 Pulling Docker image:[/bold cyan] {STRIX_IMAGE}")
    console.print(
        "[dim yellow]This only happens on first run and may take a few minutes...[/dim yellow]"
    )
    console.print()

    with console.status("[bold cyan]Downloading image layers...", spinner="dots") as status:
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(STRIX_IMAGE, stream=True, decode=True):
                last_update = _process_pull_line(line, layers_info, status, last_update)

        except DockerException as e:
            console.print()
            error_text = Text()
            error_text.append("❌ ", style="bold red")
            error_text.append("FAILED TO PULL IMAGE", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(f"Could not download: {STRIX_IMAGE}\n", style="white")
            error_text.append(str(e), style="dim red")

            panel = Panel(
                error_text,
                title="[bold red]🛡️  DOCKER PULL ERROR",
                title_align="center",
                border_style="red",
                padding=(1, 2),
            )
            console.print(panel, "\n")
            sys.exit(1)

    success_text = Text()
    success_text.append("✅ ", style="bold green")
    success_text.append("Successfully pulled Docker image", style="green")
    console.print(success_text)
    console.print()


def main() -> None:
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    check_docker_installed()
    pull_docker_image()

    validate_environment()
    asyncio.run(warm_up_llm())

    args = parse_arguments()
    if not args.run_name:
        args.run_name = generate_run_name()

    asyncio.run(run_strix_cli(args))

    results_path = Path("agent_runs") / args.run_name
    display_completion_message(args, results_path)


if __name__ == "__main__":
    main()
