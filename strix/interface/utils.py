import ipaddress
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import docker
from docker.errors import DockerException, ImageNotFound
from rich.console import Console
from rich.panel import Panel
from rich.text import Text


# Token formatting utilities
def format_token_count(count: float) -> str:
    count = int(count)
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    if count >= 1_000:
        return f"{count / 1_000:.1f}K"
    return str(count)


# Display utilities
def get_severity_color(severity: str) -> str:
    severity_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#65a30d",
        "info": "#0284c7",
    }
    return severity_colors.get(severity, "#6b7280")


def _build_vulnerability_stats(stats_text: Text, tracer: Any) -> None:
    """Build vulnerability section of stats text."""
    vuln_count = len(tracer.vulnerability_reports)

    if vuln_count > 0:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for report in tracer.vulnerability_reports:
            severity = report.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        stats_text.append("🔍 Vulnerabilities Found: ", style="bold red")

        severity_parts = []
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts[severity]
            if count > 0:
                severity_color = get_severity_color(severity)
                severity_text = Text()
                severity_text.append(f"{severity.upper()}: ", style=severity_color)
                severity_text.append(str(count), style=f"bold {severity_color}")
                severity_parts.append(severity_text)

        for i, part in enumerate(severity_parts):
            stats_text.append(part)
            if i < len(severity_parts) - 1:
                stats_text.append(" | ", style="dim white")

        stats_text.append(" (Total: ", style="dim white")
        stats_text.append(str(vuln_count), style="bold yellow")
        stats_text.append(")", style="dim white")
        stats_text.append("\n")
    else:
        stats_text.append("🔍 Vulnerabilities Found: ", style="bold green")
        stats_text.append("0", style="bold white")
        stats_text.append(" (No exploitable vulnerabilities detected)", style="dim green")
        stats_text.append("\n")


def _build_llm_stats(stats_text: Text, total_stats: dict[str, Any]) -> None:
    """Build LLM usage section of stats text."""
    if total_stats["requests"] > 0:
        stats_text.append("\n")
        stats_text.append("📥 Input Tokens: ", style="bold cyan")
        stats_text.append(format_token_count(total_stats["input_tokens"]), style="bold white")

        if total_stats["cached_tokens"] > 0:
            stats_text.append(" • ", style="dim white")
            stats_text.append("⚡ Cached Tokens: ", style="bold green")
            stats_text.append(format_token_count(total_stats["cached_tokens"]), style="bold white")

        stats_text.append(" • ", style="dim white")
        stats_text.append("📤 Output Tokens: ", style="bold cyan")
        stats_text.append(format_token_count(total_stats["output_tokens"]), style="bold white")

        if total_stats["cost"] > 0:
            stats_text.append(" • ", style="dim white")
            stats_text.append("💰 Total Cost: ", style="bold cyan")
            stats_text.append(f"${total_stats['cost']:.4f}", style="bold yellow")
    else:
        stats_text.append("\n")
        stats_text.append("💰 Total Cost: ", style="bold cyan")
        stats_text.append("$0.0000 ", style="bold yellow")
        stats_text.append("• ", style="bold white")
        stats_text.append("📊 Tokens: ", style="bold cyan")
        stats_text.append("0", style="bold white")


def build_final_stats_text(tracer: Any) -> Text:
    """Build stats text for final output with detailed messages and LLM usage."""
    stats_text = Text()
    if not tracer:
        return stats_text

    _build_vulnerability_stats(stats_text, tracer)

    tool_count = tracer.get_real_tool_count()
    agent_count = len(tracer.agents)

    stats_text.append("🤖 Agents Used: ", style="bold cyan")
    stats_text.append(str(agent_count), style="bold white")
    stats_text.append(" • ", style="dim white")
    stats_text.append("🛠️ Tools Called: ", style="bold cyan")
    stats_text.append(str(tool_count), style="bold white")

    llm_stats = tracer.get_total_llm_stats()
    _build_llm_stats(stats_text, llm_stats["total"])

    return stats_text


def build_live_stats_text(tracer: Any, agent_config: dict[str, Any] | None = None) -> Text:
    stats_text = Text()
    if not tracer:
        return stats_text

    if agent_config:
        llm_config = agent_config["llm_config"]
        model = getattr(llm_config, "model_name", "Unknown")
        stats_text.append(f"🧠 Model: {model}")
        stats_text.append("\n")

    vuln_count = len(tracer.vulnerability_reports)
    tool_count = tracer.get_real_tool_count()
    agent_count = len(tracer.agents)

    stats_text.append("🔍 Vulnerabilities: ", style="bold white")
    stats_text.append(f"{vuln_count}", style="dim white")
    stats_text.append("\n")
    if vuln_count > 0:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for report in tracer.vulnerability_reports:
            severity = report.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        severity_parts = []
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts[severity]
            if count > 0:
                severity_color = get_severity_color(severity)
                severity_text = Text()
                severity_text.append(f"{severity.upper()}: ", style=severity_color)
                severity_text.append(str(count), style=f"bold {severity_color}")
                severity_parts.append(severity_text)

        for i, part in enumerate(severity_parts):
            stats_text.append(part)
            if i < len(severity_parts) - 1:
                stats_text.append(" | ", style="dim white")

        stats_text.append("\n")

    stats_text.append("🤖 Agents: ", style="bold white")
    stats_text.append(str(agent_count), style="dim white")
    stats_text.append(" • ", style="dim white")
    stats_text.append("🛠️ Tools: ", style="bold white")
    stats_text.append(str(tool_count), style="dim white")

    llm_stats = tracer.get_total_llm_stats()
    total_stats = llm_stats["total"]

    stats_text.append("\n")

    stats_text.append("📥 Input: ", style="bold white")
    stats_text.append(format_token_count(total_stats["input_tokens"]), style="dim white")

    stats_text.append(" • ", style="dim white")
    stats_text.append("⚡ ", style="bold white")
    stats_text.append("Cached: ", style="bold white")
    stats_text.append(format_token_count(total_stats["cached_tokens"]), style="dim white")

    stats_text.append("\n")

    stats_text.append("📤 Output: ", style="bold white")
    stats_text.append(format_token_count(total_stats["output_tokens"]), style="dim white")

    stats_text.append(" • ", style="dim white")
    stats_text.append("💰 Cost: ", style="bold white")
    stats_text.append(f"${total_stats['cost']:.4f}", style="dim white")

    return stats_text


# Name generation utilities


def _slugify_for_run_name(text: str, max_length: int = 32) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = text.strip("-")
    if len(text) > max_length:
        text = text[:max_length].rstrip("-")
    return text or "pentest"


def _derive_target_label_for_run_name(targets_info: list[dict[str, Any]] | None) -> str:  # noqa: PLR0911
    if not targets_info:
        return "pentest"

    first = targets_info[0]
    target_type = first.get("type")
    details = first.get("details", {}) or {}
    original = first.get("original", "") or ""

    if target_type == "web_application":
        url = details.get("target_url", original)
        try:
            parsed = urlparse(url)
            return str(parsed.netloc or parsed.path or url)
        except Exception:  # noqa: BLE001
            return str(url)

    if target_type == "repository":
        repo = details.get("target_repo", original)
        parsed = urlparse(repo)
        path = parsed.path or repo
        name = path.rstrip("/").split("/")[-1] or path
        if name.endswith(".git"):
            name = name[:-4]
        return str(name)

    if target_type == "local_code":
        path_str = details.get("target_path", original)
        try:
            return str(Path(path_str).name or path_str)
        except Exception:  # noqa: BLE001
            return str(path_str)

    if target_type == "ip_address":
        return str(details.get("target_ip", original) or original)

    return str(original or "pentest")


def generate_run_name(targets_info: list[dict[str, Any]] | None = None) -> str:
    base_label = _derive_target_label_for_run_name(targets_info)
    slug = _slugify_for_run_name(base_label)

    random_suffix = secrets.token_hex(2)

    return f"{slug}_{random_suffix}"


# Target processing utilities
def infer_target_type(target: str) -> tuple[str, dict[str, str]]:  # noqa: PLR0911
    if not target or not isinstance(target, str):
        raise ValueError("Target must be a non-empty string")

    target = target.strip()

    lower_target = target.lower()
    bare_repo_prefixes = (
        "github.com/",
        "www.github.com/",
        "gitlab.com/",
        "www.gitlab.com/",
        "bitbucket.org/",
        "www.bitbucket.org/",
    )
    if any(lower_target.startswith(p) for p in bare_repo_prefixes):
        return "repository", {"target_repo": f"https://{target}"}

    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        if any(
            host in parsed.netloc.lower() for host in ["github.com", "gitlab.com", "bitbucket.org"]
        ):
            return "repository", {"target_repo": target}
        return "web_application", {"target_url": target}

    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        return "ip_address", {"target_ip": str(ip_obj)}

    path = Path(target).expanduser()
    try:
        if path.exists():
            if path.is_dir():
                resolved = path.resolve()
                return "local_code", {"target_path": str(resolved)}
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
        "- A domain name (e.g., example.com)\n"
        "- An IP address (e.g., 192.168.1.10)"
    )


def sanitize_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "-", name.strip())
    return sanitized or "target"


def derive_repo_base_name(repo_url: str) -> str:
    if repo_url.endswith("/"):
        repo_url = repo_url[:-1]

    if ":" in repo_url and repo_url.startswith("git@"):
        path_part = repo_url.split(":", 1)[1]
    else:
        path_part = urlparse(repo_url).path or repo_url

    candidate = path_part.split("/")[-1]
    if candidate.endswith(".git"):
        candidate = candidate[:-4]

    return sanitize_name(candidate or "repository")


def derive_local_base_name(path_str: str) -> str:
    try:
        base = Path(path_str).resolve().name
    except (OSError, RuntimeError):
        base = Path(path_str).name
    return sanitize_name(base or "workspace")


def assign_workspace_subdirs(targets_info: list[dict[str, Any]]) -> None:
    name_counts: dict[str, int] = {}

    for target in targets_info:
        target_type = target["type"]
        details = target["details"]

        base_name: str | None = None
        if target_type == "repository":
            base_name = derive_repo_base_name(details["target_repo"])
        elif target_type == "local_code":
            base_name = derive_local_base_name(details.get("target_path", "local"))

        if base_name is None:
            continue

        count = name_counts.get(base_name, 0) + 1
        name_counts[base_name] = count

        workspace_subdir = base_name if count == 1 else f"{base_name}-{count}"

        details["workspace_subdir"] = workspace_subdir


def collect_local_sources(targets_info: list[dict[str, Any]]) -> list[dict[str, str]]:
    local_sources: list[dict[str, str]] = []

    for target_info in targets_info:
        details = target_info["details"]
        workspace_subdir = details.get("workspace_subdir")

        if target_info["type"] == "local_code" and "target_path" in details:
            local_sources.append(
                {
                    "source_path": details["target_path"],
                    "workspace_subdir": workspace_subdir,
                }
            )

        elif target_info["type"] == "repository" and "cloned_repo_path" in details:
            local_sources.append(
                {
                    "source_path": details["cloned_repo_path"],
                    "workspace_subdir": workspace_subdir,
                }
            )

    return local_sources


# Repository utilities
def clone_repository(repo_url: str, run_name: str, dest_name: str | None = None) -> str:
    console = Console()

    git_executable = shutil.which("git")
    if git_executable is None:
        raise FileNotFoundError("Git executable not found in PATH")

    temp_dir = Path(tempfile.gettempdir()) / "strix_repos" / run_name
    temp_dir.mkdir(parents=True, exist_ok=True)

    if dest_name:
        repo_name = dest_name
    else:
        repo_name = Path(repo_url).stem if repo_url.endswith(".git") else Path(repo_url).name

    clone_path = temp_dir / repo_name

    if clone_path.exists():
        shutil.rmtree(clone_path)

    try:
        with console.status(f"[bold cyan]Cloning repository {repo_url}...", spinner="dots"):
            subprocess.run(  # noqa: S603
                [
                    git_executable,
                    "clone",
                    repo_url,
                    str(clone_path),
                ],
                capture_output=True,
                text=True,
                check=True,
            )

        return str(clone_path.absolute())

    except subprocess.CalledProcessError as e:
        error_text = Text()
        error_text.append("❌ ", style="bold red")
        error_text.append("REPOSITORY CLONE FAILED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append(f"Could not clone repository: {repo_url}\n", style="white")
        error_text.append(
            f"Error: {e.stderr if hasattr(e, 'stderr') and e.stderr else str(e)}", style="dim red"
        )

        panel = Panel(
            error_text,
            title="[bold red]🛡️  STRIX CLONE ERROR",
            title_align="center",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)
    except FileNotFoundError:
        error_text = Text()
        error_text.append("❌ ", style="bold red")
        error_text.append("GIT NOT FOUND", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("Git is not installed or not available in PATH.\n", style="white")
        error_text.append("Please install Git to clone repositories.\n", style="white")

        panel = Panel(
            error_text,
            title="[bold red]🛡️  STRIX CLONE ERROR",
            title_align="center",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


# Docker utilities
def check_docker_connection() -> Any:
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
        raise RuntimeError("Docker not available") from None


def image_exists(client: Any, image_name: str) -> bool:
    try:
        client.images.get(image_name)
    except ImageNotFound:
        return False
    else:
        return True


def update_layer_status(layers_info: dict[str, str], layer_id: str, layer_status: str) -> None:
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


def process_pull_line(
    line: dict[str, Any], layers_info: dict[str, str], status: Any, last_update: str
) -> str:
    if "id" in line and "status" in line:
        layer_id = line["id"]
        update_layer_status(layers_info, layer_id, line["status"])

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


# LLM utilities
def validate_llm_response(response: Any) -> None:
    if not response or not response.choices or not response.choices[0].message.content:
        raise RuntimeError("Invalid response from LLM")
