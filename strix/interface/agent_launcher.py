"""Launch Strix through an authenticated coding-agent CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from strix.config import load_settings
from strix.mcp.install import skill_path


def uses_coding_agent(args: Any) -> bool:
    """Return whether this invocation should delegate reasoning to a coding agent."""
    requested = str(getattr(args, "agent", "auto") or "auto")
    if requested == "legacy":
        return False
    if requested in {"codex", "claude"}:
        return True
    return not bool(load_settings().llm.model)


def resolve_agent(requested: str) -> str:
    """Resolve ``auto`` to an installed, authenticated-agent-capable CLI."""
    if requested != "auto":
        if shutil.which(requested) is None:
            raise RuntimeError(f"Requested coding agent CLI is not installed: {requested}")
        return requested
    for candidate in (os.environ.get("STRIX_AGENT"), "codex", "claude"):
        if candidate and candidate in {"codex", "claude"} and shutil.which(candidate):
            return candidate
    raise RuntimeError(
        "No coding agent CLI found. Install Codex or Claude Code, or configure legacy "
        "provider mode with STRIX_LLM."
    )


def _scan_prompt(args: Any) -> str:
    instructions_path = skill_path() / "SKILL.md"
    targets = [] if args.resume else list(args.target or [])
    mounts = [] if args.resume else list(args.mount or [])
    call = {
        "targets": targets,
        "mounts": mounts,
        "scan_mode": args.scan_mode,
        "instruction": args.instruction or "",
        "run_name": args.resume,
        "resume": bool(args.resume),
        "scope_mode": args.scope_mode,
        "diff_base": args.diff_base,
        "non_interactive": args.non_interactive,
    }
    return (
        "Run a Strix security assessment now. Read the complete skill file at "
        f"{instructions_path} and follow it exactly. Use the connected Strix MCP tools for the "
        "scan "
        "lifecycle, isolated security commands, proxy traffic, findings, and final report. "
        "Do not call any model API or ask for a model API key. Begin by calling start_scan with "
        f"these arguments: {json.dumps(call, ensure_ascii=False)}. Continue until finish_scan "
        "succeeds, unless authorization or a material blocker requires user input."
    )


def _mcp_command() -> tuple[str, list[str]]:
    return sys.executable, ["-m", "strix.mcp.server"]


def build_agent_command(args: Any, agent: str) -> list[str]:
    """Build a coding-agent command with an ephemeral Strix MCP server."""
    python, server_args = _mcp_command()
    prompt = _scan_prompt(args)
    cwd = str(Path.cwd())
    if agent == "codex":
        command = [
            "codex",
            "-C",
            cwd,
            "-c",
            f"mcp_servers.strix.command={json.dumps(python)}",
            "-c",
            f"mcp_servers.strix.args={json.dumps(server_args)}",
            "-c",
            "mcp_servers.strix.startup_timeout_sec=120",
            "-c",
            "mcp_servers.strix.tool_timeout_sec=900",
        ]
        if args.non_interactive:
            command.insert(1, "exec")
        command.append(prompt)
        return command

    config = json.dumps(
        {
            "mcpServers": {
                "strix": {"type": "stdio", "command": python, "args": server_args, "env": {}}
            }
        }
    )
    command = ["claude", "--mcp-config", config]
    if args.non_interactive:
        command.append("--print")
        if args.max_budget_usd is not None:
            command.extend(["--max-budget-usd", str(args.max_budget_usd)])
    # ``--mcp-config`` accepts multiple values. Without an option terminator,
    # Claude consumes the positional prompt as another config path.
    command.extend(["--", prompt])
    return command


def launch_agent_scan(args: Any) -> int:
    """Run Strix in the selected coding agent and return its exit status."""
    agent = resolve_agent(str(args.agent or "auto"))
    command = build_agent_command(args, agent)
    command[0] = shutil.which(agent) or command[0]
    result = subprocess.run(command, check=False)  # noqa: S603
    return result.returncode
