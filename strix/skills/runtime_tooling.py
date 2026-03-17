from __future__ import annotations

import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_TOOL_SKILL_PATHS: dict[str, str] = {
    "nmap": "tooling/nmap",
    "nuclei": "tooling/nuclei",
    "httpx": "tooling/httpx",
    "ffuf": "tooling/ffuf",
    "subfinder": "tooling/subfinder",
    "naabu": "tooling/naabu",
    "katana": "tooling/katana",
    "sqlmap": "tooling/sqlmap",
}

_TOOL_DOC_URLS: dict[str, str] = {
    "nmap": "https://nmap.org/book/man-briefoptions.html",
    "nuclei": "https://docs.projectdiscovery.io/opensource/nuclei/running",
    "httpx": "https://docs.projectdiscovery.io/opensource/httpx/running",
    "ffuf": "https://github.com/ffuf/ffuf",
    "subfinder": "https://docs.projectdiscovery.io/opensource/subfinder/overview",
    "naabu": "https://docs.projectdiscovery.io/opensource/naabu/overview",
    "katana": "https://docs.projectdiscovery.io/opensource/katana/overview",
    "sqlmap": "https://github.com/sqlmapproject/sqlmap/wiki/Usage",
}

_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_HELP_FLAGS = {"-h", "--help", "-help", "-?", "help", "—help"}
_SUDO_OPTIONS_WITH_VALUE = {
    "-u",
    "--user",
    "-g",
    "--group",
    "-h",
    "--host",
    "-p",
    "--prompt",
    "-C",
    "--close-from",
    "-T",
    "--command-timeout",
}
_WRAPPER_COMMANDS = {
    "command",
    "builtin",
    "nohup",
    "time",
    "stdbuf",
    "nice",
    "ionice",
    "chrt",
    "setsid",
}
_TIMEOUT_VALUE_RE = re.compile(r"^\d+(\.\d+)?([smhd])?$")


@dataclass(frozen=True)
class ToolingPreflight:
    skills_to_load: tuple[str, ...]
    tools_with_new_skills: tuple[str, ...]
    help_requested_tools: tuple[str, ...]


def get_tooling_preflight(
    actions: list[dict[str, Any]],
    already_loaded_skills: set[str],
) -> ToolingPreflight:
    skills_to_load: list[str] = []
    tools_with_new_skills: list[str] = []
    help_requested_tools: list[str] = []

    for action in actions:
        tool_name = action.get("toolName")
        if tool_name != "terminal_execute":
            continue

        args = action.get("args", {})
        if not isinstance(args, dict):
            continue

        command = args.get("command")
        if not isinstance(command, str) or not command.strip():
            continue

        for detected in _extract_detected_tools(command):
            skill_path = _TOOL_SKILL_PATHS.get(detected.name)
            if not skill_path:
                continue

            if detected.uses_help_flag and detected.name not in help_requested_tools:
                help_requested_tools.append(detected.name)

            if skill_path not in already_loaded_skills and skill_path not in skills_to_load:
                skills_to_load.append(skill_path)
                if detected.name not in tools_with_new_skills:
                    tools_with_new_skills.append(detected.name)

    return ToolingPreflight(
        skills_to_load=tuple(skills_to_load),
        tools_with_new_skills=tuple(tools_with_new_skills),
        help_requested_tools=tuple(help_requested_tools),
    )


def build_tooling_preflight_message(
    tools_with_new_skills: Sequence[str],
    help_requested_tools: Sequence[str],
) -> str:
    lines: list[str] = ["<runtime_tool_skill_context>"]

    if tools_with_new_skills:
        loaded = ", ".join(tools_with_new_skills)
        lines.append(
            "Loaded tool-specific CLI skills for: "
            f"{loaded}. Use these references before running commands."
        )
        lines.append("Official docs:")
        for tool in tools_with_new_skills:
            url = _TOOL_DOC_URLS.get(tool)
            if url:
                lines.append(f"- {tool}: {url}")

    if help_requested_tools:
        preferred = ", ".join(help_requested_tools)
        lines.append(
            f"Prefer loaded syntax over help flags for these tools ({preferred}) "
            "to avoid wasting iterations."
        )

    lines.append(
        "If you need version-specific confirmation, call web_search against the official docs "
        "URL for that exact tool and then run the command."
    )
    lines.append("</runtime_tool_skill_context>")
    return "\n".join(lines)


def canonical_runtime_skill_name(skill_name: str) -> str:
    normalized = skill_name.strip()
    if not normalized:
        return normalized
    return _TOOL_SKILL_PATHS.get(normalized, normalized)


@dataclass(frozen=True)
class _DetectedTool:
    name: str
    uses_help_flag: bool


def _extract_detected_tools(command: str) -> list[_DetectedTool]:
    detections: list[_DetectedTool] = []
    for segment in _split_shell_segments(command):
        command_name, args = _extract_command_and_args(segment)
        if not command_name:
            continue
        if command_name not in _TOOL_SKILL_PATHS:
            continue

        uses_help_flag = any(_is_help_arg(arg) for arg in args)
        existing = next((d for d in detections if d.name == command_name), None)
        if existing is None:
            detections.append(_DetectedTool(command_name, uses_help_flag))
            continue
        if uses_help_flag and not existing.uses_help_flag:
            detections = [
                _DetectedTool(d.name, uses_help_flag=True)
                if d.name == command_name
                else d
                for d in detections
            ]

    return detections


def _split_shell_segments(command: str) -> list[str]:
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escape_next = False
    index = 0

    while index < len(command):
        char = command[index]

        if escape_next:
            current.append(char)
            escape_next = False
            index += 1
            continue

        if char == "\\" and quote != "'":
            current.append(char)
            escape_next = True
            index += 1
            continue

        if quote:
            current.append(char)
            if char == quote:
                quote = None
            index += 1
            continue

        if char in {"'", '"'}:
            quote = char
            current.append(char)
            index += 1
            continue

        if char in {";", "\n", "|"}:
            if char == "|" and index + 1 < len(command) and command[index + 1] == "|":
                index += 1

            segment = "".join(current).strip()
            if segment:
                segments.append(segment)
            current = []
            index += 1
            continue

        if char == "&" and index + 1 < len(command) and command[index + 1] == "&":
            segment = "".join(current).strip()
            if segment:
                segments.append(segment)
            current = []
            index += 2
            continue

        current.append(char)
        index += 1

    tail = "".join(current).strip()
    if tail:
        segments.append(tail)

    return segments


def _extract_command_and_args(segment: str) -> tuple[str | None, list[str]]:
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        tokens = segment.split()

    index = 0
    while index < len(tokens):
        part = tokens[index]

        if part == "sudo":
            index = _consume_sudo(tokens, index + 1)
            continue

        if part == "env":
            index = _consume_env(tokens, index + 1)
            continue

        if part == "timeout":
            index = _consume_timeout(tokens, index + 1)
            continue

        if part in _WRAPPER_COMMANDS:
            index += 1
            continue

        if _ASSIGNMENT_RE.match(part):
            index += 1
            continue

        if part == "--":
            index += 1
            continue

        if part.startswith("-"):
            index += 1
            continue

        command_name = Path(part).name.lower()
        return command_name, tokens[index + 1 :]

    return None, []


def _consume_sudo(tokens: list[str], start_index: int) -> int:
    index = start_index
    while index < len(tokens):
        part = tokens[index]
        if part in _SUDO_OPTIONS_WITH_VALUE and index + 1 < len(tokens):
            index += 2
            continue
        if part.startswith("-"):
            index += 1
            continue
        break
    return index


def _consume_env(tokens: list[str], start_index: int) -> int:
    index = start_index
    while index < len(tokens):
        part = tokens[index]
        if part.startswith("-"):
            index += 1
            continue
        if _ASSIGNMENT_RE.match(part):
            index += 1
            continue
        break
    return index


def _consume_timeout(tokens: list[str], start_index: int) -> int:
    index = start_index
    while index < len(tokens) and tokens[index].startswith("-"):
        index += 1

    if index < len(tokens) and _TIMEOUT_VALUE_RE.match(tokens[index]):
        index += 1

    return index


def _is_help_arg(arg: str) -> bool:
    normalized = arg.strip().lower()
    if normalized in _HELP_FLAGS:
        return True
    return normalized.startswith("—") and normalized.endswith("help")
