"""Discovery and explicit enablement checks for host-side MCP servers."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from strix.config import load_settings


if TYPE_CHECKING:
    from strix.config.settings import McpServerExtras


class McpConfigError(ValueError):
    """An untrusted MCP configuration cannot be used safely."""


@dataclass(frozen=True)
class McpDefinition:
    name: str
    source: Path
    raw: Any
    definition_hash: str


@dataclass(frozen=True)
class EnabledMcpServer:
    definition: McpDefinition
    extras: McpServerExtras
    params: dict[str, Any]


_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def user_mcp_path() -> Path:
    return Path.home() / ".strix" / ".mcp.json"


def project_mcp_path(cwd: Path | None = None) -> Path:
    return (cwd or Path.cwd()) / ".mcp.json"


def discover_servers(*, cwd: Path | None = None) -> dict[str, McpDefinition]:
    """Return user definitions overlaid by project definitions by server name."""
    definitions: dict[str, McpDefinition] = {}
    for path in (user_mcp_path(), project_mcp_path(cwd)):
        for name, raw in _read_definition_file(path).items():
            source = path.resolve()
            definitions[name] = McpDefinition(
                name=name,
                source=source,
                raw=raw,
                definition_hash=_definition_hash(source, raw),
            )
    return definitions


def server_statuses(*, cwd: Path | None = None) -> dict[str, str]:
    """Classify discovered servers without expanding secrets or launching anything."""
    extras = load_settings().mcp.servers
    statuses: dict[str, str] = {}
    definitions = discover_servers(cwd=cwd)
    for name, definition in definitions.items():
        saved = extras.get(name)
        if saved is None or not saved.enabled:
            statuses[name] = "disabled"
        elif _matches(saved, definition):
            statuses[name] = "enabled"
        else:
            statuses[name] = "changed — re-enable required"
    for name in extras.keys() - definitions.keys():
        statuses[name] = (
            "missing — saved enablement; disable/revocation recommended"
            if extras[name].enabled
            else "missing — disabled"
        )
    return statuses


def enabled_servers(
    *, cwd: Path | None = None, names: set[str] | None = None
) -> list[EnabledMcpServer]:
    """Resolve explicitly enabled definitions, expanding env only after trust checks."""
    settings = load_settings().mcp
    definitions = discover_servers(cwd=cwd)
    candidates = (
        names
        if names is not None
        else (
            set(definitions) | {name for name, extras in settings.servers.items() if extras.enabled}
        )
    )
    resolved: list[EnabledMcpServer] = []
    for name in sorted(candidates):
        extras = settings.servers.get(name)
        if extras is None or not extras.enabled:
            continue
        definition = definitions.get(name)
        if definition is None:
            raise McpConfigError(
                f"MCP server '{name}' is enabled but its definition is missing; disable it first"
            )
        if not _matches(extras, definition):
            raise McpConfigError(f"MCP server '{name}' changed — re-enable required")
        validate_definition(name, definition.raw)
        if not extras.allow_tools:
            raise McpConfigError(f"MCP server '{name}' is enabled without an allowlist")
        resolved.append(
            EnabledMcpServer(
                definition=definition,
                extras=extras,
                params=_expand_definition(definition.raw),
            )
        )
    if names is not None:
        missing = names - {server.definition.name for server in resolved}
        if missing:
            raise McpConfigError(f"MCP server is not enabled: {', '.join(sorted(missing))}")
    return resolved


def _read_definition_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise McpConfigError(f"Cannot read MCP configuration {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise McpConfigError(f"MCP configuration {path} must be a JSON object")
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        raise McpConfigError(f"MCP configuration {path}: mcpServers must be an object")
    result: dict[str, Any] = {}
    for name, raw in servers.items():
        if not isinstance(name, str) or not name.strip():
            raise McpConfigError(f"MCP configuration {path} has an invalid server definition")
        result[name] = raw
    return result


def validate_definition(name: str, raw: Any) -> None:
    if not isinstance(raw, dict):
        raise McpConfigError(f"MCP server '{name}' must be an object")
    command = raw.get("command")
    url = raw.get("url")
    if bool(command) == bool(url):
        raise McpConfigError(f"MCP server '{name}' must set exactly one of command or url")
    if command is not None and not isinstance(command, str):
        raise McpConfigError(f"MCP server '{name}' command must be a string")
    if url is not None and not isinstance(url, str):
        raise McpConfigError(f"MCP server '{name}' url must be a string")
    for key in ("args",):
        if key in raw and (
            not isinstance(raw[key], list) or not all(isinstance(value, str) for value in raw[key])
        ):
            raise McpConfigError(f"MCP server '{name}' {key} must be a list of strings")
    for key in ("env", "headers"):
        if key in raw and (
            not isinstance(raw[key], dict)
            or not all(isinstance(k, str) and isinstance(v, str) for k, v in raw[key].items())
        ):
            raise McpConfigError(f"MCP server '{name}' {key} must be a string map")
    transport = raw.get("type")
    if transport is not None and transport not in {"sse", "streamableHttp"}:
        raise McpConfigError(f"MCP server '{name}' has unsupported type {transport!r}")


def _definition_hash(source: Path, raw: Any) -> str:
    payload = {"source": str(source), "definition": raw}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _matches(extras: McpServerExtras, definition: McpDefinition) -> bool:
    return (
        extras.source == str(definition.source)
        and extras.definition_hash == definition.definition_hash
    )


def _expand_definition(raw: Any) -> dict[str, Any]:
    return cast("dict[str, Any]", _expand_value(raw))


def _expand_value(value: Any) -> Any:
    if isinstance(value, str):
        return _VAR.sub(_expand_match, value)
    if isinstance(value, list):
        return [_expand_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _expand_value(item) for key, item in value.items()}
    return value


def _expand_match(match: re.Match[str]) -> str:
    name, default = match.groups()
    value = os.environ.get(name)
    if value is not None:
        return value
    if default is not None:
        return default
    raise McpConfigError(f"MCP configuration requires environment variable {name}")
