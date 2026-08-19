"""Settings loader, override switch, and disk persistence."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import AliasChoices, BaseModel

from strix.config.settings import Settings
from strix.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from pydantic.fields import FieldInfo


logger = logging.getLogger(__name__)


_DEFAULT_PATH: Path = Path.home() / ".strix" / "cli-config.json"
_override: Path | None = None
_cached: Settings | None = None


def load_settings() -> Settings:
    """Resolve settings from env + JSON file + defaults. Memoized.

    Precedence: env vars win, then the JSON file, then field defaults.
    """
    global _cached  # noqa: PLW0603
    if _cached is None:
        source_path = _override or _DEFAULT_PATH
        init_kwargs: dict[str, Any] = _read_json_overrides(source_path)
        _cached = Settings(**init_kwargs)
        logger.debug(
            "load_settings: resolved (override=%s, file_used=%s, json_keys=%d)",
            _override is not None,
            source_path.exists(),
            sum(len(v) for v in init_kwargs.values()),
        )
    return _cached


def apply_config_override(path: Path) -> None:
    """Switch the JSON source to ``path`` and invalidate the cache."""
    global _override, _cached  # noqa: PLW0603
    _override = path
    _cached = None
    logger.info("config override applied: %s", path)


def persist_current() -> None:
    """Write currently-set env vars to the active config file (0o600)."""
    s = load_settings()
    target = _override or _DEFAULT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)

    env_block: dict[str, str] = {}
    for sub_name in type(s).model_fields:
        sub_model = getattr(s, sub_name)
        if not isinstance(sub_model, BaseModel):
            continue
        for finfo in type(sub_model).model_fields.values():
            for alias in _aliases_for(finfo):
                value = os.environ.get(alias.upper())
                if value:
                    env_block[alias.upper()] = value
                    break

    data = _read_config_document(target, strict=True)
    data["env"] = env_block
    _write_config_document(target, data)


def config_path() -> Path:
    """Return the active persisted configuration path."""
    return _override or _DEFAULT_PATH


def update_mcp_config(mcp: dict[str, Any]) -> None:
    """Persist MCP opt-in state without dropping unrelated config keys."""
    global _cached  # noqa: PLW0603
    target = config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    data = _read_config_document(target, strict=True)
    data["mcp"] = mcp
    _write_config_document(target, data)
    _cached = None


def update_mcp_server(name: str, updates: dict[str, Any]) -> None:
    """Merge one MCP server record without persisting environment-derived settings."""
    global _cached  # noqa: PLW0603
    target = config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    data = _read_config_document(target, strict=True)
    mcp = data.get("mcp", {})
    if not isinstance(mcp, dict):
        raise TypeError(f"Cannot update malformed MCP settings in {target}: expected JSON object")
    servers = mcp.get("servers", {})
    if not isinstance(servers, dict):
        raise TypeError(
            f"Cannot update malformed MCP settings in {target}: servers must be an object"
        )
    old = servers.get(name, {})
    if not isinstance(old, dict):
        raise TypeError(
            f"Cannot update malformed MCP settings in {target}: server must be an object"
        )
    data["mcp"] = {**mcp, "servers": {**servers, name: {**old, **updates}}}
    _write_config_document(target, data)
    _cached = None


def _read_config_document(path: Path, *, strict: bool = False) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        if strict:
            raise ValueError(f"Cannot update malformed Strix configuration {path}: {exc}") from exc
        return {}
    if isinstance(data, dict):
        return data
    if strict:
        raise ValueError(
            f"Cannot update malformed Strix configuration {path}: expected JSON object"
        )
    return {}


def _write_config_document(path: Path, data: dict[str, Any]) -> None:
    write_secret_text(path, json.dumps(data, indent=2))


def _aliases_for(finfo: FieldInfo) -> list[str]:
    """Collect every env-var name that should populate ``finfo``."""
    aliases: list[str] = []
    if finfo.alias:
        aliases.append(finfo.alias)
    va = finfo.validation_alias
    if isinstance(va, AliasChoices):
        aliases.extend(c for c in va.choices if isinstance(c, str))
    elif isinstance(va, str):
        aliases.append(va)
    return aliases


def _read_json_overrides(path: Path) -> dict[str, dict[str, Any]]:
    """Read ``{"env": {...}}`` from ``path`` and remap to nested kwargs.

    Only includes keys whose env var is NOT already set, so env always
    wins over the persisted file.
    """
    if not path.exists():
        return {}
    data = _read_config_document(path)
    env_block = data.get("env", {})
    if not isinstance(env_block, dict):
        env_block = {}

    env_block_upper = {str(k).upper(): v for k, v in env_block.items()}
    env_present = {k.upper() for k in os.environ}

    nested: dict[str, dict[str, Any]] = {}
    for sub_name, sub_finfo in Settings.model_fields.items():
        sub_cls = sub_finfo.annotation
        if not (isinstance(sub_cls, type) and issubclass(sub_cls, BaseModel)):
            continue
        sub_data: dict[str, Any] = {}
        for fname, finfo in sub_cls.model_fields.items():
            aliases = [alias.upper() for alias in _aliases_for(finfo)]
            if any(alias in env_present for alias in aliases):
                continue  # env wins under some alias; skip the JSON file for this field
            for alias in aliases:
                if alias in env_block_upper:
                    sub_data[fname] = env_block_upper[alias]
                    break
        if sub_data:
            nested[sub_name] = sub_data
    mcp_block = data.get("mcp")
    if isinstance(mcp_block, dict):
        mcp_data = dict(mcp_block)
        if "STRIX_MCP_ENABLED" in env_present:
            mcp_data.pop("enabled", None)
        nested["mcp"] = mcp_data
    return nested
