"""Settings loader, override switch, and disk persistence."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from pydantic import AliasChoices, BaseModel

from strix.config.settings import Settings
from strix.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from pydantic.fields import FieldInfo


logger = logging.getLogger(__name__)


_DEFAULT_PATH: Path = Path.home() / ".strix" / "cli-config.json"
_override: Path | None = None
_cached: Settings | None = None

_REMOVED_SAFETY_MODE = "STRIX_SAFETY_MODE"


def _reject_removed_safety_mode(path: Path) -> None:
    env_keys = {key.upper() for key in os.environ}
    configured = _REMOVED_SAFETY_MODE in env_keys
    if not configured and path.exists():
        try:
            raw_data: object = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            raw_data = {}
        data = cast("dict[str, Any]", raw_data) if isinstance(raw_data, dict) else {}
        raw_env_block: object = data.get("env", {})
        env_block = cast("dict[str, Any]", raw_env_block) if isinstance(raw_env_block, dict) else {}
        configured = any(str(key).upper() == _REMOVED_SAFETY_MODE for key in env_block)
    if configured:
        raise ValueError(
            "STRIX_SAFETY_MODE was removed. Safety now defaults to guarded; remove the "
            "setting and use --dangerously-disable-safety explicitly to opt out for one run."
        )


def load_settings() -> Settings:
    """Resolve settings from env + JSON file + defaults. Memoized.

    Precedence: env vars win, then the JSON file, then field defaults.
    """
    global _cached  # noqa: PLW0603
    if _cached is None:
        source_path = _override or _DEFAULT_PATH
        _reject_removed_safety_mode(source_path)
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

    write_secret_text(target, json.dumps({"env": env_block}, indent=2))


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
    try:
        raw_data: object = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(raw_data, dict):
        return {}
    data = cast("dict[str, Any]", raw_data)
    raw_env_block: object = data.get("env", {})
    if not isinstance(raw_env_block, dict):
        return {}
    env_block = cast("dict[str, Any]", raw_env_block)

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
    return nested
