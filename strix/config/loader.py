"""Settings loader, override switch, and disk persistence."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from pydantic import AliasChoices, BaseModel

from strix.config.settings import Settings


if TYPE_CHECKING:
    from collections.abc import Callable

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
        source_path = _active_config_path()
        init_kwargs: dict[str, Any] = _read_json_overrides(source_path)
        _cached = Settings(**init_kwargs)
        logger.debug(
            "load_settings: resolved (override=%s, file_used=%s, json_keys=%d)",
            _override is not None,
            source_path.exists(),
            sum(len(value) for value in init_kwargs.values()),
        )
    return _cached


def apply_config_override(path: Path) -> None:
    """Switch the JSON source to ``path`` and invalidate the cache."""
    global _override, _cached  # noqa: PLW0603
    _override = path
    _cached = None
    logger.info("config override applied: %s", path)


def reset_settings_cache() -> None:
    """Invalidate the memoized settings so the next load re-reads env + file."""
    global _cached  # noqa: PLW0603
    _cached = None


def read_config_env(path: Path | None = None) -> dict[str, str]:
    """Return string values from the config file's ``env`` object."""
    data = _read_config_document(path if path is not None else _active_config_path())
    raw_env_block = data.get("env", {})
    if not isinstance(raw_env_block, dict):
        return {}
    return {
        key: value
        for key, value in cast("dict[object, object]", raw_env_block).items()
        if isinstance(key, str) and isinstance(value, str)
    }


def resolve_env_value(*names: str) -> str | None:
    """Resolve aliases from the environment first, then the active config."""
    for name in names:
        if value := _environment_value(name):
            return value

    config_env = {key.upper(): value for key, value in read_config_env().items() if value}
    for name in names:
        if value := config_env.get(name.upper()):
            return value
    return None


def update_config_env(updates: dict[str, str | None]) -> None:
    """Merge ``updates`` into the active config's ``env`` object."""
    target = _active_config_path()
    data = _read_config_document(target)
    raw_env_block = data.get("env")
    if not isinstance(raw_env_block, dict):
        env_block: dict[str, Any] = {}
        data["env"] = env_block
    else:
        env_block = cast("dict[str, Any]", raw_env_block)

    for key, value in updates.items():
        matching_keys = [stored for stored in env_block if stored.upper() == key.upper()]
        for stored in matching_keys:
            del env_block[stored]
        if value is not None:
            env_block[key] = value

    _atomic_write_json(target, data)
    reset_settings_cache()


def read_custom_provider_records() -> list[dict[str, str]]:
    """Return validated string fields from persisted custom-provider records."""
    data = _read_config_document(_active_config_path())
    raw_records = data.get("custom_providers", [])
    if not isinstance(raw_records, list):
        return []
    records: list[dict[str, str]] = []
    for raw_record in cast("list[object]", raw_records):
        if not isinstance(raw_record, dict):
            continue
        record = {
            key: value
            for key, value in cast("dict[object, object]", raw_record).items()
            if isinstance(key, str) and isinstance(value, str)
        }
        if record:
            records.append(record)
    return records


def mutate_custom_provider_records[T](
    mutator: Callable[[list[dict[str, str]]], T],
) -> T:
    """Read, mutate, and persist custom-provider records."""
    target = _active_config_path()
    data = _read_config_document(target)
    raw_records = data.get("custom_providers", [])
    records: list[dict[str, str]] = []
    if isinstance(raw_records, list):
        for raw_record in cast("list[object]", raw_records):
            if not isinstance(raw_record, dict):
                continue
            records.append(
                {
                    key: value
                    for key, value in cast("dict[object, object]", raw_record).items()
                    if isinstance(key, str) and isinstance(value, str)
                }
            )
    result = mutator(records)
    data["custom_providers"] = records
    _atomic_write_json(target, data)
    reset_settings_cache()
    return result


def persist_current() -> None:
    """Merge recognized currently-set env vars into the active config."""
    updates: dict[str, str | None] = {}
    for sub_finfo in Settings.model_fields.values():
        sub_cls = sub_finfo.annotation
        if not (isinstance(sub_cls, type) and issubclass(sub_cls, BaseModel)):
            continue
        for finfo in sub_cls.model_fields.values():
            for alias in _aliases_for(finfo):
                if value := _environment_value(alias):
                    updates[alias.upper()] = value
                    break
    update_config_env(updates)


def _active_config_path() -> Path:
    return _override or _DEFAULT_PATH


def _read_config_document(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        raw_data: object = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return cast("dict[str, Any]", raw_data) if isinstance(raw_data, dict) else {}


def _atomic_write_json(target: Path, data: dict[str, Any]) -> None:
    """Replace the config atomically and keep provider credentials private."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            json.dump(data, handle, indent=2)
            handle.write("\n")
        temporary_path.replace(target)
        target.chmod(0o600)
    finally:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            temporary_path.unlink()


def _environment_value(name: str) -> str | None:
    target = name.upper()
    return next(
        (value for key, value in os.environ.items() if key.upper() == target and value),
        None,
    )


def _aliases_for(finfo: FieldInfo) -> list[str]:
    """Collect every env-var name that should populate ``finfo``."""
    aliases: list[str] = []
    if finfo.alias:
        aliases.append(finfo.alias)
    validation_alias = finfo.validation_alias
    if isinstance(validation_alias, AliasChoices):
        aliases.extend(choice for choice in validation_alias.choices if isinstance(choice, str))
    elif isinstance(validation_alias, str):
        aliases.append(validation_alias)
    return aliases


def _read_json_overrides(path: Path) -> dict[str, dict[str, Any]]:
    """Read ``{"env": {...}}`` and remap recognized values to nested kwargs."""
    env_block_upper = {key.upper(): value for key, value in read_config_env(path).items()}
    env_present = {key.upper() for key, value in os.environ.items() if value}

    nested: dict[str, dict[str, Any]] = {}
    for sub_name, sub_finfo in Settings.model_fields.items():
        sub_cls = sub_finfo.annotation
        if not (isinstance(sub_cls, type) and issubclass(sub_cls, BaseModel)):
            continue
        sub_data: dict[str, Any] = {}
        for field_name, finfo in sub_cls.model_fields.items():
            aliases = [alias.upper() for alias in _aliases_for(finfo)]
            if any(alias in env_present for alias in aliases):
                continue
            for alias in aliases:
                if alias in env_block_upper:
                    sub_data[field_name] = env_block_upper[alias]
                    break
        if sub_data:
            nested[sub_name] = sub_data
    return nested
