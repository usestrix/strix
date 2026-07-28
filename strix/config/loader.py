"""Settings loader, override switch, and disk persistence."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import AliasChoices, BaseModel

from strix.config.settings import Settings


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
    for sub_name in s.model_fields:
        sub_model = getattr(s, sub_name)
        if not isinstance(sub_model, BaseModel):
            continue
        for finfo in type(sub_model).model_fields.values():
            for alias in _aliases_for(finfo):
                value = os.environ.get(alias.upper())
                if value:
                    env_block[alias.upper()] = value
                    break

    payload = json.dumps({"env": env_block}, indent=2)
    atomic_write_secure(target, payload)


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

def atomic_write_secure(target: "Path", payload: str) -> None:
    """Atomically write *payload* to *target* with mode 0o600.

    Guarantees:
      1. Sensitive content is NEVER observable with mode != 0o600.
      2. A crash leaves either the old file or the new file, never a
         half-written file.
      3. Concurrent readers see either old or new contents, never torn reads.
      4. O_NOFOLLOW defends against a pre-planted symlink at the tmp path.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target.with_name(f"{target.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        fd = os.open(
            tmp_path,
            flags=os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            mode=0o600,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            # os.fdopen takes ownership; suppress in case it failed before taking fd
            with contextlib.suppress(OSError):
                os.close(fd)
            raise
        os.replace(tmp_path, target)
        # Belt-and-suspenders: enforce mode in case os.replace inherited anything odd
        target.chmod(0o600)
    finally:
        with contextlib.suppress(OSError):
            tmp_path.unlink()


def _read_json_overrides(path: Path) -> dict[str, dict[str, Any]]:
    """Read ``{"env": {...}}`` from ``path`` and remap to nested kwargs.

    Only includes keys whose env var is NOT already set, so env always
    wins over the persisted file.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    env_block = data.get("env", {}) if isinstance(data, dict) else {}
    if not isinstance(env_block, dict):
        return {}

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
