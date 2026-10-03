"""Bug-bounty program loaders: a file, or a live platform API.

:func:`load_program` is the one entry point the rest of bounty mode calls. It takes a
spec that is either a path to a saved program file or ``platform:handle`` for a live
pull, routes to the right loader, and optionally overlays a rules-of-engagement file
(the machine-readable ROE the platform APIs do not expose).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from pydantic import ValidationError

from strix.bounty.loaders import bugcrowd, hackerone
from strix.bounty.loaders.errors import BountyLoadError
from strix.bounty.loaders.fromfile import load_program_file, program_from_mapping
from strix.bounty.schema import BountyProgram, RulesOfEngagement


if TYPE_CHECKING:
    from collections.abc import Mapping

_PLATFORM_ALIASES = {
    "hackerone": "hackerone",
    "h1": "hackerone",
    "bugcrowd": "bugcrowd",
    "bc": "bugcrowd",
}


def _looks_like_platform_spec(spec: str) -> bool:
    prefix, sep, rest = spec.partition(":")
    return bool(sep) and prefix.lower() in _PLATFORM_ALIASES and bool(rest.strip())


def apply_roe_overrides(program: BountyProgram, roe_path: str | Path) -> BountyProgram:
    """Overlay a rules-of-engagement file onto ``program``'s ROE and return a copy.

    Only keys present in the file are changed; everything else is kept. The file is
    JSON or YAML with the fields of :class:`~strix.bounty.schema.RulesOfEngagement`.
    """
    source = Path(roe_path).expanduser()
    if not source.is_file():
        raise BountyLoadError(f"rules-of-engagement file not found: {source}")
    try:
        text = source.read_text(encoding="utf-8")
        raw = json.loads(text) if source.suffix.lower() == ".json" else yaml.safe_load(text)
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise BountyLoadError(f"could not read ROE file {source}: {exc}") from exc
    if not isinstance(raw, dict):
        raise BountyLoadError(f"ROE file {source} must be a mapping")
    overrides: Mapping[str, object] = raw
    base = program.roe.model_dump()
    base.update(overrides)
    try:
        merged = RulesOfEngagement.model_validate(base)
    except ValidationError as exc:
        raise BountyLoadError(f"invalid ROE override in {source}: {exc}") from exc
    return program.model_copy(update={"roe": merged})


def load_program(
    spec: str,
    *,
    hackerone_username: str | None = None,
    hackerone_token: str | None = None,
    bugcrowd_token: str | None = None,
    roe_path: str | Path | None = None,
) -> BountyProgram:
    """Load a program from a file path or a ``platform:handle`` live spec."""
    if _looks_like_platform_spec(spec):
        prefix, _, handle = spec.partition(":")
        platform = _PLATFORM_ALIASES[prefix.lower()]
        handle = handle.strip()
        if platform == "hackerone":
            if not (hackerone_username and hackerone_token):
                raise BountyLoadError(
                    "HackerOne live pull needs an API identifier and token "
                    "(set HACKERONE_API_USERNAME and HACKERONE_API_TOKEN, or load from a file)."
                )
            program = hackerone.fetch_program(
                handle, api_username=hackerone_username, api_token=hackerone_token
            )
        else:
            if not bugcrowd_token:
                raise BountyLoadError(
                    "Bugcrowd live pull needs an API token "
                    "(set BUGCROWD_API_TOKEN, or load from a file)."
                )
            program = bugcrowd.fetch_program(handle, api_token=bugcrowd_token)
    else:
        program = load_program_file(spec)

    if roe_path is not None:
        program = apply_roe_overrides(program, roe_path)
    return program


__all__ = [
    "BountyLoadError",
    "apply_roe_overrides",
    "load_program",
    "load_program_file",
    "program_from_mapping",
]
