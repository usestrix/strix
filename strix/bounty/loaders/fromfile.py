"""Load a bug-bounty program from a saved file — the offline, no-token path.

When the platform API is unavailable (no token, air-gapped, CI without secrets) the
operator pastes a program's published scope and rules into a JSON or YAML file
shaped like :class:`~strix.bounty.schema.BountyProgram` and points bounty mode at it.
This is also how a program fetched live can be cached and re-used deterministically.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from pydantic import ValidationError

from strix.bounty.loaders.errors import BountyLoadError
from strix.bounty.schema import BountyProgram


if TYPE_CHECKING:
    from collections.abc import Mapping


def load_program_file(path: str | Path) -> BountyProgram:
    """Load and validate a program policy from ``path`` (``.json`` / ``.yaml``)."""
    source = Path(path).expanduser()
    if not source.is_file():
        raise BountyLoadError(f"bounty program file not found: {source}")
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise BountyLoadError(f"could not read bounty program file {source}: {exc}") from exc

    try:
        raw = json.loads(text) if source.suffix.lower() == ".json" else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise BountyLoadError(f"could not parse bounty program file {source}: {exc}") from exc

    return program_from_mapping(raw, source=str(source))


def program_from_mapping(raw: object, *, source: str = "<data>") -> BountyProgram:
    """Validate an already-decoded mapping into a :class:`BountyProgram`."""
    if not isinstance(raw, dict):
        kind = type(raw).__name__
        raise BountyLoadError(f"bounty program {source} must be a mapping, got {kind}")
    mapping: Mapping[str, object] = raw
    try:
        return BountyProgram.model_validate(mapping)
    except ValidationError as exc:
        raise BountyLoadError(f"invalid bounty program in {source}:\n{exc}") from exc
