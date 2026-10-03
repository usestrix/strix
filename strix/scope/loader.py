"""Load and validate ``scope.yaml`` into a :class:`ScopePolicy`.

Unlike the MCP loader (which is fail-open, since a missing MCP server just means
fewer tools), scope loading is **fail-closed by contract**: a malformed policy
raises rather than silently authorizing nothing-or-everything, and a missing file
returns ``None`` so the caller can decide the safe default for its domain (Phase 1
wiring treats ``None`` as "no authorization on record" for the new intrusive
domains). The resolution order is: explicit path → ``$STRIX_SCOPE_CONFIG`` → the
first of ``scope.yaml`` / ``.strix/scope.yaml`` found from ``cwd`` → ``None``.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import yaml
from pydantic import ValidationError

from strix.scope.schema import ScopePolicy


logger = logging.getLogger(__name__)

_PATH_ENV_VAR = "STRIX_SCOPE_CONFIG"
DEFAULT_SCOPE_FILENAMES: tuple[str, ...] = ("scope.yaml", "scope.yml", ".strix/scope.yaml")


class ScopeConfigError(RuntimeError):
    """Raised when a scope file exists but cannot be read or validated."""


def _resolve_path(path: str | Path | None, *, search_from: Path) -> Path | None:
    if path is not None:
        return Path(path).expanduser()
    override = os.environ.get(_PATH_ENV_VAR)
    if override:
        return Path(override).expanduser()
    for name in DEFAULT_SCOPE_FILENAMES:
        candidate = search_from / name
        if candidate.is_file():
            return candidate
    return None


def load_scope_policy(
    path: str | Path | None = None,
    *,
    search_from: str | Path | None = None,
) -> ScopePolicy | None:
    """Load the scope policy, or ``None`` when no scope file is present.

    Raises :class:`ScopeConfigError` when a file exists but is unreadable, is not a
    YAML mapping, or fails schema validation — an authorization document that is
    present-but-wrong must never be treated as "no restrictions".
    """
    base = Path(search_from).expanduser() if search_from is not None else Path.cwd()
    source = _resolve_path(path, search_from=base)
    if source is None:
        return None
    if not source.is_file():
        # An explicitly named path that does not exist is an error, not "no scope".
        raise ScopeConfigError(f"scope file not found: {source}")

    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ScopeConfigError(f"could not read scope file {source}: {exc}") from exc

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        kind = type(raw).__name__
        raise ScopeConfigError(f"scope file {source} must be a YAML mapping, got {kind}")

    try:
        policy = ScopePolicy.model_validate(raw)
    except ValidationError as exc:
        raise ScopeConfigError(f"invalid scope policy in {source}:\n{exc}") from exc

    logger.info(
        "Loaded scope policy from %s (allow_intrusive=%s, web=%d, network hosts=%d/cidrs=%d, "
        "cloud aws=%d)",
        source,
        policy.allow_intrusive,
        len(policy.web.domains),
        len(policy.network.hosts),
        len(policy.network.cidrs),
        len(policy.cloud.aws_account_ids),
    )
    return policy
