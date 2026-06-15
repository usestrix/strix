"""Code-route collector entry point (white-box)."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from strix.core.inventory.collectors._scope import host_in_scope
from strix.core.inventory.parsers import fastapi


if TYPE_CHECKING:
    from strix.core.inventory.models import EndpointObservation


def collect_code(
    source_path: str | Path,
    *,
    base_url: str = "http://example.com",
    scope_rules: list[str] | None = None,
) -> list[EndpointObservation]:
    """Extract route observations from a cloned source tree.

    Currently supports FastAPI only; other stacks fall through to an
    empty list (no error) as required by the Phase 3 scope amendment.

    Args:
        source_path: Path to the cloned repository or local code.
        base_url: Base URL to join relative routes against.
        scope_rules: Optional host allowlist.

    Returns:
        In-scope code observations, or an empty list for unrecognized stacks.
    """
    path = Path(source_path)
    if not path.exists():
        return []
    observations = fastapi.collect_routes(path, base_url=base_url)
    return [obs for obs in observations if host_in_scope(obs.raw_url, scope_rules)]
