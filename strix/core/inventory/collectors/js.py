"""JS route collector: turns discovered JS route hints into observations."""

from __future__ import annotations

from urllib.parse import urljoin

from strix.core.inventory.collectors._scope import host_in_scope
from strix.core.inventory.models import EndpointObservation


def _route_path_to_url(path: str, base_url: str) -> str | None:
    """Join a route path with a base URL."""
    path = path.strip()
    if not path:
        return None
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def collect_js(
    route_hints: list[str],
    *,
    base_url: str = "http://example.com",
    scope_rules: list[str] | None = None,
) -> list[EndpointObservation]:
    """Convert JS-discovered route hints into GET observations.

    Args:
        route_hints: Route paths or full URLs discovered in JS.
        base_url: Base URL to join relative paths against.
        scope_rules: Optional host allowlist.

    Returns:
        One GET observation per in-scope, unique route.
    """
    seen: set[str] = set()
    observations: list[EndpointObservation] = []
    for hint in route_hints:
        url = _route_path_to_url(hint, base_url)
        if url is None or not host_in_scope(url, scope_rules) or url in seen:
            continue
        seen.add(url)
        observations.append(
            EndpointObservation(
                method="GET",
                raw_url=url,
                source="js",
                raw_evidence={"route_hint": hint},
                scope_rules=scope_rules,
            ),
        )
    return observations
