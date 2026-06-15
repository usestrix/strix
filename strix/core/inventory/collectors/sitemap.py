"""Sitemap collector: turns Caido sitemap entries into EndpointObservations."""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import urljoin

from strix.core.inventory.collectors._scope import host_in_scope
from strix.core.inventory.models import EndpointObservation, ParamObservation


def _host_from_entry(entry: dict[str, Any]) -> str | None:
    """Derive host from a Caido sitemap entry when possible."""
    kind = entry.get("kind")
    label = cast("str | None", entry.get("label"))
    if kind == "DOMAIN" and label:
        return label
    return None


def _entry_url(entry: dict[str, Any], host: str) -> str | None:
    """Reconstruct a URL from a cleaned sitemap entry and host context."""
    request = entry.get("request") or {}
    path = request.get("path")
    if not path or not host:
        return None

    metadata = entry.get("metadata") or {}
    is_tls = metadata.get("is_tls", False)
    port = metadata.get("port")
    scheme = "https" if is_tls else "http"

    default_port = 443 if is_tls else 80
    netloc = f"{host}:{port}" if port and port != default_port else host
    base = f"{scheme}://{netloc}"
    return cast("str | None", urljoin(base, path))


def collect_sitemap(
    entries: list[dict[str, Any]],
    *,
    default_host: str | None = None,
    scope_rules: list[str] | None = None,
) -> list[EndpointObservation]:
    """Convert cleaned Caido sitemap entries into observations.

    Args:
        entries: Cleaned sitemap entries (from ``caido_api._clean_sitemap_*``).
        default_host: Fallback host for non-domain entries.
        scope_rules: Optional host allowlist.

    Returns:
        One observation per in-scope request entry.
    """
    observations: list[EndpointObservation] = []
    for entry in entries:
        request = entry.get("request") or {}
        method = request.get("method")
        path = request.get("path")
        if not method or not path:
            continue

        host = _host_from_entry(entry) or default_host
        if not host:
            continue

        url = _entry_url(entry, host)
        if url is None or not host_in_scope(url, scope_rules):
            continue

        params: dict[str, ParamObservation] = {}
        # Surface query keys (without values) as observed param names.
        if "?" in path:
            query_part = path.split("?", 1)[1]
            for raw_key in query_part.split("&"):
                key = raw_key.split("=", 1)[0] if "=" in raw_key else raw_key
                if key and key not in params:
                    params[key] = ParamObservation(
                        name=key,
                        location="query",
                        provenance=["sitemap"],
                    )

        observations.append(
            EndpointObservation(
                method=method,
                raw_url=url,
                params=params,
                source="sitemap",
                raw_evidence={
                    "id": entry.get("id"),
                    "kind": entry.get("kind"),
                    "status_code": request.get("status_code"),
                },
                scope_rules=scope_rules,
            ),
        )
    return observations
