"""Unified attack-surface inventory core."""

from __future__ import annotations

from strix.core.inventory.collectors import (
    collect_arjun,
    collect_code,
    collect_ffuf,
    collect_httpx,
    collect_js,
    collect_katana,
    collect_sitemap,
)
from strix.core.inventory.models import (
    Endpoint,
    EndpointObservation,
    Param,
    ParamClassEvidence,
    ParamObservation,
    RankedSurfaceMap,
    ReachabilityAnnotation,
)
from strix.core.inventory.normalizer import (
    dedup_endpoints,
    dedup_observations,
    endpoint_key,
    normalize_observation,
)


__all__ = [
    "Endpoint",
    "EndpointObservation",
    "Param",
    "ParamClassEvidence",
    "ParamObservation",
    "RankedSurfaceMap",
    "ReachabilityAnnotation",
    "collect_arjun",
    "collect_code",
    "collect_ffuf",
    "collect_httpx",
    "collect_js",
    "collect_katana",
    "collect_sitemap",
    "dedup_endpoints",
    "dedup_observations",
    "endpoint_key",
    "normalize_observation",
]
