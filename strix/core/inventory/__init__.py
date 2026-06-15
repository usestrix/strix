"""Unified attack-surface inventory core."""

from __future__ import annotations

from strix.core.inventory.classify import (
    agent_classify_param,
    classify_endpoint,
    classify_param,
)
from strix.core.inventory.collectors import (
    collect_arjun,
    collect_code,
    collect_ffuf,
    collect_httpx,
    collect_js,
    collect_katana,
    collect_sitemap,
)
from strix.core.inventory.extractors import (
    extract_form_params,
    extract_js_params,
    extract_openapi_params,
    extract_proxy_params,
    merge_extracted_params,
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
from strix.core.inventory.parsers.reachability import (
    ReachabilityResult,
    analyze_handler,
    analyze_source_tree,
    annotate_reachability,
)
from strix.core.inventory.scoring import build_ranked_map, score_endpoint, score_signals
from strix.core.inventory.spray import (
    all_classes,
    spray_values_for,
    spray_values_for_param,
)
from strix.core.inventory.store import load_ranked_map, save_ranked_map


__all__ = [
    "Endpoint",
    "EndpointObservation",
    "Param",
    "ParamClassEvidence",
    "ParamObservation",
    "RankedSurfaceMap",
    "ReachabilityAnnotation",
    "ReachabilityResult",
    "agent_classify_param",
    "all_classes",
    "analyze_handler",
    "analyze_source_tree",
    "annotate_reachability",
    "build_ranked_map",
    "classify_endpoint",
    "classify_param",
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
    "extract_form_params",
    "extract_js_params",
    "extract_openapi_params",
    "extract_proxy_params",
    "load_ranked_map",
    "merge_extracted_params",
    "normalize_observation",
    "save_ranked_map",
    "score_endpoint",
    "score_signals",
    "spray_values_for",
    "spray_values_for_param",
]
