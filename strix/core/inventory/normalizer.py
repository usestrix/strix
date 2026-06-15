"""Endpoint normalizer: canonicalize method+URL and record applied rules."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from strix.core.inventory.models import Endpoint, EndpointObservation, Param


_PATH_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_NUMERIC_RE = re.compile(r"^[0-9]+$")
_HASH_RE = re.compile(r"^[0-9a-f]{24,}$", re.I)


def _template_path_segment(segment: str) -> str | None:
    """Return a template placeholder for a path segment if it looks like an ID."""
    if _PATH_ID_RE.match(segment):
        return "{uuid}"
    if _NUMERIC_RE.match(segment) or _HASH_RE.match(segment):
        return "{id}"
    return None


def _normalize_path(path: str) -> tuple[str, list[str]]:
    """Normalize path: collapse repeated slashes, template IDs, strip trailing slash."""
    rules: list[str] = []
    segments = path.split("/")
    templated: list[str] = []
    for segment in segments:
        if segment == "":
            continue
        placeholder = _template_path_segment(segment)
        if placeholder:
            templated.append(placeholder)
            if "path_id_templated" not in rules:
                rules.append("path_id_templated")
        else:
            templated.append(segment)
    normalized = "/" + "/".join(templated)
    if normalized != "/" and normalized.endswith("/"):
        normalized = normalized.rstrip("/")
        rules.append("trailing_slash_removed")
    return normalized, rules


def _normalize_query(query: str) -> tuple[str, list[str]]:
    """Sort query keys and rebuild query string."""
    if not query:
        return "", []
    pairs = sorted(parse_qsl(query, keep_blank_values=True), key=lambda p: p[0])
    return urlencode(pairs), ["query_sorted"]


def _canonical_url(raw_url: str) -> tuple[str, str, list[str]]:
    """Return (canonical_url, endpoint_key, applied_rules)."""
    parsed = urlparse(raw_url)
    rules: list[str] = []

    scheme = parsed.scheme.lower()
    original_netloc = parsed.netloc
    host = (parsed.hostname or "").lower()
    port = parsed.port

    if original_netloc != original_netloc.lower():
        rules.append("host_lowercase")

    default_port = 443 if scheme == "https" else 80
    if port == default_port:
        port = None
        rules.append("default_port_stripped")

    netloc = host if port is None else f"{host}:{port}"

    original_path = parsed.path
    path, path_rules = _normalize_path(original_path)
    rules.extend(path_rules)
    if original_path != "/" and original_path.endswith("/") and not path.endswith("/"):
        rules.append("trailing_slash_removed")

    query, query_rules = _normalize_query(parsed.query)
    rules.extend(query_rules)

    canonical = urlunparse((scheme, netloc, path, "", query, ""))
    key = f"{scheme}://{netloc}{path}"
    return canonical, key, rules


def normalize_observation(obs: EndpointObservation) -> Endpoint:
    """Normalize a single observation into a canonical Endpoint."""
    canonical_url, key, rules = _canonical_url(obs.raw_url)
    endpoint = Endpoint(
        key=key,
        method=obs.method.upper(),
        url=canonical_url,
        sources={obs.source},
        normalization_rules=rules,
    )
    if obs.reachability is not None:
        endpoint.reachability = obs.reachability

    params: dict[str, Param] = {}
    for name, param_obs in obs.params.items():
        params[name] = Param(
            name=param_obs.name,
            location=param_obs.location,
            provenance=set(param_obs.provenance) or {obs.source},
            example_values=set(param_obs.example_values),
        )

    # Also surface query keys from the normalized URL itself.
    parsed = urlparse(canonical_url)
    for name, _ in parse_qsl(parsed.query):
        if name and name not in params:
            params[name] = Param(
                name=name,
                location="query",
                provenance={obs.source},
            )

    endpoint.params = params
    return endpoint


def endpoint_key(method: str, canonical_url: str) -> str:
    """Return the dedup key for a method + canonical URL."""
    parsed = urlparse(canonical_url)
    return f"{method.upper()} {parsed.scheme}://{parsed.netloc}{parsed.path}"


def _merge_param(existing: Param, incoming: Param) -> Param:
    """Merge two params by unioning provenance and example values."""
    return Param(
        name=existing.name,
        location=existing.location,
        provenance=existing.provenance | incoming.provenance,
        example_values=existing.example_values | incoming.example_values,
        class_evidence=existing.class_evidence or incoming.class_evidence,
    )


def _merge_endpoint(existing: Endpoint, incoming: Endpoint) -> Endpoint:
    """Merge two endpoints sharing the same key."""
    existing.sources |= incoming.sources
    existing.normalization_rules = list(
        dict.fromkeys(existing.normalization_rules + incoming.normalization_rules)
    )
    for name, param in incoming.params.items():
        if name in existing.params:
            existing.params[name] = _merge_param(existing.params[name], param)
        else:
            existing.params[name] = param
    return existing


def dedup_observations(observations: list[EndpointObservation]) -> dict[str, Endpoint]:
    """Normalize and merge observations into a deduplicated endpoint map."""
    endpoints: dict[str, Endpoint] = {}
    for obs in observations:
        endpoint = normalize_observation(obs)
        key = endpoint_key(endpoint.method, endpoint.url)
        endpoint.key = key
        if key in endpoints:
            endpoints[key] = _merge_endpoint(endpoints[key], endpoint)
        else:
            endpoints[key] = endpoint
    return endpoints


def dedup_endpoints(endpoints: dict[str, Endpoint]) -> dict[str, Endpoint]:
    """Re-dedup an already-deduped map (idempotence helper)."""
    result: dict[str, Endpoint] = {}
    for endpoint in endpoints.values():
        key = endpoint_key(endpoint.method, endpoint.url)
        if key in result:
            result[key] = _merge_endpoint(result[key], endpoint)
        else:
            result[key] = endpoint
    return result
