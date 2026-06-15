"""Scoring and ranked-map builder for the unified inventory."""

from __future__ import annotations

from strix.core.inventory.models import Endpoint, RankedSurfaceMap


_SIGNAL_WEIGHTS = {
    "auth-required": 2.0,
    "object-ref": 2.0,
    "state-changing-verb": 1.5,
    "upload": 1.5,
    "source-multiplicity": 1.0,
    "reachable-sink": 2.5,
}

_BASE_SCORE = 1.0


def _has_auth_signal(endpoint: Endpoint) -> bool:
    """Detect an authentication-related signal."""
    path = endpoint.url.lower()
    if any(token in path for token in ("auth", "login", "token", "session")):
        return True
    for param in endpoint.params.values():
        if param.name.lower() in {"authorization", "cookie", "token"}:
            return True
    return False


def _has_object_ref_signal(endpoint: Endpoint) -> bool:
    """Detect object-reference signal (path/query IDs or templated IDs)."""
    if "{id}" in endpoint.url or "{uuid}" in endpoint.url:
        return True
    for param in endpoint.params.values():
        if param.location in {"path", "query"} and param.name.lower() in {
            "id",
            "user_id",
            "item_id",
            "uuid",
        }:
            return True
    return False


def _has_state_changing_verb(endpoint: Endpoint) -> bool:
    """Detect state-changing HTTP method."""
    return endpoint.method in {"POST", "PUT", "PATCH", "DELETE"}


def _has_upload_signal(endpoint: Endpoint) -> bool:
    """Detect upload/file-handling signal."""
    path = endpoint.url.lower()
    if any(token in path for token in ("upload", "file", "import")):
        return True
    for param in endpoint.params.values():
        if param.name.lower() in {"file", "filename", "upload"}:
            return True
    return False


def _has_source_multiplicity(endpoint: Endpoint) -> bool:
    """Multiple sources found the same endpoint."""
    return len(endpoint.sources) > 1


def _has_reachable_sink(endpoint: Endpoint) -> bool:
    """White-box reachability marked a sink as reachable."""
    return endpoint.reachability is not None and endpoint.reachability.status == "reachable"


def extract_signals(endpoint: Endpoint) -> set[str]:
    """Return the fixed attack-surface signal set for an endpoint."""
    signals: set[str] = set()
    if _has_auth_signal(endpoint):
        signals.add("auth-required")
    if _has_object_ref_signal(endpoint):
        signals.add("object-ref")
    if _has_state_changing_verb(endpoint):
        signals.add("state-changing-verb")
    if _has_upload_signal(endpoint):
        signals.add("upload")
    if _has_source_multiplicity(endpoint):
        signals.add("source-multiplicity")
    if _has_reachable_sink(endpoint):
        signals.add("reachable-sink")
    return signals


def score_signals(signals: set[str]) -> float:
    """Monotonic score over the fixed signal set."""
    return _BASE_SCORE + sum(_SIGNAL_WEIGHTS[s] for s in signals if s in _SIGNAL_WEIGHTS)


def score_endpoint(endpoint: Endpoint) -> float:
    """Score a single endpoint by its signals."""
    signals = extract_signals(endpoint)
    endpoint.signals = sorted(signals)
    endpoint.score = score_signals(signals)
    return endpoint.score


def build_ranked_map(target_id: str, endpoints: dict[str, Endpoint]) -> RankedSurfaceMap:
    """Attach scores and return a ranked surface map."""
    for endpoint in endpoints.values():
        score_endpoint(endpoint)
    return RankedSurfaceMap(target_id=target_id, endpoints=endpoints)
