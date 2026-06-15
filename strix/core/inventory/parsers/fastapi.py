"""FastAPI route parser: read-only regex extraction of routes and methods."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urljoin

from strix.core.inventory.models import EndpointObservation, ParamObservation


_ROUTE_DECORATOR_RE = re.compile(
    r"@\s*(app|router|api_router|router_[A-Za-z0-9_]+)\s*"
    r"\.(get|post|put|delete|patch|head|options)\s*\(\s*"
    r"['\"]([^'\"]+)['\"]",
    re.IGNORECASE | re.MULTILINE,
)


_ROUTER_PREFIX_RE = re.compile(
    r"(\w+)\s*=\s*APIRouter\s*\([^)]*prefix\s*=\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)


_METHODS_ORDER = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


def _extract_router_prefixes(source: str) -> dict[str, str]:
    """Map router variable names to their prefixes within a source file."""
    return {match.group(1): match.group(2) for match in _ROUTER_PREFIX_RE.finditer(source)}


def _extract_route_decorators(source: str) -> list[tuple[str, str, str, str]]:
    """Return (router_name, method, original_path, prefixed_path) pairs."""
    prefixes = _extract_router_prefixes(source)
    found: list[tuple[str, str, str, str]] = []
    for match in _ROUTE_DECORATOR_RE.finditer(source):
        router_name = match.group(1).lower()
        method = match.group(2).upper()
        original_path = match.group(3)
        prefix = prefixes.get(router_name, "")
        prefixed_path = original_path
        if prefix:
            prefixed_path = f"{prefix.rstrip('/')}/{original_path.lstrip('/')}"
        if method in _METHODS_ORDER:
            found.append((router_name, method, original_path, prefixed_path))
    return found


def _path_params(path: str) -> dict[str, ParamObservation]:
    """Extract ``{param_name}`` path parameters."""
    params: dict[str, ParamObservation] = {}
    for match in re.finditer(r"\{([A-Za-z0-9_]+)\}", path):
        name = match.group(1)
        params[name] = ParamObservation(name=name, location="path")
    return params


def collect_routes(
    source_path: str | Path,
    *,
    base_url: str = "http://example.com",
) -> list[EndpointObservation]:
    """Collect FastAPI routes from a source tree without executing code."""
    path = Path(source_path)
    observations: list[EndpointObservation] = []
    seen: set[str] = set()
    files = [path] if path.is_file() and path.suffix == ".py" else list(path.rglob("*.py"))

    for file_path in files:
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for _router_name, method, original_path, route_path in _extract_route_decorators(source):
            url = urljoin(base_url.rstrip("/") + "/", route_path.lstrip("/"))
            key = f"{method} {url}"
            if key in seen:
                continue
            seen.add(key)
            rel_file = str(file_path.relative_to(path)) if path.is_dir() else file_path.name
            observations.append(
                EndpointObservation(
                    method=method,
                    raw_url=url,
                    params=_path_params(route_path),
                    source="code",
                    raw_evidence={
                        "file": rel_file,
                        "method": method,
                        "route_path": original_path,
                        "source_text": source,
                    },
                ),
            )
    return observations
