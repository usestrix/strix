"""FastAPI route parser: read-only regex extraction of routes and methods."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urljoin

from strix.core.inventory.models import EndpointObservation, ParamObservation


_ROUTE_DECORATOR_RE = re.compile(
    r"@\s*(?:app|router|api_router|router_[A-Za-z0-9_]+)\s*"
    r"\.(get|post|put|delete|patch|head|options)\s*\(\s*"
    r"['\"]([^'\"]+)['\"]",
    re.IGNORECASE | re.MULTILINE,
)


_METHODS_ORDER = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


def _extract_route_decorators(source: str) -> list[tuple[str, str]]:
    """Return (method, path) pairs from a FastAPI source file."""
    found: list[tuple[str, str]] = []
    for match in _ROUTE_DECORATOR_RE.finditer(source):
        method = match.group(1).upper()
        path = match.group(2)
        if method in _METHODS_ORDER:
            found.append((method, path))
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
        for method, route_path in _extract_route_decorators(source):
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
                        "route_path": route_path,
                    },
                ),
            )
    return observations
