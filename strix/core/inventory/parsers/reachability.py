"""P4 reachability seam: classify route handlers as reachable/unreachable/unknown sinks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from strix.core.inventory.models import (
    EndpointObservation,
    ReachabilityAnnotation,
    ReachabilityStatus,
)
from strix.core.inventory.parsers.fastapi import _extract_route_decorators


_SINK_PATTERNS = {
    "database": [
        r"\.execute\s*\(",
        r"\.query\s*\(",
        r"session\.exec\s*\(",
        r"\.fetchone\s*\(",
        r"\.fetchall\s*\(",
        r"\.insert\s*\(",
        r"\.update\s*\(",
        r"\.delete\s*\(",
    ],
    "file": [
        r"\bopen\s*\(",
        r"\.write\s*\(",
        r"\.read\s*\(",
        r"pathlib\.Path\s*\(",
    ],
    "os_command": [
        r"\bos\.system\s*\(",
        r"\bsubprocess\.run\s*\(",
        r"\bsubprocess\.call\s*\(",
        r"\beval\s*\(",
        r"\bexec\s*\(",
    ],
    "ssrf": [
        r"\brequests\.(?:get|post|put|delete|patch)\s*\(",
        r"\bhttpx\.(?:get|post|put|delete|patch)\s*\(",
        r"\burllib\.request\.urlopen\s*\(",
    ],
}


_AUTH_PATTERNS = [
    r"\bDepends\s*\(",
    r"get_current_user",
    r"require_auth",
    r"require_admin",
]


def _handler_body(source: str, decorator_offset: int) -> str | None:
    """Extract the function signature and body that follows a route decorator."""
    after_decorator = source[decorator_offset:]
    lines = after_decorator.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("def "):
            body_lines = lines[i:]
            stop = len(body_lines)
            for j, body_line in enumerate(body_lines[1:], start=1):
                if (
                    body_line
                    and not body_line.startswith((" ", "\t"))
                    and body_line.startswith(("@", "def ", "class "))
                ):
                    stop = j
                    break
            return "\n".join(body_lines[:stop])
    return None


@dataclass(frozen=True)
class ReachabilityResult:
    """Result of analyzing a single route handler for sink reachability."""

    status: str
    sinks: list[str]
    auth_required: bool


def analyze_handler(source: str, decorator_offset: int) -> ReachabilityResult:
    """Analyze a route handler body for reachable sinks and auth requirements."""
    body = _handler_body(source, decorator_offset)
    if body is None:
        return ReachabilityResult(status="unknown", sinks=[], auth_required=False)

    stripped = body.strip()
    if not stripped:
        return ReachabilityResult(status="unreachable", sinks=[], auth_required=False)

    sinks: list[str] = []
    for sink_name, patterns in _SINK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, body):
                sinks.append(sink_name)
                break

    auth_required = any(re.search(pattern, body) for pattern in _AUTH_PATTERNS)

    status = "reachable" if sinks else "unreachable"
    return ReachabilityResult(status=status, sinks=sinks, auth_required=auth_required)


def annotate_reachability(observations: list[EndpointObservation]) -> list[EndpointObservation]:
    """Attach reachability annotations to code-sourced observations in place."""
    for obs in observations:
        raw_evidence = obs.raw_evidence or {}
        source_text = raw_evidence.get("source_text") or ""
        if not source_text:
            obs.reachability = ReachabilityAnnotation(status="unknown")
            continue
        # Re-locate the decorator in the source text.
        route_path = raw_evidence.get("route_path", "")
        method = raw_evidence.get("method", "")
        decorator_match = re.search(
            rf"@\s*(?:app|router|api_router|router_[A-Za-z0-9_]+)\s*\.{method.lower()}\s*\(\s*['\"]{re.escape(route_path)}['\"]",
            source_text,
            re.IGNORECASE,
        )
        if not decorator_match:
            obs.reachability = ReachabilityAnnotation(status="unknown")
            continue
        result = analyze_handler(source_text, decorator_match.start())
        obs.reachability = ReachabilityAnnotation(
            status=cast("ReachabilityStatus", result.status),
            path=result.sinks,
        )
    return observations


def analyze_source_tree(source_path: str | Path) -> dict[str, ReachabilityResult]:
    """Map route keys to reachability results for a whole source tree."""
    path = Path(source_path)
    results: dict[str, ReachabilityResult] = {}
    if not path.exists():
        return results

    files = [path] if path.is_file() and path.suffix == ".py" else list(path.rglob("*.py"))
    for file_path in files:
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for _router_name, method, _original_path, route_path in _extract_route_decorators(source):
            key = f"{method} {route_path}"
            if key not in results:
                match = re.search(
                    rf"@\s*(?:app|router|api_router|router_[A-Za-z0-9_]+)\s*\.{method.lower()}\s*\(\s*['\"]{re.escape(_original_path)}['\"]",
                    source,
                    re.IGNORECASE,
                )
                if match:
                    results[key] = analyze_handler(source, match.start())
    return results
