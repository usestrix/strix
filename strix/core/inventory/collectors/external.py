"""External-tool collectors: parse ffuf/katana/arjun/httpx output offline."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl, urlparse

from strix.core.inventory.collectors._scope import host_in_scope
from strix.core.inventory.models import EndpointObservation, ParamObservation


def _parse_jsonl(text: str) -> list[dict[str, Any]]:
    """Parse newline-delimited JSON, skipping blank/invalid lines."""
    records: list[dict[str, Any]] = []
    for raw_line in text.strip().splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            records.append(parsed)
    return records


def _url_method_from_record(
    record: dict[str, Any], *, default_method: str = "GET"
) -> tuple[str | None, str]:
    """Extract URL and method from a JSON record."""
    url = record.get("url")
    if not url:
        return None, default_method
    method = str(record.get("method", default_method)).upper()
    return str(url), method


def _query_params(url: str) -> dict[str, ParamObservation]:
    """Extract query param names from a URL."""
    params: dict[str, ParamObservation] = {}
    for name, _ in parse_qsl(urlparse(url).query):
        if name and name not in params:
            params[name] = ParamObservation(name=name, location="query")
    return params


def collect_ffuf(
    output_text: str,
    *,
    scope_rules: list[str] | None = None,
) -> list[EndpointObservation]:
    """Parse ffuf JSON output into observations.

    Expects the ``-json`` output shape with a top-level ``results`` list.
    """
    observations: list[EndpointObservation] = []
    try:
        data = json.loads(output_text)
    except json.JSONDecodeError:
        return observations
    if not isinstance(data, dict):
        return observations
    results = data.get("results", [])
    if not isinstance(results, list):
        return observations
    seen: set[str] = set()
    for item in results:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not url or not host_in_scope(str(url), scope_rules) or url in seen:
            continue
        seen.add(url)
        method = str(item.get("method", "GET")).upper()
        observations.append(
            EndpointObservation(
                method=method,
                raw_url=str(url),
                params=_query_params(str(url)),
                source="ffuf",
                raw_evidence={
                    "status": item.get("status"),
                    "length": item.get("length"),
                    "words": item.get("words"),
                },
                scope_rules=scope_rules,
            ),
        )
    return observations


def collect_katana(
    output_text: str,
    *,
    scope_rules: list[str] | None = None,
) -> list[EndpointObservation]:
    """Parse katana JSONL output into observations."""
    observations: list[EndpointObservation] = []
    seen: set[str] = set()
    for record in _parse_jsonl(output_text):
        url, method = _url_method_from_record(record)
        if url is None or not host_in_scope(url, scope_rules) or url in seen:
            continue
        seen.add(url)
        observations.append(
            EndpointObservation(
                method=method,
                raw_url=url,
                params=_query_params(url),
                source="katana",
                raw_evidence={
                    "source": record.get("source"),
                    "tag": record.get("tag"),
                },
                scope_rules=scope_rules,
            ),
        )
    return observations


def collect_arjun(
    output_text: str,
    *,
    scope_rules: list[str] | None = None,
) -> list[EndpointObservation]:
    """Parse arjun JSON output into observations.

    Expects a JSON object mapping URLs to discovered parameters.
    """
    observations: list[EndpointObservation] = []
    try:
        data = json.loads(output_text)
    except json.JSONDecodeError:
        return observations
    if not isinstance(data, dict):
        return observations
    seen: set[str] = set()
    for url, params_raw in data.items():
        if not isinstance(url, str) or not host_in_scope(url, scope_rules) or url in seen:
            continue
        seen.add(url)
        params: dict[str, ParamObservation] = {}
        if isinstance(params_raw, list):
            for name in params_raw:
                if isinstance(name, str) and name:
                    params[name] = ParamObservation(name=name, location="query")
        observations.append(
            EndpointObservation(
                method="GET",
                raw_url=url,
                params=params,
                source="arjun",
                raw_evidence={"parameter_count": len(params)},
                scope_rules=scope_rules,
            ),
        )
    return observations


def collect_httpx(
    output_text: str,
    *,
    scope_rules: list[str] | None = None,
) -> list[EndpointObservation]:
    """Parse httpx JSONL output into observations."""
    observations: list[EndpointObservation] = []
    seen: set[str] = set()
    for record in _parse_jsonl(output_text):
        url, method = _url_method_from_record(record)
        if url is None or not host_in_scope(url, scope_rules) or url in seen:
            continue
        seen.add(url)
        observations.append(
            EndpointObservation(
                method=method,
                raw_url=url,
                params=_query_params(url),
                source="httpx",
                raw_evidence={
                    "status_code": record.get("status_code"),
                    "title": record.get("title"),
                },
                scope_rules=scope_rules,
            ),
        )
    return observations
