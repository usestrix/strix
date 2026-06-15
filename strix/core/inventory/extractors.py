"""Parameter extraction from proxy, OpenAPI, JS, and form sources."""

from __future__ import annotations

import json
import re
from typing import Any, cast
from urllib.parse import parse_qsl

from strix.core.inventory.models import ParamLocation, ParamObservation


_PARAM_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_\-\[\]]*$")


def _is_valid_param_name(name: str) -> bool:
    """Reject noise like JSONP callbacks or minified garbage."""
    return bool(_PARAM_NAME_RE.match(name)) and len(name) <= 128


def _add_value(obs: ParamObservation, value: str) -> None:
    if value not in obs.example_values:
        obs.example_values.append(value)


def _query_params_from_string(qs: str, source: str, params: dict[str, ParamObservation]) -> None:
    for name, value in parse_qsl(qs, keep_blank_values=True):
        if _is_valid_param_name(name):
            obs = params.setdefault(
                name,
                ParamObservation(name=name, location="query", provenance=[source]),
            )
            _add_value(obs, value)


def _body_params_from_string(body: str, source: str, params: dict[str, ParamObservation]) -> None:
    for name, value in parse_qsl(body, keep_blank_values=True):
        if _is_valid_param_name(name):
            obs = params.setdefault(
                name,
                ParamObservation(name=name, location="body", provenance=[source]),
            )
            _add_value(obs, value)


def _body_params_from_dict(
    body: dict[str, Any],
    source: str,
    params: dict[str, ParamObservation],
) -> None:
    for name, value in body.items():
        if _is_valid_param_name(name):
            obs = params.setdefault(
                name,
                ParamObservation(name=name, location="body", provenance=[source]),
            )
            value_str = json.dumps(value) if isinstance(value, (dict, list)) else str(value)
            _add_value(obs, value_str)


def _header_params(
    headers: dict[str, Any],
    source: str,
    params: dict[str, ParamObservation],
) -> None:
    for header, value in headers.items():
        if _is_valid_param_name(header):
            obs = params.setdefault(
                header,
                ParamObservation(name=header, location="header", provenance=[source]),
            )
            _add_value(obs, str(value))


def extract_proxy_params(
    records: list[dict[str, Any]],
    source: str = "proxy",
) -> dict[str, ParamObservation]:
    """Extract parameters from proxy request/response records."""
    params: dict[str, ParamObservation] = {}
    for record in records:
        request: dict[str, Any] = record.get("request") or {}
        url = request.get("url", "")
        if isinstance(url, str) and "?" in url:
            _query_params_from_string(url.split("?", 1)[1], source, params)

        _header_params(request.get("headers") or {}, source, params)

        body = request.get("body")
        if isinstance(body, dict):
            _body_params_from_dict(body, source, params)
        elif isinstance(body, str) and body:
            _body_params_from_string(body, source, params)

    return params


def extract_openapi_params(
    spec: dict[str, Any],
    source: str = "openapi",
) -> dict[str, ParamObservation]:
    """Extract parameters from an OpenAPI document."""
    params: dict[str, ParamObservation] = {}
    for path_item in spec.get("paths", {}).values():
        if not isinstance(path_item, dict):
            continue
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            for param in operation.get("parameters", []):
                if not isinstance(param, dict):
                    continue
                name = param.get("name")
                location = param.get("in")
                if name and location and _is_valid_param_name(name):
                    location = location.lower()
                    if location not in {"query", "header", "path", "body", "formdata"}:
                        location = "query"
                    if name not in params:
                        params[name] = ParamObservation(
                            name=name,
                            location=cast("ParamLocation", location),
                            provenance=[source],
                        )
    return params


def _extract_js_query_params(
    source: str,
    source_tag: str,
    params: dict[str, ParamObservation],
) -> None:
    for match in re.finditer(r"[?&]([a-zA-Z_][a-zA-Z0-9_]*)=", source):
        name = match.group(1)
        if _is_valid_param_name(name) and name not in params:
            params[name] = ParamObservation(name=name, location="query", provenance=[source_tag])


def _extract_js_form_data_params(
    source: str,
    source_tag: str,
    params: dict[str, ParamObservation],
) -> None:
    pattern = r"formData\.(?:append|set)\(\s*['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]"
    for match in re.finditer(pattern, source):
        name = match.group(1)
        if _is_valid_param_name(name) and name not in params:
            params[name] = ParamObservation(name=name, location="body", provenance=[source_tag])


def _extract_js_json_body_params(
    source: str,
    source_tag: str,
    params: dict[str, ParamObservation],
) -> None:
    for match in re.finditer(r"JSON\.stringify\(\{([^}]*)\}", source):
        for key_match in re.finditer(r"([a-zA-Z_][a-zA-Z0-9_]*):", match.group(1)):
            name = key_match.group(1)
            if _is_valid_param_name(name) and name not in params:
                params[name] = ParamObservation(name=name, location="body", provenance=[source_tag])


def extract_js_params(source: str, source_tag: str = "js") -> dict[str, ParamObservation]:
    """Extract candidate parameters from JS source patterns."""
    params: dict[str, ParamObservation] = {}
    _extract_js_query_params(source, source_tag, params)
    _extract_js_form_data_params(source, source_tag, params)
    _extract_js_json_body_params(source, source_tag, params)
    return params


def extract_form_params(html: str, source: str = "form") -> dict[str, ParamObservation]:
    """Extract form input names from raw HTML."""
    params: dict[str, ParamObservation] = {}
    for tag in ("input", "textarea", "select"):
        pattern = rf"<{tag}[^>]+name=[\"']([a-zA-Z_][a-zA-Z0-9_\-\[\]]*)[\"']"
        for match in re.finditer(pattern, html, re.I):
            name = match.group(1)
            if _is_valid_param_name(name) and name not in params:
                params[name] = ParamObservation(name=name, location="body", provenance=[source])
    return params


def merge_extracted_params(
    existing: dict[str, ParamObservation],
    extracted: dict[str, ParamObservation],
) -> dict[str, ParamObservation]:
    """Merge extracted parameters into an existing map, unioning provenance and example values."""
    for name, param in extracted.items():
        if name in existing:
            current = existing[name]
            for prov in param.provenance:
                if prov not in current.provenance:
                    current.provenance.append(prov)
            for value in param.example_values:
                if value not in current.example_values:
                    current.example_values.append(value)
            if current.location != param.location and param.location not in {current.location}:
                current.location = param.location
        else:
            existing[name] = param
    return existing
