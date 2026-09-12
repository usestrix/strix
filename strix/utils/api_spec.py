"""Recognize API specifications and extract the hosts they declare.

Supports OpenAPI 3.x, Swagger 2.0, and Postman Collection v2.1. Two things about
an API spec must be decided on the host, in code: whether a target file is a
spec at all (detection), and which base URLs it authorizes as in-scope hosts
(scope cannot be self-granted by the agent). Everything else about the contract
— operations, parameters, request bodies, auth — is left to the agent, which
reads the spec file directly in the sandbox, so ``$ref``, ``allOf``, and nested
schemas resolve properly instead of being re-parsed here. Collections held only
in Postman are fetched here too, so the API key stays on the host and never
enters the sandbox.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
import yaml


logger = logging.getLogger(__name__)


SPEC_EXTENSIONS = frozenset({".json", ".yaml", ".yml"})

#: Guard against pathological Postman folder nesting.
_MAX_POSTMAN_DEPTH = 25


class SpecParseError(ValueError):
    """Raised when a spec cannot be read, recognized, or fetched."""


def load_spec(path: str | Path) -> dict[str, Any]:
    """Load an API spec file as a mapping.

    Raises :class:`SpecParseError` if the file cannot be read or is not a
    JSON/YAML mapping.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise SpecParseError(f"Cannot read spec {p}: {exc}") from exc
    # JSON is a subset of YAML, so safe_load parses both; try JSON first for a
    # clearer error and to keep the fast path fast.
    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SpecParseError(f"{p} is not valid JSON or YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise SpecParseError(f"{p} does not contain a mapping at the top level")
    return data


def classify_spec(raw: dict[str, Any]) -> str | None:
    """Return ``openapi`` / ``swagger`` / ``postman``, or ``None`` if unrecognized."""
    if isinstance(raw.get("openapi"), str):
        return "openapi"
    if str(raw.get("swagger", "")).startswith("2"):
        return "swagger"
    info = raw.get("info")
    if isinstance(info, dict) and ("_postman_id" in info or "item" in raw):
        return "postman"
    return None


def detect_spec_format(path: Path) -> str | None:
    """Return the spec format of *path*, or ``None`` if it is not a spec.

    Only files whose extension is in :data:`SPEC_EXTENSIONS` are inspected; the
    contents are then loaded to confirm, so an arbitrary ``.json`` config is not
    mistaken for a spec.
    """
    if path.suffix.lower() not in SPEC_EXTENSIONS:
        return None
    try:
        raw = load_spec(path)
    except SpecParseError:
        return None
    return classify_spec(raw)


def spec_title(raw: dict[str, Any]) -> str:
    """Return the spec's declared name, for display in the task and run record."""
    info = raw.get("info")
    if not isinstance(info, dict):
        return "API"
    name = info.get("title") or info.get("name") or "API"
    return str(name).strip() or "API"


def _absolute_urls(candidates: list[str]) -> list[str]:
    """Keep absolute http(s) URLs, without trailing slashes, in declared order."""
    urls: list[str] = []
    for candidate in candidates:
        split = urlsplit(candidate.strip())
        if split.scheme in ("http", "https") and split.netloc:
            urls.append(candidate.strip().rstrip("/"))
    return list(dict.fromkeys(urls))


_SERVER_VAR_PATTERN = re.compile(r"\{([^{}/]+)\}")


def _resolve_server_url(url: str, variables: Any) -> str:
    """Substitute an OpenAPI server template's variables with their defaults."""
    if "{" not in url or not isinstance(variables, dict):
        return url
    defaults: dict[str, str] = {}
    for name, spec in variables.items():
        if isinstance(spec, dict) and spec.get("default") is not None:
            defaults[str(name)] = str(spec["default"])
    return _SERVER_VAR_PATTERN.sub(lambda m: defaults.get(m.group(1), m.group(0)), url)


def _openapi_base_urls(raw: dict[str, Any]) -> list[str]:
    servers = raw.get("servers")
    if not isinstance(servers, list):
        return []
    return _absolute_urls(
        [
            _resolve_server_url(str(server["url"]), server.get("variables"))
            for server in servers
            if isinstance(server, dict) and server.get("url")
        ],
    )


def _swagger_base_urls(raw: dict[str, Any]) -> list[str]:
    host = str(raw.get("host", "")).strip()
    if not host:
        return []
    base_path = str(raw.get("basePath", "")).strip()
    schemes = [s for s in (raw.get("schemes") or ["https"]) if isinstance(s, str)]
    return _absolute_urls([f"{scheme}://{host}{base_path}" for scheme in schemes])


_POSTMAN_VAR_PATTERN = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")


def postman_variables(raw: dict[str, Any]) -> dict[str, str]:
    """Build a ``{name: value}`` map from a Postman ``variable`` block."""
    variables: dict[str, str] = {}
    entries = raw.get("variable")
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict) and entry.get("key") is not None:
                variables[str(entry["key"])] = str(entry.get("value", ""))
    return variables


def _resolve_postman_vars(text: str, variables: dict[str, str]) -> str:
    if not variables or "{{" not in text:
        return text
    return _POSTMAN_VAR_PATTERN.sub(lambda m: variables.get(m.group(1), m.group(0)), text)


def _postman_request_url(url: Any, variables: dict[str, str]) -> str:
    if isinstance(url, str):
        raw = url
    elif isinstance(url, dict):
        raw = str(url.get("raw", ""))
        if not raw:
            host = url.get("host")
            raw = ".".join(str(h) for h in host) if isinstance(host, list) else str(host or "")
    else:
        return ""
    return _resolve_postman_vars(raw, variables)


def _walk_postman_hosts(
    items: Any,
    variables: dict[str, str],
    hosts: list[str],
    depth: int = 0,
) -> None:
    if depth > _MAX_POSTMAN_DEPTH or not isinstance(items, list):
        return
    for node in items:
        if not isinstance(node, dict):
            continue
        if isinstance(node.get("item"), list):
            _walk_postman_hosts(node["item"], variables, hosts, depth + 1)
            continue
        request = node.get("request")
        if not isinstance(request, dict):
            continue
        url = _postman_request_url(request.get("url"), variables)
        split = urlsplit(url)
        if split.scheme and split.netloc:
            hosts.append(f"{split.scheme}://{split.netloc}")


def _postman_base_urls(raw: dict[str, Any], extra_variables: dict[str, str] | None) -> list[str]:
    variables = postman_variables(raw)
    if extra_variables:
        variables.update(extra_variables)  # environment values override collection defaults
    hosts: list[str] = []
    _walk_postman_hosts(raw.get("item"), variables, hosts)
    return _absolute_urls(sorted(set(hosts)))


def spec_base_urls(
    raw: dict[str, Any],
    *,
    extra_variables: dict[str, str] | None = None,
) -> list[str]:
    """Return the absolute base URLs a spec declares, for scope authorization.

    Relative and unresolved-template URLs are dropped: an unusable value would
    otherwise be authorized as an in-scope host. Callers pair the spec with an
    explicit ``--target`` host when the spec declares none.
    """
    spec_format = classify_spec(raw)
    if spec_format == "openapi":
        return _openapi_base_urls(raw)
    if spec_format == "swagger":
        return _swagger_base_urls(raw)
    if spec_format == "postman":
        return _postman_base_urls(raw, extra_variables)
    raise SpecParseError("File is not a recognized OpenAPI, Swagger, or Postman spec")


POSTMAN_API_BASE = "https://api.getpostman.com"
_POSTMAN_FETCH_TIMEOUT = 30


def _postman_api_json(url: str, api_key: str, label: str) -> dict[str, Any]:
    """GET a Postman API resource and return the parsed JSON payload.

    Raises :class:`SpecParseError` with an actionable message on auth, network,
    or shape errors.
    """
    if not api_key:
        raise SpecParseError(
            "POSTMAN_API_KEY is not set. Export a Postman API key (PMAK-…) to "
            "fetch from the Postman API, or pass a local collection file instead.",
        )
    try:
        response = requests.get(
            url,
            headers={"X-Api-Key": api_key, "Accept": "application/json"},
            timeout=_POSTMAN_FETCH_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise SpecParseError(f"Failed to reach the Postman API: {exc}") from exc

    if response.status_code == 401:
        raise SpecParseError("Postman API rejected the key (401). Check POSTMAN_API_KEY.")
    if response.status_code == 404:
        raise SpecParseError(
            f"Postman {label} not found (404). Check the id and that the key can access it.",
        )
    if response.status_code != 200:
        raise SpecParseError(f"Postman API returned HTTP {response.status_code} for {label}.")
    try:
        payload = response.json()
    except ValueError as exc:
        raise SpecParseError(f"Postman API returned non-JSON for {label}") from exc
    if not isinstance(payload, dict):
        raise SpecParseError(f"Unexpected Postman API response shape for {label}")
    return payload


def fetch_postman_collection(collection_uid: str, api_key: str) -> dict[str, Any]:
    """Fetch a collection from the Postman API and return the raw collection dict.

    Uses ``GET /collections/{uid}`` with the ``X-Api-Key`` header. The endpoint
    wraps the collection under a ``collection`` key, unwrapped here so the result
    matches an exported collection file.
    """
    payload = _postman_api_json(
        f"{POSTMAN_API_BASE}/collections/{collection_uid}",
        api_key,
        f"collection {collection_uid}",
    )
    collection = payload.get("collection", payload)
    if not isinstance(collection, dict) or not collection:
        raise SpecParseError(f"Postman collection {collection_uid} came back empty")
    return collection


def fetch_postman_environment(environment_uid: str, api_key: str) -> dict[str, str]:
    """Fetch a Postman environment and return its enabled ``{key: value}`` pairs.

    Disabled values are skipped, matching how Postman resolves an environment at
    request time.
    """
    payload = _postman_api_json(
        f"{POSTMAN_API_BASE}/environments/{environment_uid}",
        api_key,
        f"environment {environment_uid}",
    )
    environment = payload.get("environment", payload)
    values = environment.get("values") if isinstance(environment, dict) else None
    if not isinstance(values, list):
        return {}
    return {
        str(value["key"]): str(value.get("value", ""))
        for value in values
        if isinstance(value, dict) and value.get("key") and value.get("enabled", True)
    }
