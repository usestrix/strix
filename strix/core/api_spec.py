"""Parse API specifications into a normalized endpoint inventory.

Supports OpenAPI 3.x, Swagger 2.0, and Postman Collection v2.1. The goal is
not full schema validation but extracting the *attack surface* an agent needs:
every operation (method + path), its parameters and body fields, the declared
auth, and the base server URLs.

The inventory feeds two places:

* :func:`strix.core.inputs.build_root_task` renders it as an endpoint list so
  the agent tests every operation instead of discovering them by crawling.
* :func:`strix.core.inputs.build_scope_context` uses the base URLs to mark the
  API hosts as authorized, in-scope targets.

Parsing is intentionally defensive: a malformed or partial spec yields whatever
could be recovered rather than raising, so a single bad operation never sinks a
whole run.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
import yaml

from strix.config import load_settings


logger = logging.getLogger(__name__)


SPEC_EXTENSIONS = frozenset({".json", ".yaml", ".yml"})
_HTTP_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"},
)

#: Cap the number of endpoints rendered into a prompt so a large spec cannot
#: blow up the context window. The full inventory is still persisted.
MAX_ENDPOINTS_RENDERED = 200

#: Recursion / size guards for pathological Postman trees and huge specs.
_MAX_POSTMAN_DEPTH = 25
_MAX_ENDPOINTS_PARSED = 5000


@dataclass
class Endpoint:
    """A single API operation."""

    method: str
    path: str
    summary: str = ""
    parameters: list[str] = field(default_factory=list)
    body_fields: list[str] = field(default_factory=list)
    security: list[str] = field(default_factory=list)

    def render(self) -> str:
        line = f"{self.method} {self.path}"
        if self.summary:
            line += f" — {self.summary}"
        extras: list[str] = []
        if self.parameters:
            extras.append("params: " + ", ".join(self.parameters))
        if self.body_fields:
            extras.append("body: " + ", ".join(self.body_fields))
        if self.security:
            extras.append("auth: " + ", ".join(self.security))
        if extras:
            line += " (" + "; ".join(extras) + ")"
        return line


@dataclass
class ApiSpecInventory:
    """Normalized view of an API specification."""

    spec_format: str
    title: str
    base_urls: list[str]
    endpoints: list[Endpoint]

    def to_details(self) -> dict[str, Any]:
        """Return a JSON-serializable form for the run record / viewer."""
        return {
            "spec_format": self.spec_format,
            "title": self.title,
            "base_urls": list(self.base_urls),
            "endpoint_count": len(self.endpoints),
            "endpoints": [
                {
                    "method": e.method,
                    "path": e.path,
                    "summary": e.summary,
                    "parameters": e.parameters,
                    "body_fields": e.body_fields,
                    "security": e.security,
                }
                for e in self.endpoints
            ],
        }


class SpecParseError(ValueError):
    """Raised when a file cannot be recognized or parsed as an API spec."""


def _load_raw(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    # JSON is a subset of YAML, so safe_load parses both; try JSON first for a
    # clearer error and to keep the fast path fast.
    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SpecParseError(f"{path} is not valid JSON or YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise SpecParseError(f"{path} does not contain a mapping at the top level")
    return data


def _classify(raw: dict[str, Any]) -> str | None:
    if isinstance(raw.get("openapi"), str):
        return "openapi"
    if str(raw.get("swagger", "")).startswith("2"):
        return "swagger"
    info = raw.get("info")
    if isinstance(info, dict) and ("_postman_id" in info or "item" in raw):
        return "postman"
    return None


def detect_spec_format(path: Path) -> str | None:
    """Return ``openapi`` / ``swagger`` / ``postman`` for *path*, else ``None``.

    Only files whose extension is in :data:`SPEC_EXTENSIONS` are inspected; the
    contents are then loaded to confirm, so an arbitrary ``.json`` config is not
    mistaken for a spec.
    """
    if path.suffix.lower() not in SPEC_EXTENSIONS:
        return None
    try:
        raw = _load_raw(path)
    except (OSError, SpecParseError):
        return None
    return _classify(raw)


def _schema_type(schema: Any) -> str:
    if not isinstance(schema, dict):
        return ""
    typ = schema.get("type")
    if isinstance(typ, str):
        return typ
    if "$ref" in schema:
        return str(schema["$ref"]).rsplit("/", 1)[-1]
    return ""


def _format_param(param: dict[str, Any]) -> str:
    name = str(param.get("name", "")).strip()
    if not name:
        return ""
    location = str(param.get("in", "")).strip()
    # OpenAPI 3 nests the type under "schema"; Swagger 2 puts it inline.
    typ = _schema_type(param.get("schema")) or _schema_type(param)
    required = "*" if param.get("required") else ""
    label = name + required
    meta = ":".join(p for p in (location, typ) if p)
    return f"{label} ({meta})" if meta else label


def _security_names(entries: Any) -> list[str]:
    names: list[str] = []
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                names.extend(str(k) for k in entry)
    # De-duplicate while preserving order.
    return list(dict.fromkeys(names))


def _resolve_ref(ref: Any, root: dict[str, Any]) -> Any:
    """Resolve a local JSON-Pointer ``$ref`` (``#/a/b``) against *root*.

    Handles both OpenAPI (``#/components/schemas/…``) and Swagger
    (``#/definitions/…``) roots. Remote refs (``other.json#/…``) are not
    resolved and yield ``None``.
    """
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node: Any = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")  # JSON Pointer unescape
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _schema_property_names(
    schema: Any,
    root: dict[str, Any],
    seen: set[str] | None = None,
) -> list[str]:
    """Collect property names from *schema*, following ``$ref`` and ``allOf`` etc.

    Recurses through ``$ref`` and the ``allOf``/``oneOf``/``anyOf`` composition
    keywords so bodies declared by reference or composition still surface their
    fields. ``seen`` guards against circular ``$ref`` chains.
    """
    if not isinstance(schema, dict):
        return []
    seen = seen if seen is not None else set()
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in seen:
            return []
        seen.add(ref)
        return _schema_property_names(_resolve_ref(ref, root), root, seen)
    names: list[str] = list(schema.get("properties", {}) or {})
    for combiner in ("allOf", "oneOf", "anyOf"):
        for sub in schema.get(combiner, []) or []:
            names.extend(_schema_property_names(sub, root, seen))
    return list(dict.fromkeys(names))  # de-duplicate, preserve order


def _body_fields(request_body: Any, root: dict[str, Any]) -> list[str]:
    if not isinstance(request_body, dict):
        return []
    # An OpenAPI requestBody may itself be a $ref into components.requestBodies.
    ref = request_body.get("$ref")
    if isinstance(ref, str):
        resolved = _resolve_ref(ref, root)
        return _body_fields(resolved, root) if isinstance(resolved, dict) else []
    content = request_body.get("content")
    if not isinstance(content, dict):
        return []
    for media in content.values():
        schema = media.get("schema") if isinstance(media, dict) else None
        names = _schema_property_names(schema, root)
        if names:
            return names
    return []


def _iter_operations(item: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [
        (method, op)
        for method, op in item.items()
        if method.lower() in _HTTP_METHODS and isinstance(op, dict)
    ]


def _parse_openapi(raw: dict[str, Any]) -> ApiSpecInventory:
    info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
    title = str(info.get("title", "API")) if isinstance(info, dict) else "API"
    base_urls: list[str] = [
        str(server["url"])
        for server in raw.get("servers", []) or []
        if isinstance(server, dict) and server.get("url")
    ]

    global_security = _security_names(raw.get("security"))
    endpoints: list[Endpoint] = []
    paths = raw.get("paths")
    if isinstance(paths, dict):
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            shared_params = item.get("parameters", []) or []
            for method, op in _iter_operations(item):
                params = [
                    _format_param(p)
                    for p in (*shared_params, *(op.get("parameters", []) or []))
                    if isinstance(p, dict)
                ]
                # An explicit ``security: []`` opts an operation out of auth and
                # must override the global policy; only a *missing* key inherits it.
                op_security = (
                    _security_names(op.get("security"))
                    if "security" in op
                    else global_security
                )
                endpoints.append(
                    Endpoint(
                        method=method.upper(),
                        path=str(path),
                        summary=str(op.get("summary", "")).strip(),
                        parameters=[p for p in params if p],
                        body_fields=_body_fields(op.get("requestBody"), raw),
                        security=op_security,
                    ),
                )
                if len(endpoints) >= _MAX_ENDPOINTS_PARSED:
                    return ApiSpecInventory("openapi", title, base_urls, endpoints)
    return ApiSpecInventory("openapi", title, base_urls, endpoints)


def _parse_swagger(raw: dict[str, Any]) -> ApiSpecInventory:
    info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
    title = str(info.get("title", "API")) if isinstance(info, dict) else "API"
    host = str(raw.get("host", "")).strip()
    base_path = str(raw.get("basePath", "")).strip()
    schemes = [s for s in (raw.get("schemes") or ["https"]) if isinstance(s, str)]
    base_urls: list[str] = []
    if host:
        base_urls = [f"{scheme}://{host}{base_path}" for scheme in schemes]
    elif base_path:
        base_urls = [base_path]

    global_security = _security_names(raw.get("security"))
    endpoints: list[Endpoint] = []
    paths = raw.get("paths")
    if isinstance(paths, dict):
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            shared_params = item.get("parameters", []) or []
            for method, op in _iter_operations(item):
                merged = [
                    p
                    for p in (*shared_params, *(op.get("parameters", []) or []))
                    if isinstance(p, dict)
                ]
                params = [_format_param(p) for p in merged if p.get("in") != "body"]
                body_fields: list[str] = []
                for p in merged:
                    if p.get("in") == "body":
                        body_fields = _schema_property_names(p.get("schema"), raw)
                # An explicit ``security: []`` opts an operation out of auth and
                # must override the global policy; only a *missing* key inherits it.
                op_security = (
                    _security_names(op.get("security"))
                    if "security" in op
                    else global_security
                )
                endpoints.append(
                    Endpoint(
                        method=method.upper(),
                        path=str(path),
                        summary=str(op.get("summary", "")).strip(),
                        parameters=[p for p in params if p],
                        body_fields=body_fields,
                        security=op_security,
                    ),
                )
                if len(endpoints) >= _MAX_ENDPOINTS_PARSED:
                    return ApiSpecInventory("swagger", title, base_urls, endpoints)
    return ApiSpecInventory("swagger", title, base_urls, endpoints)


_VAR_PATTERN = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")


def _collect_variables(entries: Any) -> dict[str, str]:
    """Build a ``{name: value}`` map from a Postman ``variable`` block."""
    variables: dict[str, str] = {}
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict) and entry.get("key") is not None:
                variables[str(entry["key"])] = str(entry.get("value", ""))
    return variables


def _resolve_vars(text: str, variables: dict[str, str]) -> str:
    """Substitute ``{{var}}`` placeholders using the collection variables."""
    if not variables or "{{" not in text:
        return text
    return _VAR_PATTERN.sub(lambda m: variables.get(m.group(1), m.group(0)), text)


def _postman_url(url: Any, variables: dict[str, str]) -> tuple[str, str]:
    """Return ``(base_url, path)`` from a Postman request ``url`` node."""
    if isinstance(url, str):
        raw = url
    elif isinstance(url, dict):
        raw = str(url.get("raw", ""))
        if not raw:
            host = url.get("host")
            host_str = ".".join(host) if isinstance(host, list) else str(host or "")
            path = url.get("path")
            path_str = "/".join(str(p) for p in path) if isinstance(path, list) else str(path or "")
            raw = f"{host_str}/{path_str}".strip("/")
    else:
        return "", ""
    raw = _resolve_vars(raw, variables)
    split = urlsplit(raw)
    if split.scheme and split.netloc:
        return f"{split.scheme}://{split.netloc}", split.path or "/"
    return "", raw


_PATH_VAR_PATTERN = re.compile(r":([A-Za-z0-9_]+)")


def _normalize_postman_path(path: str) -> tuple[str, list[str]]:
    """Turn Postman ``:var`` path segments into ``{var}`` and list them as params.

    Mirrors the OpenAPI path-template style so path variables read consistently
    and surface as object references worth testing (IDOR/BOLA candidates).
    """
    names = _PATH_VAR_PATTERN.findall(path)
    normalized = _PATH_VAR_PATTERN.sub(lambda m: "{" + m.group(1) + "}", path)
    return normalized, [f"{name} (path)" for name in names]


def _postman_query_params(url: Any, variables: dict[str, str]) -> list[str]:
    if not isinstance(url, dict) or not isinstance(url.get("query"), list):
        return []
    return [
        f"{_resolve_vars(str(q['key']), variables)} (query)"
        for q in url["query"]
        if isinstance(q, dict) and q.get("key") and not q.get("disabled")
    ]


def _postman_header_params(request: dict[str, Any], variables: dict[str, str]) -> list[str]:
    headers = request.get("header")
    if not isinstance(headers, list):
        return []
    return [
        f"{_resolve_vars(str(entry['key']), variables)} (header)"
        for entry in headers
        if isinstance(entry, dict) and entry.get("key") and not entry.get("disabled")
    ]


def _postman_body_fields(request: dict[str, Any], variables: dict[str, str]) -> list[str]:
    body = request.get("body")
    if not isinstance(body, dict):
        return []
    mode = body.get("mode")
    if mode == "raw":
        raw = _resolve_vars(str(body.get("raw", "")), variables)
        try:
            parsed = json.loads(raw)
        except ValueError:  # JSONDecodeError is a ValueError subclass
            return []
        return list(parsed.keys()) if isinstance(parsed, dict) else []
    if mode in ("urlencoded", "formdata"):
        entries = body.get(mode)
        if isinstance(entries, list):
            return [
                str(e["key"])
                for e in entries
                if isinstance(e, dict) and e.get("key") and not e.get("disabled")
            ]
    return []


def _postman_auth(auth: Any, inherited: list[str]) -> list[str]:
    """Return the auth scheme name for a request/folder, falling back to inherited."""
    if isinstance(auth, dict):
        auth_type = str(auth.get("type", "")).strip()
        if auth_type and auth_type != "noauth":
            return [auth_type]
        if auth_type == "noauth":
            return []
    return inherited


def _walk_postman(
    items: Any,
    endpoints: list[Endpoint],
    base_urls: set[str],
    variables: dict[str, str],
    inherited_auth: list[str],
    depth: int = 0,
) -> None:
    if depth > _MAX_POSTMAN_DEPTH or not isinstance(items, list):
        return
    for node in items:
        if not isinstance(node, dict):
            continue
        if isinstance(node.get("item"), list):
            folder_auth = _postman_auth(node.get("auth"), inherited_auth)
            _walk_postman(node["item"], endpoints, base_urls, variables, folder_auth, depth + 1)
            continue
        request = node.get("request")
        if not isinstance(request, dict):
            continue
        method = str(request.get("method", "GET")).upper()
        base, raw_path = _postman_url(request.get("url"), variables)
        if base:
            base_urls.add(base)
        path, path_params = _normalize_postman_path(raw_path or "/")
        params = (
            path_params
            + _postman_query_params(request.get("url"), variables)
            + _postman_header_params(request, variables)
        )
        endpoints.append(
            Endpoint(
                method=method,
                path=path,
                summary=str(node.get("name", "")).strip(),
                parameters=params,
                body_fields=_postman_body_fields(request, variables),
                security=_postman_auth(request.get("auth"), inherited_auth),
            ),
        )
        if len(endpoints) >= _MAX_ENDPOINTS_PARSED:
            return


def _parse_postman(
    raw: dict[str, Any],
    extra_variables: dict[str, str] | None = None,
) -> ApiSpecInventory:
    info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
    title = str(info.get("name", "Postman Collection")) if isinstance(info, dict) else "Postman"
    variables = _collect_variables(raw.get("variable"))
    if extra_variables:
        variables.update(extra_variables)  # environment values override collection defaults
    endpoints: list[Endpoint] = []
    base_urls: set[str] = set()
    collection_auth = _postman_auth(raw.get("auth"), [])
    _walk_postman(raw.get("item"), endpoints, base_urls, variables, collection_auth)
    return ApiSpecInventory("postman", title, sorted(base_urls), endpoints)


def _parse_raw(raw: dict[str, Any]) -> ApiSpecInventory:
    spec_format = _classify(raw)
    if spec_format == "openapi":
        return _parse_openapi(raw)
    if spec_format == "swagger":
        return _parse_swagger(raw)
    if spec_format == "postman":
        return _parse_postman(raw)
    raise SpecParseError("File is not a recognized OpenAPI, Swagger, or Postman spec")


def parse_api_spec(path: str | Path) -> ApiSpecInventory:
    """Parse the spec at *path* into an :class:`ApiSpecInventory`.

    Raises :class:`SpecParseError` if the file cannot be read or recognized.
    """
    p = Path(path)
    try:
        raw = _load_raw(p)
    except OSError as exc:
        raise SpecParseError(f"Cannot read spec {p}: {exc}") from exc
    return _parse_raw(raw)


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
        f"collection '{collection_uid}'",
    )
    collection = payload.get("collection")
    if not isinstance(collection, dict):
        raise SpecParseError(f"Unexpected Postman API response shape for '{collection_uid}'")
    return collection


def fetch_postman_environment(environment_uid: str, api_key: str) -> dict[str, str]:
    """Fetch a Postman environment and return its enabled ``{key: value}`` map.

    Environments hold the base URLs, hosts, and tokens that collections
    reference as ``{{variables}}``; pulling them in lets those placeholders
    resolve to real values for the scan. Optional — only used when an
    environment id is supplied.
    """
    payload = _postman_api_json(
        f"{POSTMAN_API_BASE}/environments/{environment_uid}",
        api_key,
        f"environment '{environment_uid}'",
    )
    environment = payload.get("environment")
    values = environment.get("values") if isinstance(environment, dict) else None
    resolved: dict[str, str] = {}
    if isinstance(values, list):
        for entry in values:
            if (
                isinstance(entry, dict)
                and entry.get("key") is not None
                and entry.get("enabled", True)
            ):
                resolved[str(entry["key"])] = str(entry.get("value", ""))
    return resolved


def parse_postman_api(
    collection_uid: str,
    api_key: str,
    environment_uid: str = "",
) -> ApiSpecInventory:
    """Fetch a Postman collection (and optional environment) and parse it."""
    collection = fetch_postman_collection(collection_uid, api_key)
    extra_variables = fetch_postman_environment(environment_uid, api_key) if environment_uid else {}
    return _parse_postman(collection, extra_variables=extra_variables)


@lru_cache(maxsize=64)
def _parse_cached(resolved: str, mtime: float) -> ApiSpecInventory:
    del mtime  # part of the cache key only; invalidates when the file changes
    return parse_api_spec(resolved)


@lru_cache(maxsize=16)
def _fetch_cached(collection_uid: str, api_key: str, environment_uid: str) -> ApiSpecInventory:
    return parse_postman_api(collection_uid, api_key, environment_uid)


def load_inventory(details: dict[str, Any]) -> ApiSpecInventory | None:
    """Return the inventory for an ``api_spec`` target's ``details`` block.

    Handles both sources: a local spec file (``source`` absent or ``"file"``)
    and a collection pulled from the Postman API (``source == "postman_api"``).
    Results are memoized so the root-task and scope-context builders do not
    re-read the file or re-hit the API. Returns ``None`` (and logs) on any
    failure so callers degrade gracefully.
    """
    if details.get("source") == "postman_api":
        uid = details.get("collection_uid")
        if not uid:
            return None
        env_uid = str(details.get("environment_uid") or "")
        try:
            api_key = load_settings().integrations.postman_api_key or ""
            return _fetch_cached(str(uid), api_key, env_uid)
        except SpecParseError as exc:
            logger.warning("api_spec: failed to fetch Postman collection %s: %s", uid, exc)
            return None

    spec = details.get("target_spec")
    if not spec:
        return None
    try:
        path = Path(str(spec)).resolve()
        mtime = path.stat().st_mtime
    except OSError as exc:
        logger.warning("api_spec: cannot stat %s: %s", spec, exc)
        return None
    try:
        return _parse_cached(str(path), mtime)
    except SpecParseError as exc:
        logger.warning("api_spec: failed to parse %s: %s", spec, exc)
        return None


def render_inventory(
    inventory: ApiSpecInventory,
    *,
    max_endpoints: int = MAX_ENDPOINTS_RENDERED,
) -> str:
    """Render an inventory as a markdown block for the root task prompt."""
    lines: list[str] = [f"- {inventory.title} ({inventory.spec_format})"]
    if inventory.base_urls:
        lines.append("  - Base URL(s): " + ", ".join(inventory.base_urls))
    lines.append(f"  - Endpoints ({len(inventory.endpoints)}):")
    lines.extend(f"    - {endpoint.render()}" for endpoint in inventory.endpoints[:max_endpoints])
    remaining = len(inventory.endpoints) - max_endpoints
    if remaining > 0:
        lines.append(f"    - … and {remaining} more endpoint(s) (see run record)")
    return "\n".join(lines)
