"""Tests for the API-spec parser in strix.core.api_spec."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
import requests

from strix.core.api_spec import (
    MAX_ENDPOINTS_RENDERED,
    SpecParseError,
    detect_spec_format,
    fetch_postman_collection,
    fetch_postman_environment,
    load_inventory,
    parse_api_spec,
    parse_postman_api,
    render_inventory,
)


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


OPENAPI_YAML = """
openapi: 3.0.1
info:
  title: Shop API
  version: 1.0.0
servers:
  - url: https://api.shop.test/v1
security:
  - bearerAuth: []
paths:
  /users/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
    get:
      summary: Get user
      parameters:
        - name: expand
          in: query
          schema:
            type: string
    put:
      summary: Update user
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name: {}
                role: {}
"""

SWAGGER_JSON = {
    "swagger": "2.0",
    "info": {"title": "Legacy"},
    "host": "legacy.test",
    "basePath": "/api",
    "schemes": ["https"],
    "paths": {
        "/orders": {
            "post": {
                "summary": "Create order",
                "parameters": [
                    {"name": "X-Trace", "in": "header", "type": "string"},
                    {
                        "name": "body",
                        "in": "body",
                        "schema": {"properties": {"amount": {}, "currency": {}}},
                    },
                ],
            }
        }
    },
}

POSTMAN_JSON = {
    "info": {"_postman_id": "abc-123", "name": "Pet Store"},
    "item": [
        {
            "name": "Pets",
            "item": [
                {
                    "name": "List pets",
                    "request": {
                        "method": "GET",
                        "url": {
                            "raw": "https://petstore.test/pets?limit=10",
                            "query": [{"key": "limit"}],
                        },
                    },
                }
            ],
        },
        {
            "name": "Add pet",
            "request": {"method": "POST", "url": "https://petstore.test/pets"},
        },
    ],
}


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_detect_openapi_yaml(tmp_path: Path) -> None:
    path = _write(tmp_path, "openapi.yaml", OPENAPI_YAML)
    assert detect_spec_format(path) == "openapi"


def test_detect_swagger_json(tmp_path: Path) -> None:
    path = _write(tmp_path, "swagger.json", json.dumps(SWAGGER_JSON))
    assert detect_spec_format(path) == "swagger"


def test_detect_postman_json(tmp_path: Path) -> None:
    path = _write(tmp_path, "collection.json", json.dumps(POSTMAN_JSON))
    assert detect_spec_format(path) == "postman"


def test_detect_ignores_non_spec_extension(tmp_path: Path) -> None:
    path = _write(tmp_path, "notes.txt", OPENAPI_YAML)
    assert detect_spec_format(path) is None


def test_detect_ignores_non_spec_json(tmp_path: Path) -> None:
    path = _write(tmp_path, "config.json", json.dumps({"foo": "bar"}))
    assert detect_spec_format(path) is None


def test_parse_openapi_endpoints_and_params(tmp_path: Path) -> None:
    inventory = parse_api_spec(_write(tmp_path, "openapi.yaml", OPENAPI_YAML))

    assert inventory.spec_format == "openapi"
    assert inventory.title == "Shop API"
    assert inventory.base_urls == ["https://api.shop.test/v1"]
    assert len(inventory.endpoints) == 2

    get = next(e for e in inventory.endpoints if e.method == "GET")
    # path-level and operation-level params are merged
    assert any(p.startswith("id*") and "path" in p for p in get.parameters)
    assert any("expand" in p for p in get.parameters)
    assert get.security == ["bearerAuth"]

    put = next(e for e in inventory.endpoints if e.method == "PUT")
    assert put.body_fields == ["name", "role"]


def test_parse_swagger_builds_base_url_and_body(tmp_path: Path) -> None:
    inventory = parse_api_spec(_write(tmp_path, "swagger.json", json.dumps(SWAGGER_JSON)))

    assert inventory.spec_format == "swagger"
    assert inventory.base_urls == ["https://legacy.test/api"]
    (endpoint,) = inventory.endpoints
    assert endpoint.method == "POST"
    assert endpoint.path == "/orders"
    assert endpoint.body_fields == ["amount", "currency"]
    # body param is not rendered as a query/path param
    assert all("body" not in p for p in endpoint.parameters)
    assert any("X-Trace" in p for p in endpoint.parameters)


def test_parse_postman_walks_folders(tmp_path: Path) -> None:
    inventory = parse_api_spec(_write(tmp_path, "collection.json", json.dumps(POSTMAN_JSON)))

    assert inventory.spec_format == "postman"
    assert inventory.base_urls == ["https://petstore.test"]
    methods = {(e.method, e.path) for e in inventory.endpoints}
    assert ("GET", "/pets") in methods
    assert ("POST", "/pets") in methods


def test_parse_rejects_unrecognized_file(tmp_path: Path) -> None:
    path = _write(tmp_path, "thing.json", json.dumps({"foo": 1}))
    with pytest.raises(SpecParseError):
        parse_api_spec(path)


def test_parse_rejects_malformed_yaml(tmp_path: Path) -> None:
    path = _write(tmp_path, "broken.yaml", "openapi: 3.0.0\npaths: [unclosed")
    with pytest.raises(SpecParseError):
        parse_api_spec(path)


def test_render_inventory_caps_endpoints(tmp_path: Path) -> None:
    paths = {f"/r{i}": {"get": {"summary": f"op {i}"}} for i in range(MAX_ENDPOINTS_RENDERED + 25)}
    spec = {"openapi": "3.0.0", "info": {"title": "Big"}, "paths": paths}
    inventory = parse_api_spec(_write(tmp_path, "big.json", json.dumps(spec)))

    rendered = render_inventory(inventory)
    assert "and 25 more endpoint(s)" in rendered
    assert rendered.count("\n    - GET") == MAX_ENDPOINTS_RENDERED


def test_to_details_is_json_serializable(tmp_path: Path) -> None:
    inventory = parse_api_spec(_write(tmp_path, "openapi.yaml", OPENAPI_YAML))
    details = inventory.to_details()
    # round-trips through json without error
    assert json.loads(json.dumps(details))["endpoint_count"] == 2


def test_load_inventory_returns_none_for_missing_spec() -> None:
    assert load_inventory({"target_spec": "/nonexistent/spec.yaml"}) is None


def test_load_inventory_returns_none_without_spec_key() -> None:
    assert load_inventory({}) is None


def test_load_inventory_parses_and_caches(tmp_path: Path) -> None:
    path = _write(tmp_path, "openapi.yaml", OPENAPI_YAML)
    details = {"target_spec": str(path)}
    first = load_inventory(details)
    second = load_inventory(details)
    assert first is not None
    assert second is first  # served from the mtime-keyed cache


# --- Postman variable resolution + API fetch -----------------------------

POSTMAN_WITH_VARS = {
    "info": {"_postman_id": "v-1", "name": "Var Collection"},
    "variable": [{"key": "baseUrl", "value": "https://api.vars.test"}],
    "item": [
        {
            "name": "Get thing",
            "request": {
                "method": "GET",
                "url": {"raw": "{{baseUrl}}/things/1"},
            },
        }
    ],
}


class _FakeResponse:
    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        return self._payload


def test_postman_resolves_collection_variables(tmp_path: Path) -> None:
    inventory = parse_api_spec(_write(tmp_path, "vars.json", json.dumps(POSTMAN_WITH_VARS)))
    assert inventory.base_urls == ["https://api.vars.test"]
    assert inventory.endpoints[0].path == "/things/1"


def test_fetch_postman_collection_unwraps(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_get(url: str, headers: dict[str, str], **_kwargs: Any) -> _FakeResponse:
        captured["url"] = url
        captured["headers"] = headers
        return _FakeResponse(200, {"collection": POSTMAN_WITH_VARS})

    monkeypatch.setattr(requests, "get", fake_get)
    collection = fetch_postman_collection("abc-123", "PMAK-xyz")

    assert collection["info"]["name"] == "Var Collection"
    assert captured["url"].endswith("/collections/abc-123")
    assert captured["headers"]["X-Api-Key"] == "PMAK-xyz"


def test_parse_postman_api_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        requests,
        "get",
        lambda *_a, **_k: _FakeResponse(200, {"collection": POSTMAN_WITH_VARS}),
    )
    inventory = parse_postman_api("abc-123", "PMAK-xyz")
    assert inventory.spec_format == "postman"
    assert inventory.base_urls == ["https://api.vars.test"]


def test_fetch_postman_missing_key_raises() -> None:
    with pytest.raises(SpecParseError, match="POSTMAN_API_KEY"):
        fetch_postman_collection("abc-123", "")


def test_fetch_postman_404_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        requests,
        "get",
        lambda *_a, **_k: _FakeResponse(404, {}),
    )
    with pytest.raises(SpecParseError, match="not found"):
        fetch_postman_collection("missing", "PMAK-xyz")


def test_fetch_postman_401_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        requests,
        "get",
        lambda *_a, **_k: _FakeResponse(401, {}),
    )
    with pytest.raises(SpecParseError, match="rejected the key"):
        fetch_postman_collection("abc-123", "bad-key")


# --- Postman environment resolution --------------------------------------

POSTMAN_NEEDS_ENV = {
    "info": {"_postman_id": "e-1", "name": "Env Collection"},
    "item": [
        {"name": "Get thing", "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/things/1"}}}
    ],
}

ENV_PAYLOAD = {
    "environment": {
        "name": "prod",
        "values": [
            {"key": "baseUrl", "value": "https://api.env.test", "enabled": True},
            {"key": "secretToken", "value": "s3cr3t", "enabled": False},
        ],
    }
}


def _dispatch_get(
    collection: dict[str, Any],
    env: dict[str, Any],
) -> Callable[..., _FakeResponse]:
    def fake_get(url: str, **_kwargs: Any) -> _FakeResponse:
        if "/environments/" in url:
            return _FakeResponse(200, env)
        return _FakeResponse(200, {"collection": collection})

    return fake_get


def test_fetch_postman_environment_returns_enabled_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(requests, "get", lambda *_a, **_k: _FakeResponse(200, ENV_PAYLOAD))
    values = fetch_postman_environment("env-1", "PMAK-xyz")
    assert values == {"baseUrl": "https://api.env.test"}  # disabled secret excluded


def test_parse_postman_api_resolves_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(requests, "get", _dispatch_get(POSTMAN_NEEDS_ENV, ENV_PAYLOAD))
    inventory = parse_postman_api("coll-1", "PMAK-xyz", "env-1")
    assert inventory.base_urls == ["https://api.env.test"]
    assert inventory.endpoints[0].path == "/things/1"


def test_parse_postman_api_without_env_leaves_variable_unresolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        requests,
        "get",
        lambda *_a, **_k: _FakeResponse(200, {"collection": POSTMAN_NEEDS_ENV}),
    )
    inventory = parse_postman_api("coll-1", "PMAK-xyz")
    # no environment supplied -> no concrete base URL recovered
    assert inventory.base_urls == []


# --- Postman header / body / auth extraction -----------------------------

POSTMAN_RICH = {
    "info": {"_postman_id": "r-1", "name": "Rich"},
    "variable": [
        {"key": "baseUrl", "value": "https://api.rich.test"},
        {"key": "petName", "value": "Rex"},
    ],
    "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}"}]},
    "item": [
        {
            "name": "Create pet",
            "request": {
                "method": "POST",
                "header": [
                    {"key": "Content-Type", "value": "application/json"},
                    {"key": "X-Trace", "value": "1", "disabled": True},
                ],
                "body": {"mode": "raw", "raw": '{"name": "{{petName}}", "species": "dog"}'},
                "url": {"raw": "{{baseUrl}}/pets"},
            },
        },
        {
            "name": "Admin",
            "request": {
                "method": "GET",
                "auth": {"type": "apikey", "apikey": [{"key": "key", "value": "X-Admin"}]},
                "url": {"raw": "{{baseUrl}}/admin"},
            },
        },
    ],
}


def test_postman_extracts_headers_body_and_auth(tmp_path: Path) -> None:
    inventory = parse_api_spec(_write(tmp_path, "rich.json", json.dumps(POSTMAN_RICH)))
    assert inventory.base_urls == ["https://api.rich.test"]

    create = next(e for e in inventory.endpoints if e.path == "/pets")
    assert create.body_fields == ["name", "species"]  # body raw parsed, {{petName}} resolved
    assert "Content-Type (header)" in create.parameters
    assert all("X-Trace" not in p for p in create.parameters)  # disabled header skipped
    assert create.security == ["bearer"]  # inherited from collection-level auth

    admin = next(e for e in inventory.endpoints if e.path == "/admin")
    assert admin.security == ["apikey"]  # request-level auth overrides inherited


POSTMAN_PATH_VARS = {
    "info": {"_postman_id": "p-1", "name": "Path Vars"},
    "variable": [{"key": "baseUrl", "value": "https://api.pv.test"}],
    "item": [
        {
            "name": "Get order",
            "request": {
                "method": "GET",
                "url": {
                    "raw": "{{baseUrl}}/users/:userId/orders/:orderId?expand=items",
                    "query": [{"key": "expand", "value": "items"}],
                },
            },
        }
    ],
}


def test_postman_normalizes_colon_path_variables(tmp_path: Path) -> None:
    inventory = parse_api_spec(_write(tmp_path, "pv.json", json.dumps(POSTMAN_PATH_VARS)))
    (endpoint,) = inventory.endpoints
    # :var segments become {var}, matching the OpenAPI template style
    assert endpoint.path == "/users/{userId}/orders/{orderId}"
    assert "userId (path)" in endpoint.parameters
    assert "orderId (path)" in endpoint.parameters
    assert "expand (query)" in endpoint.parameters
