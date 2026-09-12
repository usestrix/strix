"""Tests for spec recognition and base-URL extraction in strix.utils.api_spec."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
import requests
import yaml

from strix.utils.api_spec import (
    SpecParseError,
    classify_spec,
    detect_spec_format,
    fetch_postman_collection,
    fetch_postman_environment,
    load_spec,
    spec_base_urls,
    spec_title,
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
  - url: https://{region}.api.shop.test/{ver}
    variables:
      region:
        default: eu
      ver:
        default: v1
paths:
  /users/{id}:
    get:
      summary: Get user
"""

SWAGGER_JSON = {
    "swagger": "2.0",
    "info": {"title": "Legacy"},
    "host": "legacy.test",
    "basePath": "/api",
    "schemes": ["https"],
    "paths": {"/orders": {"post": {"summary": "Create order"}}},
}

POSTMAN_JSON = {
    "info": {"_postman_id": "abc-123", "name": "Pet Store"},
    "item": [
        {
            "name": "Pets",
            "item": [
                {
                    "name": "List pets",
                    "request": {"method": "GET", "url": {"raw": "https://petstore.test/pets"}},
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


# --- detection -----------------------------------------------------------


def test_detect_openapi_yaml(tmp_path: Path) -> None:
    assert detect_spec_format(_write(tmp_path, "openapi.yaml", OPENAPI_YAML)) == "openapi"


def test_detect_swagger_json(tmp_path: Path) -> None:
    assert detect_spec_format(_write(tmp_path, "swagger.json", json.dumps(SWAGGER_JSON))) == (
        "swagger"
    )


def test_detect_postman_json(tmp_path: Path) -> None:
    assert detect_spec_format(_write(tmp_path, "collection.json", json.dumps(POSTMAN_JSON))) == (
        "postman"
    )


def test_detect_ignores_non_spec_extension(tmp_path: Path) -> None:
    assert detect_spec_format(_write(tmp_path, "notes.txt", OPENAPI_YAML)) is None


def test_detect_ignores_non_spec_json(tmp_path: Path) -> None:
    assert detect_spec_format(_write(tmp_path, "config.json", json.dumps({"foo": "bar"}))) is None


def test_classify_unrecognized_is_none() -> None:
    assert classify_spec({"foo": 1}) is None


# --- loading -------------------------------------------------------------


def test_load_spec_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SpecParseError, match="Cannot read"):
        load_spec(tmp_path / "nope.yaml")


def test_load_spec_rejects_malformed_yaml(tmp_path: Path) -> None:
    with pytest.raises(SpecParseError):
        load_spec(_write(tmp_path, "broken.yaml", "openapi: 3.0.0\npaths: [unclosed"))


def test_load_spec_rejects_non_mapping(tmp_path: Path) -> None:
    with pytest.raises(SpecParseError, match="mapping"):
        load_spec(_write(tmp_path, "list.json", json.dumps([1, 2, 3])))


def test_spec_title_reads_openapi_and_postman() -> None:
    assert spec_title(yaml.safe_load(OPENAPI_YAML)) == "Shop API"
    assert spec_title(POSTMAN_JSON) == "Pet Store"
    assert spec_title({"info": {}}) == "API"


# --- base URL extraction -------------------------------------------------


def test_openapi_base_urls_resolve_server_variables() -> None:
    raw = yaml.safe_load(OPENAPI_YAML)
    # {region}/{ver} substituted with their declared defaults
    assert spec_base_urls(raw) == ["https://eu.api.shop.test/v1"]


def test_openapi_drops_unresolved_relative_server() -> None:
    raw = {"openapi": "3.0.0", "info": {"title": "X"}, "servers": [{"url": "/v2"}]}
    # relative URL is not an authorizable host
    assert spec_base_urls(raw) == []


def test_swagger_base_urls_built_from_host() -> None:
    assert spec_base_urls(SWAGGER_JSON) == ["https://legacy.test/api"]


def test_swagger_without_host_yields_no_base_urls() -> None:
    assert spec_base_urls({"swagger": "2.0", "info": {}, "paths": {}}) == []


def test_postman_base_urls_from_request_hosts() -> None:
    assert spec_base_urls(POSTMAN_JSON) == ["https://petstore.test"]


def test_spec_base_urls_rejects_unrecognized() -> None:
    with pytest.raises(SpecParseError):
        spec_base_urls({"foo": 1})


# --- Postman variable / environment resolution ---------------------------

POSTMAN_WITH_VARS = {
    "info": {"_postman_id": "v-1", "name": "Var Collection"},
    "variable": [{"key": "baseUrl", "value": "https://api.vars.test"}],
    "item": [
        {"name": "Get thing", "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/things/1"}}}
    ],
}

POSTMAN_NEEDS_ENV = {
    "info": {"_postman_id": "e-1", "name": "Env Collection"},
    "item": [
        {"name": "Get thing", "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/things/1"}}}
    ],
}


def test_postman_resolves_collection_variables() -> None:
    assert spec_base_urls(POSTMAN_WITH_VARS) == ["https://api.vars.test"]


def test_postman_without_env_leaves_variable_unresolved() -> None:
    # {{baseUrl}} never resolves -> no absolute host recovered
    assert spec_base_urls(POSTMAN_NEEDS_ENV) == []


def test_postman_environment_values_resolve_base_url() -> None:
    resolved = spec_base_urls(
        POSTMAN_NEEDS_ENV,
        extra_variables={"baseUrl": "https://api.env.test"},
    )
    assert resolved == ["https://api.env.test"]


# --- Postman API fetch ---------------------------------------------------


class _FakeResponse:
    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        return self._payload


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


def test_fetch_postman_missing_key_raises() -> None:
    with pytest.raises(SpecParseError, match="POSTMAN_API_KEY"):
        fetch_postman_collection("abc-123", "")


def test_fetch_postman_404_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(requests, "get", lambda *_a, **_k: _FakeResponse(404, {}))
    with pytest.raises(SpecParseError, match="not found"):
        fetch_postman_collection("missing", "PMAK-xyz")


def test_fetch_postman_401_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(requests, "get", lambda *_a, **_k: _FakeResponse(401, {}))
    with pytest.raises(SpecParseError, match="rejected the key"):
        fetch_postman_collection("abc-123", "bad-key")


def test_fetch_postman_empty_collection_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(requests, "get", lambda *_a, **_k: _FakeResponse(200, {"collection": {}}))
    with pytest.raises(SpecParseError, match="empty"):
        fetch_postman_collection("abc-123", "PMAK-xyz")


def test_fetch_postman_environment_returns_enabled_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "environment": {
            "name": "prod",
            "values": [
                {"key": "baseUrl", "value": "https://api.env.test", "enabled": True},
                {"key": "secretToken", "value": "s3cr3t", "enabled": False},
            ],
        }
    }
    monkeypatch.setattr(requests, "get", lambda *_a, **_k: _FakeResponse(200, payload))
    values = fetch_postman_environment("env-1", "PMAK-xyz")
    assert values == {"baseUrl": "https://api.env.test"}  # disabled secret excluded


def _dispatch_get(
    collection: dict[str, Any],
    env: dict[str, Any],
) -> Callable[..., _FakeResponse]:
    def fake_get(url: str, **_kwargs: Any) -> _FakeResponse:
        if "/environments/" in url:
            return _FakeResponse(200, env)
        return _FakeResponse(200, {"collection": collection})

    return fake_get


def test_fetch_then_resolve_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    env = {"environment": {"values": [{"key": "baseUrl", "value": "https://api.env.test"}]}}
    monkeypatch.setattr(requests, "get", _dispatch_get(POSTMAN_NEEDS_ENV, env))

    collection = fetch_postman_collection("coll-1", "PMAK-xyz")
    variables = fetch_postman_environment("env-1", "PMAK-xyz")
    assert spec_base_urls(collection, extra_variables=variables) == ["https://api.env.test"]
