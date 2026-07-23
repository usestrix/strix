"""Integration of the ``api_spec`` target type into detection and input builders."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.core.inputs import build_root_task, build_scope_context
from strix.interface.utils import infer_target_type


OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "Shop API", "version": "1"},
    "servers": [{"url": "https://api.shop.test/v1"}],
    "paths": {
        "/users/{id}": {
            "get": {
                "summary": "Get user",
                "parameters": [{"name": "id", "in": "path", "schema": {"type": "string"}}],
            }
        }
    },
}


def _spec_target(tmp_path: Path) -> dict[str, object]:
    path = tmp_path / "openapi.json"
    path.write_text(json.dumps(OPENAPI), encoding="utf-8")
    ttype, details = infer_target_type(str(path))
    return {"type": ttype, "details": details, "original": str(path)}


def test_infer_target_type_detects_api_spec(tmp_path: Path) -> None:
    target = _spec_target(tmp_path)
    assert target["type"] == "api_spec"
    assert target["details"]["spec_format"] == "openapi"
    assert Path(target["details"]["target_spec"]).is_absolute()


def test_infer_target_type_still_rejects_non_spec_file(tmp_path: Path) -> None:
    path = tmp_path / "data.json"
    path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    with pytest.raises(ValueError, match="not a directory"):
        infer_target_type(str(path))


def test_infer_target_type_detects_postman_uri() -> None:
    ttype, details = infer_target_type("postman://12345-abcdef-uid")
    assert ttype == "api_spec"
    assert details["source"] == "postman_api"
    assert details["collection_uid"] == "12345-abcdef-uid"
    assert details["spec_format"] == "postman"


def test_infer_target_type_rejects_empty_postman_uri() -> None:
    with pytest.raises(ValueError, match="collection id"):
        infer_target_type("postman://")


def test_infer_target_type_parses_postman_environment() -> None:
    _ttype, details = infer_target_type("postman://coll-uid?env=env-uid")
    assert details["collection_uid"] == "coll-uid"
    assert details["environment_uid"] == "env-uid"


def test_infer_target_type_postman_without_env_omits_key() -> None:
    _ttype, details = infer_target_type("postman://coll-uid")
    assert "environment_uid" not in details


def test_build_root_task_renders_endpoint_inventory(tmp_path: Path) -> None:
    task = build_root_task({"targets": [_spec_target(tmp_path)]})
    assert "API Specifications" in task
    assert "Shop API (openapi)" in task
    assert "https://api.shop.test/v1" in task
    assert "GET /users/{id}" in task


def test_build_scope_context_authorizes_base_urls(tmp_path: Path) -> None:
    context = build_scope_context({"targets": [_spec_target(tmp_path)]})
    authorized = context["authorized_targets"]

    types = {a["type"] for a in authorized}
    assert "api_spec" in types
    assert "web_application" in types
    assert any(a["value"] == "https://api.shop.test/v1" for a in authorized)
