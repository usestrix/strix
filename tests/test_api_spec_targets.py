"""Integration of the ``api_spec`` target type into detection, staging, and inputs."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

import pytest

from strix.core.inputs import build_root_task, build_scope_context
from strix.interface.scan_setup import build_targets_info
from strix.interface.utils import (
    infer_target_type,
    stage_api_specs,
    write_fetched_collection,
    write_postman_environment,
)


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


def _write_spec(directory: Path, name: str = "openapi.json") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(json.dumps(OPENAPI), encoding="utf-8")
    return path


def _resolved_targets(*spec_paths: Path) -> list[dict[str, Any]]:
    """Run spec targets through the real setup path (detection + spec resolution)."""
    args = argparse.Namespace(target=[str(p) for p in spec_paths], target_list=None)
    build_targets_info(args)
    targets: list[dict[str, Any]] = args.targets_info
    return targets


def _staged_target(tmp_path: Path, run_name: str = "test-run") -> dict[str, Any]:
    targets = _resolved_targets(_write_spec(tmp_path / "src"))
    stage_api_specs(targets, run_name)
    return targets[0]


def test_infer_target_type_detects_api_spec(tmp_path: Path) -> None:
    path = _write_spec(tmp_path)
    ttype, details = infer_target_type(str(path))
    assert ttype == "api_spec"
    assert details["spec_format"] == "openapi"
    assert Path(details["target_spec"]).is_absolute()


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


def test_a_fetched_postman_environment_is_staged_beside_its_collection(tmp_path: Path) -> None:
    """The collection keeps its ``{{placeholders}}``, so the values have to travel with it."""
    environment = tmp_path / "coll-uid.postman_environment.json"
    environment.write_text(json.dumps({"tenantId": "acme"}), encoding="utf-8")
    targets = _resolved_targets(_write_spec(tmp_path / "src"))
    targets[0]["details"]["environment_file"] = str(environment)

    stage_api_specs(targets, "env-run")

    details = targets[0]["details"]
    assert details["environment_path"] == ("/workspace/api-specs/coll-uid.postman_environment.json")
    staged = Path(tempfile.gettempdir()) / "strix_api_specs" / "env-run"
    assert (staged / "coll-uid.postman_environment.json").exists()
    assert json.loads((staged / "coll-uid.postman_environment.json").read_text("utf-8")) == {
        "tenantId": "acme"
    }


def test_the_root_task_points_at_the_staged_environment(tmp_path: Path) -> None:
    target = _staged_target(tmp_path)
    target["details"]["environment_path"] = "/workspace/api-specs/coll-uid.postman_environment.json"

    task = build_root_task({"targets": [target]})

    assert "/workspace/api-specs/coll-uid.postman_environment.json" in task
    assert "{{name}}" in task


def test_the_root_task_omits_the_environment_line_without_one(tmp_path: Path) -> None:
    task = build_root_task({"targets": [_staged_target(tmp_path)]})

    assert "Environment variables from the selected environment" not in task


def test_build_targets_info_records_title_and_base_urls(tmp_path: Path) -> None:
    (target,) = _resolved_targets(_write_spec(tmp_path))
    assert target["details"]["spec_title"] == "Shop API"
    assert target["details"]["base_urls"] == ["https://api.shop.test/v1"]


def test_build_targets_info_rejects_unparseable_spec(tmp_path: Path) -> None:
    path = tmp_path / "openapi.json"
    path.write_text('{"openapi": "3.0.0", "info": {"title": "X"}, "paths"', encoding="utf-8")
    args = argparse.Namespace(target=[str(path)], target_list=None)
    # a broken file is not recognized as a spec, so it fails as an unusable target
    with pytest.raises(ValueError, match="Invalid target"):
        build_targets_info(args)


def test_stage_api_specs_copies_spec_into_workspace_dir(tmp_path: Path) -> None:
    targets = _resolved_targets(_write_spec(tmp_path / "src"))
    (source,) = stage_api_specs(targets, "stage-run")

    assert source["workspace_subdir"] == "api-specs"
    staged = Path(source["source_path"]) / "openapi.json"
    assert json.loads(staged.read_text(encoding="utf-8"))["info"]["title"] == "Shop API"
    assert targets[0]["details"]["workspace_path"] == "/workspace/api-specs/openapi.json"


def test_stage_api_specs_disambiguates_same_filename(tmp_path: Path) -> None:
    targets = _resolved_targets(
        _write_spec(tmp_path / "a"),
        _write_spec(tmp_path / "b"),
    )
    (source,) = stage_api_specs(targets, "dupe-run")

    staged_paths = [t["details"]["workspace_path"] for t in targets]
    assert staged_paths == [
        "/workspace/api-specs/openapi.json",
        "/workspace/api-specs/openapi-2.json",
    ]
    assert (Path(source["source_path"]) / "openapi-2.json").is_file()


def test_stage_api_specs_without_specs_returns_nothing() -> None:
    assert stage_api_specs([{"type": "web_application", "details": {}}], "run") == []


def test_build_root_task_points_at_the_spec_file(tmp_path: Path) -> None:
    task = build_root_task({"targets": [_staged_target(tmp_path)]})
    assert "API Specifications" in task
    assert "Shop API (openapi specification" in task
    assert "/workspace/api-specs/openapi.json" in task
    assert "https://api.shop.test/v1" in task
    assert "test every operation it declares" in task


def test_build_scope_context_authorizes_base_urls(tmp_path: Path) -> None:
    context = build_scope_context({"targets": [_staged_target(tmp_path)]})
    authorized = context["authorized_targets"]

    types = {a["type"] for a in authorized}
    assert "api_spec" in types
    assert "web_application" in types
    assert any(a["value"] == "https://api.shop.test/v1" for a in authorized)


def test_two_environments_of_one_collection_do_not_overwrite_each_other(
    tmp_path: Path,
) -> None:
    """`--target postman://C?env=A --target postman://C?env=B` must keep both value sets."""
    first = write_postman_environment({"tenantId": "acme"}, "coll-uid", "env-a")
    second = write_postman_environment({"tenantId": "globex"}, "coll-uid", "env-b")

    assert first != second
    assert json.loads(Path(first).read_text("utf-8")) == {"tenantId": "acme"}
    assert json.loads(Path(second).read_text("utf-8")) == {"tenantId": "globex"}

    targets = _resolved_targets(_write_spec(tmp_path / "src"), _write_spec(tmp_path / "src2"))
    targets[0]["details"]["environment_file"] = first
    targets[1]["details"]["environment_file"] = second
    stage_api_specs(targets, "two-env-run")

    paths = [target["details"]["environment_path"] for target in targets]
    assert paths[0] != paths[1]
    assert json.loads(Path(first).read_text("utf-8"))["tenantId"] == "acme"


def test_a_fetched_environment_is_owner_only_from_creation() -> None:
    """The values must never exist in a world-readable file, not even between two calls."""
    path = Path(write_postman_environment({"fixtureToken": "secret"}, "coll-uid", "env-a"))
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text("utf-8")) == {"fixtureToken": "secret"}


def test_a_fetched_collection_is_owner_only_from_creation() -> None:
    """A collection carries its own variables and auth blocks, not just an item tree."""
    path = Path(
        write_fetched_collection(
            {
                "info": {"_postman_id": "coll-uid"},
                "item": [],
                "variable": [{"key": "token", "value": "x"}],
            },
            "coll-uid",
        )
    )
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text("utf-8"))["variable"][0]["key"] == "token"


def test_environment_pairs_that_join_the_same_way_get_distinct_files() -> None:
    """`a-b` + `c` and `a` + `b-c` read the same joined name; the digest keeps them apart."""
    first = write_postman_environment({"tenantId": "A"}, "a-b", "c")
    second = write_postman_environment({"tenantId": "B"}, "a", "b-c")

    assert first != second
    assert json.loads(Path(first).read_text("utf-8")) == {"tenantId": "A"}
    assert json.loads(Path(second).read_text("utf-8")) == {"tenantId": "B"}


def test_collection_ids_that_sanitize_alike_get_distinct_files() -> None:
    """`a/b` and `a:b` both sanitize to `a-b`; the digest keeps the two collections apart."""
    first = write_fetched_collection(
        {"info": {"_postman_id": "a/b"}, "item": [{"name": "slash"}]}, "a/b"
    )
    second = write_fetched_collection(
        {"info": {"_postman_id": "a:b"}, "item": [{"name": "colon"}]}, "a:b"
    )

    assert first != second
    assert json.loads(Path(first).read_text("utf-8"))["item"][0]["name"] == "slash"
    assert json.loads(Path(second).read_text("utf-8"))["item"][0]["name"] == "colon"
