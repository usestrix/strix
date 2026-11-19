"""Integration of the ``api_spec`` target type into detection, staging, and inputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest

from strix.core.inputs import build_root_task, build_scope_context
from strix.interface.scan_setup import build_targets_info
from strix.interface.utils import infer_target_type, stage_api_specs


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


def _write_spec_with_ref(directory: Path, reference: str, name: str = "openapi.json") -> Path:
    spec = {
        **OPENAPI,
        "components": {"schemas": {"User": {"$ref": reference}}},
    }
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _isolate_staging(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    staging_root = tmp_path / "temporary"
    monkeypatch.setattr("strix.interface.utils.tempfile.gettempdir", lambda: str(staging_root))


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
    original = _write_spec(tmp_path / "src")
    targets = _resolved_targets(original)
    (source,) = stage_api_specs(targets, "stage-run")

    assert source["workspace_subdir"] == "api-specs"
    staged = Path(source["source_path"]) / "openapi.json"
    assert json.loads(staged.read_text(encoding="utf-8"))["info"]["title"] == "Shop API"
    assert staged.read_bytes() == original.read_bytes()
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


def test_stage_api_specs_copies_transitive_json_and_yaml_refs(tmp_path: Path) -> None:
    source_dir = tmp_path / "src"
    spec = _write_spec_with_ref(source_dir, "./schemas/User.json#/definitions/User")
    schemas = source_dir / "schemas"
    schemas.mkdir()
    (schemas / "User.json").write_text(
        json.dumps({"definitions": {"User": {"$ref": "../common.yaml#/User"}}}),
        encoding="utf-8",
    )
    (source_dir / "common.yaml").write_text("User:\n  type: object\n", encoding="utf-8")
    (source_dir / "unused.yaml").write_text("Secret: unreferenced\n", encoding="utf-8")

    targets = _resolved_targets(spec)
    (staged_source,) = stage_api_specs(targets, "relative-refs")
    staged = Path(staged_source["source_path"])

    assert (staged / "openapi.json").is_file()
    assert (staged / "schemas" / "User.json").is_file()
    assert (staged / "common.yaml").is_file()
    assert not (staged / "unused.yaml").exists()
    assert (staged / "openapi.json").read_bytes() == spec.read_bytes()
    assert staged_source["workspace_subdir"] == "api-specs"
    assert targets[0]["details"]["workspace_path"] == "/workspace/api-specs/openapi.json"


def test_stage_api_specs_terminates_local_ref_cycles(tmp_path: Path) -> None:
    source_dir = tmp_path / "src"
    spec = _write_spec_with_ref(source_dir, "schemas/User.yaml#/User")
    schemas = source_dir / "schemas"
    schemas.mkdir()
    (schemas / "User.yaml").write_text(
        "User:\n  allOf:\n    - $ref: ../openapi.json#/components/schemas/User\n",
        encoding="utf-8",
    )

    (staged_source,) = stage_api_specs(_resolved_targets(spec), "cyclic-refs")
    staged = Path(staged_source["source_path"])

    assert sorted(path.relative_to(staged) for path in staged.rglob("*") if path.is_file()) == [
        Path("openapi.json"),
        Path("schemas/User.yaml"),
    ]


def test_stage_api_specs_keeps_fragment_only_refs_internal(tmp_path: Path) -> None:
    spec = _write_spec_with_ref(tmp_path / "src", "#/components/schemas/Local")

    (staged_source,) = stage_api_specs(_resolved_targets(spec), "fragment-ref")
    staged = Path(staged_source["source_path"])

    assert [path.relative_to(staged) for path in staged.rglob("*") if path.is_file()] == [
        Path("openapi.json")
    ]


def test_stage_api_specs_does_not_fetch_remote_refs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = _write_spec_with_ref(tmp_path / "src", "https://schemas.example.test/User.json")

    def unexpected_fetch(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("remote reference was fetched")

    monkeypatch.setattr("strix.interface.utils.requests.get", unexpected_fetch)
    (staged_source,) = stage_api_specs(_resolved_targets(spec), "remote-ref")
    staged = Path(staged_source["source_path"])

    assert [path.relative_to(staged) for path in staged.rglob("*") if path.is_file()] == [
        Path("openapi.json")
    ]


def test_stage_api_specs_keeps_postman_collections_single_file(tmp_path: Path) -> None:
    collection = {
        "info": {"name": "Collection", "_postman_id": "fixture"},
        "item": [],
        "metadata": {"$ref": "missing.yaml"},
    }
    path = tmp_path / "collection.json"
    path.write_text(json.dumps(collection), encoding="utf-8")
    targets = _resolved_targets(path)

    (staged_source,) = stage_api_specs(targets, "postman-single-file")
    staged = Path(staged_source["source_path"])

    assert (staged / "collection.json").read_bytes() == path.read_bytes()
    assert targets[0]["details"]["workspace_path"] == "/workspace/api-specs/collection.json"


def test_stage_api_specs_rejects_missing_local_ref_without_partial_stage(tmp_path: Path) -> None:
    spec = _write_spec_with_ref(tmp_path / "src", "schemas/Missing.yaml#/User")
    targets = _resolved_targets(spec)

    with pytest.raises(ValueError, match=r"Missing\.yaml"):
        stage_api_specs(targets, "missing-ref")

    assert not (tmp_path / "temporary" / "strix_api_specs" / "missing-ref").exists()
    assert "workspace_path" not in targets[0]["details"]


def test_stage_api_specs_rejects_ref_outside_spec_root(tmp_path: Path) -> None:
    source_dir = tmp_path / "src"
    spec = _write_spec_with_ref(source_dir, "../outside.yaml#/User")
    (tmp_path / "outside.yaml").write_text("User: {type: object}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="outside the API spec directory"):
        stage_api_specs(_resolved_targets(spec), "escaping-ref")


def test_stage_api_specs_rejects_encoded_ref_escape(tmp_path: Path) -> None:
    source_dir = tmp_path / "src"
    spec = _write_spec_with_ref(source_dir, "..%2Foutside.yaml#/User")
    (tmp_path / "outside.yaml").write_text("User: {type: object}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="outside the API spec directory"):
        stage_api_specs(_resolved_targets(spec), "encoded-escape")


def test_stage_api_specs_rejects_symlinked_ref(tmp_path: Path) -> None:
    source_dir = tmp_path / "src"
    spec = _write_spec_with_ref(source_dir, "schemas/User.yaml#/User")
    schemas = source_dir / "schemas"
    schemas.mkdir()
    real_schema = schemas / "real.yaml"
    real_schema.write_text("User: {type: object}\n", encoding="utf-8")
    (schemas / "User.yaml").symlink_to(real_schema)

    with pytest.raises(ValueError, match="symbolic link"):
        stage_api_specs(_resolved_targets(spec), "symlink-ref")


def test_stage_api_specs_isolates_colliding_multifile_specs(tmp_path: Path) -> None:
    specs: list[Path] = []
    for directory, marker in (("a", "first"), ("b", "second")):
        source_dir = tmp_path / directory
        specs.append(_write_spec_with_ref(source_dir, "schemas/User.json"))
        schemas = source_dir / "schemas"
        schemas.mkdir()
        (schemas / "User.json").write_text(json.dumps({"marker": marker}), encoding="utf-8")

    targets = _resolved_targets(*specs)
    (staged_source,) = stage_api_specs(targets, "isolated-refs")
    staged = Path(staged_source["source_path"])

    assert [target["details"]["workspace_path"] for target in targets] == [
        "/workspace/api-specs/openapi/openapi.json",
        "/workspace/api-specs/openapi-2/openapi.json",
    ]
    assert json.loads((staged / "openapi" / "schemas" / "User.json").read_text())["marker"] == (
        "first"
    )
    assert (
        json.loads((staged / "openapi-2" / "schemas" / "User.json").read_text())["marker"]
        == "second"
    )


def test_stage_api_specs_rejects_unsupported_local_ref_type(tmp_path: Path) -> None:
    source_dir = tmp_path / "src"
    spec = _write_spec_with_ref(source_dir, "schemas/User.txt")
    schemas = source_dir / "schemas"
    schemas.mkdir()
    (schemas / "User.txt").write_text("not a JSON or YAML document", encoding="utf-8")

    with pytest.raises(ValueError, match="JSON or YAML"):
        stage_api_specs(_resolved_targets(spec), "unsupported-ref")


def test_stage_api_specs_validates_all_targets_before_publishing(tmp_path: Path) -> None:
    good = _write_spec(tmp_path / "good")
    bad = _write_spec_with_ref(tmp_path / "bad", "missing.yaml")
    targets = _resolved_targets(good, bad)
    targets[0]["details"]["workspace_path"] = "/workspace/api-specs/stale.json"

    with pytest.raises(ValueError, match=r"missing\.yaml"):
        stage_api_specs(targets, "atomic-stage")

    assert not (tmp_path / "temporary" / "strix_api_specs" / "atomic-stage").exists()
    assert all("workspace_path" not in target["details"] for target in targets)


def test_stage_api_specs_enforces_file_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_dir = tmp_path / "src"
    spec = _write_spec_with_ref(source_dir, "one.yaml")
    (source_dir / "one.yaml").write_text("$ref: two.yaml\n", encoding="utf-8")
    (source_dir / "two.yaml").write_text("type: object\n", encoding="utf-8")
    monkeypatch.setattr("strix.interface.utils._API_SPEC_MAX_FILES", 2)

    with pytest.raises(ValueError, match="2-file staging limit"):
        stage_api_specs(_resolved_targets(spec), "file-limit")


def test_stage_api_specs_enforces_limits_across_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    specs = [_write_spec(tmp_path / str(index)) for index in range(3)]
    monkeypatch.setattr("strix.interface.utils._API_SPEC_MAX_FILES", 2)

    with pytest.raises(ValueError, match="2-file staging limit"):
        stage_api_specs(_resolved_targets(*specs), "aggregate-file-limit")


def test_stage_api_specs_enforces_depth_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_dir = tmp_path / "src"
    spec = _write_spec_with_ref(source_dir, "one.yaml")
    (source_dir / "one.yaml").write_text("$ref: two.yaml\n", encoding="utf-8")
    (source_dir / "two.yaml").write_text("type: object\n", encoding="utf-8")
    monkeypatch.setattr("strix.interface.utils._API_SPEC_MAX_REF_DEPTH", 1)

    with pytest.raises(ValueError, match="1-level limit"):
        stage_api_specs(_resolved_targets(spec), "depth-limit")


def test_stage_api_specs_enforces_total_byte_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = _write_spec(tmp_path / "src")
    monkeypatch.setattr("strix.interface.utils._API_SPEC_MAX_TOTAL_BYTES", 10)

    with pytest.raises(ValueError, match="10-byte staging limit"):
        stage_api_specs(_resolved_targets(spec), "byte-limit")


def test_stage_api_specs_rejects_unsafe_run_name(tmp_path: Path) -> None:
    targets = _resolved_targets(_write_spec(tmp_path / "src"))

    with pytest.raises(ValueError, match="Invalid run name"):
        stage_api_specs(targets, "../outside")

    assert not (tmp_path / "outside").exists()


def test_stage_api_specs_rejects_symlinked_staging_directory(tmp_path: Path) -> None:
    source = _write_spec(tmp_path / "src")
    temporary_root = tmp_path / "temporary"
    temporary_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (temporary_root / "strix_api_specs").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="staging directory cannot be a symbolic link"):
        stage_api_specs(_resolved_targets(source), "symlinked-stage")

    assert list(outside.iterdir()) == []


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
