"""Postman environments must survive target resolution and sandbox staging."""

from __future__ import annotations

import argparse
import copy
import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import requests

from strix.interface.scan_setup import build_targets_info
from strix.interface.utils import stage_api_specs
from strix.utils.api_spec import postman_variables


COLLECTION = {
    "info": {"_postman_id": "collection-1", "name": "Environment handoff"},
    "variable": [
        {"key": "baseUrl", "value": "https://default.test", "description": "API host"},
        {"key": "fallback", "value": "collection fallback"},
        {"key": "unusedDefault", "value": "{{unusedSecret}}"},
    ],
    "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{ token }}"}]},
    "item": [
        {
            "name": "Nested folder",
            "item": [
                {
                    "request": {
                        "method": "POST",
                        "url": "{{baseUrl}}/tenants/{{tenant}}",
                        "header": [{"key": "X-Fallback", "value": "{{fallback}}"}],
                        "body": {"mode": "raw", "raw": '{"account": "{{account}}"}'},
                    }
                }
            ],
        }
    ],
}


@pytest.fixture
def postman_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    collection = copy.deepcopy(COLLECTION)
    payloads: dict[str, Any] = {
        "collection": collection,
        "environments": {
            "env-1": [
                {"key": "baseUrl", "value": "https://one.test"},
                {"key": "token", "value": "{{accessToken}}"},
                {"key": "accessToken", "value": "scan-only-token"},
                {"key": "tenant", "value": "tenant-one"},
                {"key": "account", "value": ""},
                {"key": "fallback", "value": "disabled value", "enabled": False},
                {"key": "unusedSecret", "value": "unrelated-secret"},
            ],
            "env-2": [
                {"key": "baseUrl", "value": "https://two.test"},
                {"key": "tenant", "value": "tenant-two"},
            ],
        },
        "calls": [],
    }

    def get(url: str, **kwargs: Any) -> SimpleNamespace:
        assert kwargs["headers"]["X-Api-Key"] == "host-only-api-key"
        payloads["calls"].append(url)
        if "/environments/" in url:
            body = {"environment": {"values": payloads["environments"][url.rsplit("/", 1)[1]]}}
        else:
            body = {"collection": collection}
        return SimpleNamespace(status_code=200, json=lambda: body)

    monkeypatch.setattr(requests, "get", get)
    monkeypatch.setattr("strix.interface.utils.tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(
        "strix.interface.scan_setup.load_settings",
        lambda: SimpleNamespace(integrations=SimpleNamespace(postman_api_key="host-only-api-key")),
    )
    return payloads


def _targets(*uris: str) -> list[dict[str, Any]]:
    args = argparse.Namespace(target=list(uris), target_list=None)
    build_targets_info(args)
    targets: list[dict[str, Any]] = args.targets_info
    return targets


def test_environment_values_reach_the_staged_collection(postman_api: dict[str, Any]) -> None:
    targets = _targets("postman://collection-1?env=env-1")
    (source,) = stage_api_specs(targets, "environment-handoff")
    details = targets[0]["details"]
    staged = Path(source["source_path"]) / Path(details["workspace_path"]).name
    raw = json.loads(staged.read_text())
    variables = postman_variables(raw)

    assert details["base_urls"] == ["https://one.test"]
    assert variables["baseUrl"] == "https://one.test"
    assert variables["token"] == "{{accessToken}}"  # noqa: S105 - unresolved template
    assert variables["accessToken"] == "scan-only-token"
    assert variables["tenant"] == "tenant-one"
    assert variables["account"] == ""
    assert variables["fallback"] == "collection fallback"
    assert "unusedSecret" not in variables
    assert "host-only-api-key" not in staged.read_text()
    assert "unrelated-secret" not in staged.read_text()
    assert "scan-only-token" not in json.dumps(targets)
    assert raw["auth"] == COLLECTION["auth"]
    assert raw["item"] == COLLECTION["item"]
    assert raw["variable"][0]["description"] == "API host"
    assert postman_api["collection"] == COLLECTION


@pytest.mark.usefixtures("postman_api")
def test_two_environments_of_one_collection_keep_distinct_snapshots() -> None:
    targets = _targets("postman://collection-1?env=env-1", "postman://collection-1?env=env-2")
    assert targets[0]["details"]["target_spec"] != targets[1]["details"]["target_spec"]
    (source,) = stage_api_specs(targets, "two-environments")
    assert targets[0]["details"]["workspace_path"] != targets[1]["details"]["workspace_path"]
    for target, expected in zip(targets, ("tenant-one", "tenant-two"), strict=True):
        staged = Path(source["source_path"]) / Path(target["details"]["workspace_path"]).name
        assert postman_variables(json.loads(staged.read_text()))["tenant"] == expected


@pytest.mark.usefixtures("postman_api")
def test_environment_snapshot_is_private_before_and_after_staging() -> None:
    targets = _targets("postman://collection-1?env=env-1")
    assert Path(targets[0]["details"]["target_spec"]).stat().st_mode & 0o777 == 0o600
    (source,) = stage_api_specs(targets, "private-environment")
    staged = Path(source["source_path"]) / Path(targets[0]["details"]["workspace_path"]).name
    assert staged.stat().st_mode & 0o777 == 0o600


def test_collection_without_environment_keeps_its_contents(postman_api: dict[str, Any]) -> None:
    (target,) = _targets("postman://collection-1")
    assert json.loads(Path(target["details"]["target_spec"]).read_text()) == COLLECTION
    assert len(postman_api["calls"]) == 1


def test_referenced_variable_cycles_do_not_expand_forever(postman_api: dict[str, Any]) -> None:
    postman_api["environments"]["env-1"] = [
        {"key": "token", "value": "{{cycle}}"},
        {"key": "cycle", "value": "{{token}}"},
    ]
    (target,) = _targets("postman://collection-1?env=env-1")
    variables = postman_variables(json.loads(Path(target["details"]["target_spec"]).read_text()))
    assert variables["token"] == "{{cycle}}"  # noqa: S105 - unresolved template
    assert variables["cycle"] == "{{token}}"


def test_references_in_collection_values_find_environment_dependencies(
    postman_api: dict[str, Any],
) -> None:
    postman_api["collection"]["variable"].append({"key": "token", "value": "{{accessToken}}"})
    postman_api["environments"]["env-1"] = [{"key": "accessToken", "value": "scan-only-token"}]
    (target,) = _targets("postman://collection-1?env=env-1")
    variables = postman_variables(json.loads(Path(target["details"]["target_spec"]).read_text()))
    assert variables["token"] == "{{accessToken}}"  # noqa: S105 - unresolved template
    assert variables["accessToken"] == "scan-only-token"


@pytest.mark.usefixtures("postman_api")
def test_staging_releases_the_download_snapshot_and_keeps_the_run_copy() -> None:
    targets = _targets("postman://collection-1?env=env-1")
    downloaded = Path(targets[0]["details"]["target_spec"])
    (source,) = stage_api_specs(targets, "snapshot-cleanup")

    assert not downloaded.parent.exists()
    staged = Path(targets[0]["details"]["target_spec"])
    assert staged.parent == Path(source["source_path"])
    assert postman_variables(json.loads(staged.read_text()))["tenant"] == "tenant-one"
    # Repeating setup uses the retained run snapshot rather than a removed input.
    assert stage_api_specs(targets, "snapshot-cleanup") == [source]


@pytest.mark.usefixtures("postman_api")
def test_failed_staging_keeps_downloads_available_for_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    targets = _targets("postman://collection-1?env=env-1")
    downloaded = Path(targets[0]["details"]["target_spec"])
    copy_file = shutil.copy2

    def fail_copy(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("staging unavailable")

    monkeypatch.setattr(shutil, "copy2", fail_copy)
    with pytest.raises(OSError, match="staging unavailable"):
        stage_api_specs(targets, "failed-staging")
    assert downloaded.is_file()
    monkeypatch.setattr(shutil, "copy2", copy_file)
    stage_api_specs(targets, "failed-staging")
    assert not downloaded.parent.exists()
