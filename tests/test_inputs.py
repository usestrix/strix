"""Tests for asset routing into the agent task, scope, and workspace mounts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from strix.core.inputs import build_root_task, build_scope_context
from strix.interface.utils import assign_workspace_subdirs, collect_local_sources


def _asset(asset_type: str, value: str, **extra: Any) -> dict[str, Any]:
    return {
        "type": "asset",
        "details": {"asset_type": asset_type, "value": value, **extra},
        "original": value,
    }


def test_build_root_task_lists_assets_and_existing_skill() -> None:
    cfg = {
        "targets": [_asset("cidr", "10.0.0.0/8"), _asset("graphql_endpoint", "https://x/graphql")]
    }
    task = build_root_task(cfg)
    assert "CIDR: 10.0.0.0/8" in task
    assert "GraphQL Endpoint: https://x/graphql" in task
    # graphql skill ships with the repo -> recommended; cidr skill does not exist yet.
    assert "Load the `graphql` skill" in task
    assert "Load the `cidr` skill" not in task


def test_build_scope_context_uses_asset_type_as_label() -> None:
    cfg = {"targets": [_asset("aws_account", "123456789012")]}
    authorized = build_scope_context(cfg)["authorized_targets"]
    assert authorized == [
        {"type": "aws_account", "value": "123456789012", "workspace_path": ""},
    ]


def test_file_asset_collected_as_local_file_source(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    targets = [_asset("android_apk", str(apk))]
    assign_workspace_subdirs(targets)
    assert targets[0]["details"]["workspace_subdir"] == "app.apk"
    assert collect_local_sources(targets) == [
        {"source_path": str(apk), "workspace_subdir": "app.apk", "is_dir": False},
    ]


def test_identifier_asset_is_not_mounted() -> None:
    targets = [_asset("cidr", "10.0.0.0/8")]
    assign_workspace_subdirs(targets)
    assert "workspace_subdir" not in targets[0]["details"]
    assert collect_local_sources(targets) == []
