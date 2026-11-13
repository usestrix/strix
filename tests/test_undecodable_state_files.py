"""A state file that is not UTF-8 must not stop the tool that reads it.

Each store is written UTF-8 with ``ensure_ascii=False``, so an interrupted write can
leave a truncated multi-byte sequence: the file is then readable but not decodable,
which raises ``UnicodeDecodeError`` - a ``ValueError``, so it never matches an
``OSError`` or ``json.JSONDecodeError`` handler.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from strix.config import codex
from strix.interface.platform_identity import read_or_create_identity
from strix.interface.viewer import auth as viewer_auth
from strix.report import coverage as coverage_report
from strix.tools.coverage import tools as coverage_tools
from strix.tools.mcp import loader as mcp_loader
from strix.tools.notes import tools as notes_tools
from strix.tools.threat_model import tools as threat_model_tools
from strix.tools.todo import tools as todo_tools


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def _undecodable(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(b'{"truncated": "\xff\xfe"}')
    return path


@pytest.mark.parametrize(
    ("hydrate", "file_name"),
    [
        (todo_tools.hydrate_todos_from_disk, "todos.json"),
        (notes_tools.hydrate_notes_from_disk, "notes.json"),
        (threat_model_tools.hydrate_threat_models_from_disk, "threat_models.json"),
        (coverage_tools.hydrate_coverage_from_disk, "coverage.json"),
    ],
)
def test_a_hydrate_from_an_undecodable_file_keeps_the_store_empty(
    tmp_path: Path, hydrate: Callable[[Path], None], file_name: str
) -> None:
    _undecodable(tmp_path, file_name)

    hydrate(tmp_path)  # must not raise


def test_an_undecodable_mcp_config_reads_as_no_connections(tmp_path: Path) -> None:
    path = _undecodable(tmp_path, "mcp.json")

    assert mcp_loader.load_user_mcp_configs(path) == []


def test_a_decodable_config_is_still_read(tmp_path: Path) -> None:
    """The guard must not swallow the healthy path."""
    path = tmp_path / "mcp.json"
    path.write_text(
        json.dumps([{"name": "example", "url": "https://example.com/mcp"}]),
        encoding="utf-8",
    )

    configs = mcp_loader.load_user_mcp_configs(path)
    assert len(configs) == 1
    assert configs[0].name == "example"
    assert configs[0].url == "https://example.com/mcp"


def test_an_undecodable_subscription_store_reads_as_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _undecodable(tmp_path, "subscription-auth.json")
    monkeypatch.setattr(codex, "AUTH_PATH", path)

    assert codex._read_store() == {}


def test_an_undecodable_identity_file_still_yields_an_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _undecodable(tmp_path, "identity.json")
    monkeypatch.setattr("strix.interface.platform_identity.IDENTITY_PATH", path)

    record = read_or_create_identity()

    assert record["client_instance_id"]


def test_an_undecodable_auth_file_reads_as_signed_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _undecodable(tmp_path, "auth.json")
    monkeypatch.setattr(viewer_auth, "AUTH_PATH", path)

    assert viewer_auth.read_auth() is None


def test_an_undecodable_agent_graph_reads_as_empty(tmp_path: Path) -> None:
    _undecodable(tmp_path, "agents.json")

    assert coverage_report.read_agent_graph(tmp_path) == {}
