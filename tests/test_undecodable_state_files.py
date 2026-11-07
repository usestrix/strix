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
    path.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")

    assert mcp_loader.load_user_mcp_configs(path) == []
