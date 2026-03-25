"""Pytest configuration and shared fixtures for Strix tests."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from strix.config import Config


@pytest.fixture
def write_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Callable[[dict[str, Any]], Path]]:
    config_path = tmp_path / "config.json"

    def _write(data: dict[str, Any]) -> Path:
        config_path.write_text(json.dumps(data), encoding="utf-8")
        monkeypatch.setattr(Config, "_config_file_override", config_path)
        Config.reload()
        return config_path

    _write({})
    yield _write
    monkeypatch.setattr(Config, "_config_file_override", None)
    Config.reload()
