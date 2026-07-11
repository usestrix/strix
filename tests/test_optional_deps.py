"""Tests for the optional-dependency extras declared in pyproject.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path


PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _optional_dependencies() -> dict[str, list[str]]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return data["project"]["optional-dependencies"]


def test_vertex_extra_pins_google_auth() -> None:
    extras = _optional_dependencies()
    assert "vertex" in extras
    assert any(req.startswith("google-auth") for req in extras["vertex"])


def test_bedrock_extra_pins_boto3() -> None:
    extras = _optional_dependencies()
    assert "bedrock" in extras
    assert any(req.startswith("boto3") for req in extras["bedrock"])
