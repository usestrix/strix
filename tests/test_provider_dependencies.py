"""Vertex AI and Bedrock support ship with every install, not as extras."""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent.parent


def _pyproject() -> dict[str, object]:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


@pytest.mark.parametrize("package", ["google-auth", "boto3"])
def test_provider_packages_are_regular_dependencies(package: str) -> None:
    project = _pyproject()["project"]
    assert isinstance(project, dict)
    assert any(req.startswith(package) for req in project["dependencies"])
    assert "optional-dependencies" not in project


@pytest.mark.parametrize(
    "module",
    [
        "google.auth",
        "google.auth.transport.requests",
        "google.oauth2.service_account",
        "boto3",
        "litellm.llms.vertex_ai.vertex_llm_base",
        "litellm.llms.bedrock.base_aws_llm",
    ],
)
def test_provider_modules_import(module: str) -> None:
    importlib.import_module(module)


def test_pyinstaller_spec_bundles_google_auth() -> None:
    spec = (ROOT / "strix.spec").read_text(encoding="utf-8")
    assert "collect_submodules('google.auth')" in spec
    assert "'google.auth'," not in spec
    assert "'google.oauth2'," not in spec
