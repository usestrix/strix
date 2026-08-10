"""Tests for the optional-dependency extras declared in pyproject.toml."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
BUILD_RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "build-release.yml"


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


def test_release_build_selects_bedrock_extra() -> None:
    """Standalone release binaries must bundle boto3, or Bedrock users hit
    ``ModuleNotFoundError: No module named 'boto3'`` at LLM warm-up with no
    way to install it into a frozen binary (#574)."""
    workflow = yaml.safe_load(BUILD_RELEASE_WORKFLOW.read_text(encoding="utf-8"))
    build_step = next(
        step
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if step.get("name") == "Build"
    )
    assert "uv sync --frozen --extra bedrock" in build_step["run"]


def test_litellm_pinned_past_bedrock_tool_choice_fix() -> None:
    """litellm <1.95.0 maps Bedrock's ``parallel_tool_calls`` to a
    ``tool_choice`` object missing the required ``type`` discriminator,
    so every Bedrock Claude request 400s with ``tool_choice.type: Field
    required`` (BerriAI/litellm#34347, fixed in litellm 1.95.0)."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    litellm_spec = next(dep for dep in data["project"]["dependencies"] if dep.startswith("litellm"))
    match = re.search(r">=\s*(\d+)\.(\d+)\.(\d+)", litellm_spec)
    assert match, f"expected a >= floor on litellm, got: {litellm_spec!r}"
    assert (int(match[1]), int(match[2])) >= (1, 95)
