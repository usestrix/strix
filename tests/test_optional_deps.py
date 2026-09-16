"""Tests for the optional-dependency extras declared in pyproject.toml."""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
PYINSTALLER_SPEC = REPO_ROOT / "strix.spec"
BUILD_RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "build-release.yml"


def _optional_dependencies() -> dict[str, list[str]]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    extras: dict[str, list[str]] = data["project"]["optional-dependencies"]
    return extras


def test_vertex_extra_pins_google_auth() -> None:
    extras = _optional_dependencies()
    assert "vertex" in extras
    assert any(req.startswith("google-auth") for req in extras["vertex"])


def test_bedrock_extra_pins_boto3() -> None:
    extras = _optional_dependencies()
    assert "bedrock" in extras
    assert any(req.startswith("boto3") for req in extras["bedrock"])


def _pyinstaller_excludes() -> list[str]:
    """Read the ``excludes`` list from strix.spec without executing it.

    Executing the spec imports PyInstaller, so parse it and take the literal.
    """
    tree = ast.parse(PYINSTALLER_SPEC.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "excludes" for t in node.targets
        ):
            excludes: list[str] = ast.literal_eval(node.value)
            return excludes
    raise AssertionError("strix.spec defines no `excludes` list")


def _is_excluded(module: str, excludes: list[str]) -> bool:
    # PyInstaller drops a module when it or any parent package is excluded.
    parts = module.split(".")
    return any(".".join(parts[:i]) in excludes for i in range(1, len(parts) + 1))


def test_binary_keeps_the_google_auth_modules_vertex_needs() -> None:
    """The standalone binary must be able to authenticate to Vertex AI.

    litellm's vertex_ai Gemini path imports google.auth and google.oauth2 for
    every call. Excluding them from the PyInstaller bundle made every Vertex
    model fail with ``No module named 'google'`` on the binary install.
    """
    excludes = _pyinstaller_excludes()
    for module in (
        "google.auth",
        "google.auth.credentials",
        "google.auth.transport.requests",
        "google.oauth2",
        "google.oauth2.service_account",
    ):
        assert not _is_excluded(module, excludes), f"{module} is excluded from the binary"


def test_release_build_installs_the_vertex_extra() -> None:
    """Keeping google.auth in the bundle only helps if the build installs it."""
    workflow = BUILD_RELEASE_WORKFLOW.read_text(encoding="utf-8")
    # A commented-out command must not satisfy the check: a build that stopped
    # installing the extra would otherwise still pass on the comment's text.
    sync_lines = [
        line.strip()
        for line in workflow.splitlines()
        if "uv sync" in line and not line.lstrip().startswith("#")
    ]
    assert sync_lines, "the release workflow no longer runs uv sync"
    assert all("--extra vertex" in line for line in sync_lines), sync_lines


def test_workflow_check_ignores_commented_out_sync_commands(tmp_path: Path) -> None:
    """The workflow check must read commands, not comments that mention them."""
    workflow = tmp_path / "build-release.yml"
    workflow.write_text(
        "        run: |\n          # uv sync --frozen --extra vertex\n          uv sync --frozen\n",
        encoding="utf-8",
    )

    sync_lines = [
        line.strip()
        for line in workflow.read_text(encoding="utf-8").splitlines()
        if "uv sync" in line and not line.lstrip().startswith("#")
    ]

    assert sync_lines == ["uv sync --frozen"]
    assert not all("--extra vertex" in line for line in sync_lines)
