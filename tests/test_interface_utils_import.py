"""Tests that pure utility modules import without Docker or network side effects."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest


class TestInterfaceUtilsImportHygiene:
    """Group 2 — import-side-effect reduction."""

    def test_validate_repo_url_imports_without_docker(self) -> None:
        """Direct package import must succeed when docker is unavailable."""
        # We mock the docker module as unavailable to prove the module does
        # not import it at the top level. Any function that actually needs the
        # Docker daemon will fail at call time, not import time.
        sys.modules["docker"] = None  # type: ignore[assignment]
        try:
            from strix.interface.utils import (
                infer_target_type,
                rewrite_localhost_targets,
                validate_repo_url,
            )

            assert validate_repo_url("https://github.com/org/repo.git") == (
                "https://github.com/org/repo.git"
            )
            assert infer_target_type("https://example.com") == (
                "web_application",
                {"target_url": "https://example.com"},
            )
            targets = [
                {"type": "web_application", "details": {"target_url": "http://localhost:8080"}}
            ]
            rewrite_localhost_targets(targets, "host-gateway")
            assert targets[0]["details"]["target_url"] == "http://host-gateway:8080"
        finally:
            sys.modules.pop("docker", None)
            # Remove any partially-imported strix modules so later tests get a clean state.
            for name in list(sys.modules):
                if name.startswith("strix"):
                    del sys.modules[name]

    def test_check_docker_connection_lazily_imports_docker(self) -> None:
        """check_docker_connection must import docker only when called."""
        from docker.errors import DockerException

        from strix.interface import utils as interface_utils

        # docker is not imported at module load time.
        assert "docker" not in getattr(interface_utils, "__dict__", {})
        # The function is still callable; force a deterministic failure so
        # the test does not depend on whether a Docker daemon is running.
        with (
            patch("docker.from_env", side_effect=DockerException("mock")),
            pytest.raises(RuntimeError, match="Docker not available"),
        ):
            interface_utils.check_docker_connection()

    def test_net_package_imports_without_docker(self) -> None:
        """The new strix.core.net package must be pure and importable without docker."""
        sys.modules["docker"] = None  # type: ignore[assignment]
        try:
            from strix.core import net

            assert hasattr(net, "normalize_url")
            assert hasattr(net, "is_internal_target")
        finally:
            sys.modules.pop("docker", None)
            for name in list(sys.modules):
                if name.startswith("strix"):
                    del sys.modules[name]
