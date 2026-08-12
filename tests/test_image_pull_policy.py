­r‡^Ñf¥–Ø¦{O,yÊ'vÃ®¶›­"""Regression tests for sandbox image acquisition policy."""

from __future__ import annotations

from typing import Literal
from unittest.mock import MagicMock, patch

import pytest

from strix.config.settings import RuntimeSettings, Settings
from strix.interface.environment import pull_docker_image
from strix.runtime.docker_client import StrixDockerSandboxClient


def _missing_image_client(
    *, pull_policy: Literal["auto", "never"] = "auto"
) -> StrixDockerSandboxClient:
    client = StrixDockerSandboxClient.__new__(StrixDockerSandboxClient)
    client.docker_client = MagicMock()
    client.image_pull_policy = pull_policy
    client.image_exists = MagicMock(return_value=False)
    return client


def test_cli_never_policy_rejects_missing_image_without_pull() -> None:
    docker_client = MagicMock()
    settings = Settings(
        runtime=RuntimeSettings(
            STRIX_IMAGE="example.invalid/sandbox@sha256:deadbeef",
            STRIX_IMAGE_PULL_POLICY="never",
        )
    )

    with (
        patch("strix.interface.environment.check_docker_connection", return_value=docker_client),
        patch("strix.interface.environment.image_exists", return_value=False),
        patch("strix.interface.environment.load_settings", return_value=settings),
        pytest.raises(
            RuntimeError,
            match=r"example\.invalid/sandbox@sha256:deadbeef.*forbids pulling",
        ),
    ):
        pull_docker_image()

    docker_client.api.pull.assert_not_called()


@pytest.mark.asyncio
async def test_container_creation_rechecks_never_policy_without_pull() -> None:
    client = _missing_image_client(pull_policy="never")

    with pytest.raises(
        RuntimeError,
        match=r"example\.invalid/sandbox@sha256:deadbeef.*forbids pulling",
    ):
        await client._create_container("example.invalid/sandbox@sha256:deadbeef")

    client.docker_client.images.pull.assert_not_called()
    client.docker_client.containers.create.assert_not_called()


@pytest.mark.asyncio
async def test_container_creation_uses_present_image_with_never_policy() -> None:
    client = _missing_image_client(pull_policy="never")
    client.image_exists = MagicMock(return_value=True)
    client.docker_client.containers.create.return_value = MagicMock(short_id="abc123")

    await client._create_container("example.invalid/sandbox@sha256:deadbeef")

    client.docker_client.images.pull.assert_not_called()
    client.docker_client.containers.create.assert_called_once()


@pytest.mark.asyncio
async def test_container_creation_keeps_default_auto_pull() -> None:
    client = _missing_image_client()
    client.image_exists = MagicMock(side_effect=[False, True])
    client.docker_client.containers.create.return_value = MagicMock(short_id="abc123")

    await client._create_container("example.invalid/sandbox:latest")

    client.docker_client.images.pull.assert_called_once_with(
        "example.invalid/sandbox", tag="latest", all_tags=False
    )
    client.docker_client.containers.create.assert_called_once()
