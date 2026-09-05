"""Tests for fail-closed mount-free sandbox transport and symlink-safe snapshotting."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from agents.sandbox.entries import Dir, File


try:
    import docker
except ImportError:
    docker = None  # type: ignore[assignment]

import strix.config.loader as config_loader
from strix.config import load_settings
from strix.report.state import ReportState, set_global_report_state
from strix.runtime.backends import (
    _BACKENDS,
    _BIND_MOUNT_BACKENDS,
    _MOUNT_FREE_BACKENDS,
    backend_supports_mount_free,
    register_backend,
)
from strix.runtime.session_manager import (
    _symlink_safe_dir_entry,
    cleanup,
    create_or_reuse,
)


def _docker_available() -> bool:
    if docker is None:
        return False
    try:
        docker.from_env().ping()
    except Exception:  # noqa: BLE001
        return False
    else:
        return True


@pytest.mark.asyncio
async def test_mount_free_fail_closed_on_unsupported_backend() -> None:
    """When STRIX_REQUIRE_MOUNT_FREE is active, backends without mount-free support fail closed."""
    backend_name = "test_legacy_backend"
    mock_backend = AsyncMock()

    register_backend(
        backend_name,
        mock_backend,
        supports_bind_mounts=True,
        supports_mount_free=False,
    )

    try:
        assert not backend_supports_mount_free(backend_name)
        with (
            patch.dict(
                os.environ,
                {
                    "STRIX_REQUIRE_MOUNT_FREE": "1",
                    "STRIX_RUNTIME_BACKEND": backend_name,
                },
            ),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            config_loader._cached = None
            settings = load_settings()
            assert settings.runtime.require_mount_free
            assert settings.runtime.backend == backend_name

            source_path = str(Path(temp_dir) / "app")
            Path(source_path).mkdir()
            (Path(source_path) / "test.py").write_text("print('hello')")

            with pytest.raises(RuntimeError, match="does not support mount-free transport"):
                await create_or_reuse(
                    "test_scan_fail_closed",
                    image="dummy-image",
                    local_sources=[{"workspace_subdir": "app", "source_path": source_path}],
                )
    finally:
        _BACKENDS.pop(backend_name, None)
        _BIND_MOUNT_BACKENDS.discard(backend_name)
        _MOUNT_FREE_BACKENDS.discard(backend_name)
        config_loader._cached = None


@pytest.mark.asyncio
async def test_mount_free_success_path_stub_backend() -> None:
    """Mount-free backend gets zero bind mounts, manifest entries, and read-only grants."""
    backend_name = "test_mount_free_backend"
    captured_kwargs: dict[str, Any] = {}

    fake_session = AsyncMock()
    fake_session.resolve_exposed_port = AsyncMock(
        return_value=type("Endpoint", (), {"tls": False, "host": "127.0.0.1", "port": 48080})()
    )
    fake_client = AsyncMock()

    async def _mock_backend(*_args: Any, **kwargs: Any) -> tuple[Any, Any]:
        captured_kwargs.update(kwargs)
        return fake_client, fake_session

    register_backend(
        backend_name,
        _mock_backend,
        supports_bind_mounts=False,
        supports_mount_free=True,
    )

    report_state = ReportState()
    set_global_report_state(report_state)

    try:
        with (
            patch.dict(
                os.environ,
                {
                    "STRIX_REQUIRE_MOUNT_FREE": "1",
                    "STRIX_RUNTIME_BACKEND": backend_name,
                },
            ),
            patch("strix.runtime.session_manager.bootstrap_caido", new=AsyncMock()),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            config_loader._cached = None
            source_dir = Path(temp_dir) / "app"
            source_dir.mkdir()
            (source_dir / "index.js").write_text("console.log('hi');")

            scan_id = "test_mount_free_success"
            bundle = await create_or_reuse(
                scan_id,
                image="dummy-image",
                local_sources=[{"workspace_subdir": "app", "source_path": str(source_dir)}],
            )

            assert captured_kwargs.get("bind_mounts") == []
            manifest = captured_kwargs.get("manifest")
            assert manifest is not None
            assert "app" in manifest.entries
            assert len(manifest.extra_path_grants) == 1
            grant = manifest.extra_path_grants[0]
            assert grant.path == str(source_dir.resolve())
            assert grant.read_only is True

            assert bundle.get("transport") == "mount-free"
            assert report_state.run_record.get("transport") == "mount-free"
    finally:
        await cleanup("test_mount_free_success")
        _BACKENDS.pop(backend_name, None)
        _BIND_MOUNT_BACKENDS.discard(backend_name)
        _MOUNT_FREE_BACKENDS.discard(backend_name)
        config_loader._cached = None
        set_global_report_state(None)


def test_symlink_safe_dir_entry_behavior() -> None:
    """In-tree files are kept; out-of-tree and directory symlinks are safely skipped."""
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        source_dir = root / "source"
        source_dir.mkdir()
        (source_dir / "file.txt").write_text("regular file")

        sub = source_dir / "sub"
        sub.mkdir()
        (sub / "nested.txt").write_text("nested content")

        # In-tree relative file symlink
        (source_dir / "link_to_file.txt").symlink_to(Path("file.txt"))

        # In-tree directory symlink
        (source_dir / "link_to_sub").symlink_to(Path("sub"))

        # Out-of-tree file symlink
        secret_file = root / "secret.txt"
        secret_file.write_text("SECRET")
        (source_dir / "link_to_secret.txt").symlink_to(secret_file)

        # Dangling symlink
        (source_dir / "dangling.txt").symlink_to(Path("nonexistent.txt"))

        entry = _symlink_safe_dir_entry(source_dir)
        assert isinstance(entry, Dir)
        children = entry.children

        assert "file.txt" in children
        assert isinstance(children["file.txt"], File)
        assert children["file.txt"].content == b"regular file"

        assert "sub" in children
        assert isinstance(children["sub"], Dir)

        # In-tree file symlink is resolved into File
        assert "link_to_file.txt" in children
        assert isinstance(children["link_to_file.txt"], File)
        assert children["link_to_file.txt"].content == b"regular file"

        # Out-of-tree, directory, and dangling symlinks are skipped
        assert "link_to_secret.txt" not in children
        assert "link_to_sub" not in children
        assert "dangling.txt" not in children


def test_adversarial_symlink_swap_defense() -> None:
    """Files swapped for symlinks after traversal cannot be read through descriptor pinning."""
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        source_dir = root / "repo"
        source_dir.mkdir()
        target = source_dir / "target.txt"
        target.write_text("SAFE")

        secret = root / "secret.txt"
        secret.write_text("SECRET_DATA")

        # Emulate TOCTOU attack: open directory descriptor, then swap target for symlink
        dir_fd = os.open(str(source_dir), os.O_RDONLY | os.O_DIRECTORY)
        target.unlink()
        target.symlink_to(secret)

        try:
            # Descriptor-pinned open with O_NOFOLLOW must reject opening the symlink
            with pytest.raises(OSError):
                fd = os.open(
                    "target.txt",
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0),
                    dir_fd=dir_fd,
                )
                os.close(fd)
        finally:
            os.close(dir_fd)


@pytest.mark.skipif(not _docker_available(), reason="Docker daemon is not running")
@pytest.mark.asyncio
async def test_real_docker_mount_free_integration() -> None:
    """Docker integration acceptance test: verify no host bind mounts exist on container."""
    assert docker is not None
    scan_id = "test_docker_mount_free_proof"
    with (
        patch.dict(
            os.environ,
            {
                "STRIX_REQUIRE_MOUNT_FREE": "1",
                "STRIX_RUNTIME_BACKEND": "docker",
            },
        ),
        patch("strix.runtime.session_manager.bootstrap_caido", new=AsyncMock()),
        tempfile.TemporaryDirectory() as temp_dir,
    ):
        config_loader._cached = None
        source_dir = Path(temp_dir) / "app"
        source_dir.mkdir()
        (source_dir / "hello.txt").write_text("mount_free_proof")

        report_state = ReportState()
        set_global_report_state(report_state)

        try:
            bundle = await create_or_reuse(
                scan_id,
                image="python:3.11-slim",
                local_sources=[{"workspace_subdir": "app", "source_path": str(source_dir)}],
            )

            assert bundle.get("transport") == "mount-free"
            assert report_state.run_record.get("transport") == "mount-free"

            session = bundle["session"]
            docker_client = docker.from_env()

            # Locate container ID from session inner state
            container_id = getattr(
                getattr(getattr(session, "_inner", None), "state", None),
                "container_id",
                None,
            )
            assert container_id is not None, "Container ID must be present in session state"

            container = docker_client.containers.get(container_id)
            inspect_data = container.attrs

            # Verify no host bind mounts in HostConfig or Mounts
            host_config = inspect_data.get("HostConfig", {})
            binds = host_config.get("Binds") or []
            mounts = inspect_data.get("Mounts") or []

            # Ensure host source directory is not present in binds or bind mounts
            resolved_source = str(source_dir.resolve())
            assert not any(resolved_source in str(b) for b in binds)

            bind_mount_entries = [m for m in mounts if m.get("Type") == "bind"]
            for m in bind_mount_entries:
                assert resolved_source not in str(m.get("Source", ""))

            # Verify the uploaded files are materialized in /workspace/app
            exec_res = container.exec_run("cat /workspace/app/hello.txt")
            assert exec_res.exit_code == 0
            assert b"mount_free_proof" in exec_res.output
        finally:
            await cleanup(scan_id)
            config_loader._cached = None
            set_global_report_state(None)
