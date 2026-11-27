"""Regression tests for the TUI sidecar wheel build hook.

The wheel build hook compiles the Go sidecar and stamps the wheel with a
platform tag derived from the build host. Issue #1838: a ``GOOS``/``GOARCH``
inherited from the calling environment silently cross-compiles the sidecar
while the wheel keeps advertising the host platform, so a Linux ELF can end
up inside a wheel tagged for macOS. The hook must build native-only and fail
early when the effective Go target and the wheel platform tag disagree.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from typing import Any

import pytest


_HOOK_PATH = Path(__file__).resolve().parent.parent / "scripts" / "tui_sidecar_hook.py"


def _load_hook_module() -> Any:
    spec = importlib.util.spec_from_file_location("tui_sidecar_hook", _HOOK_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _RunRecorder:
    """Fake ``subprocess.run`` that answers ``go env`` and records ``go build``."""

    def __init__(self, goos: str, goarch: str) -> None:
        self.goos = goos
        self.goarch = goarch
        self.build_invocations: list[dict[str, Any]] = []
        self.env_queries = 0

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert kwargs.get("check") is True
        if len(args) > 1 and args[1] == "env":
            self.env_queries += 1
            return subprocess.CompletedProcess(
                args, 0, stdout=f"{self.goos}\n{self.goarch}\n", stderr=""
            )
        self.build_invocations.append({"args": args, "env": kwargs.get("env")})
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")


def _make_hook(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, recorder: _RunRecorder) -> Any:
    module = _load_hook_module()
    monkeypatch.setattr(module.subprocess, "run", recorder)
    monkeypatch.setattr(module.sysconfig, "get_platform", lambda: "linux-x86_64")
    # Initialize only reads ``self.root``; feed the constructor minimal dummies.
    return module.CustomBuildHook(str(tmp_path), {}, None, None, "", "wheel")


def test_build_env_strips_go_cross_compile_vars(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Inherited GOOS/GOARCH/GOARM must never reach the sidecar go build."""
    recorder = _RunRecorder("linux", "amd64")
    hook = _make_hook(monkeypatch, tmp_path, recorder)
    monkeypatch.setenv("GOOS", "darwin")
    monkeypatch.setenv("GOARCH", "arm64")
    monkeypatch.setenv("GOARM", "7")
    monkeypatch.delenv("STRIX_WHEEL_PLATFORM_TAG", raising=False)

    # Mirror the build_data shape hatchling provides (force_include pre-created).
    build_data: dict[str, Any] = {"force_include": {}}
    hook.initialize("1", build_data)

    assert recorder.env_queries == 1
    assert len(recorder.build_invocations) == 1
    env = recorder.build_invocations[0]["env"]
    assert env is not None
    assert env["CGO_ENABLED"] == "0"
    for var in ("GOOS", "GOARCH", "GOARM"):
        assert var not in env, f"{var} leaked into the sidecar go build environment"


def test_sysconfig_tag_matches_native_go_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Default tag comes from sysconfig and must agree with the Go target."""
    recorder = _RunRecorder("linux", "amd64")
    hook = _make_hook(monkeypatch, tmp_path, recorder)
    monkeypatch.delenv("STRIX_WHEEL_PLATFORM_TAG", raising=False)

    # Mirror the build_data shape hatchling provides (force_include pre-created).
    build_data: dict[str, Any] = {"force_include": {}}
    hook.initialize("1", build_data)
    assert build_data["tag"] == "py3-none-linux_x86_64"


def test_matching_override_platform_tag_succeeds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The CI override tag (e.g. manylinux) is accepted when it matches."""
    recorder = _RunRecorder("linux", "amd64")
    hook = _make_hook(monkeypatch, tmp_path, recorder)
    monkeypatch.setenv("STRIX_WHEEL_PLATFORM_TAG", "manylinux_2_17_x86_64")

    # Mirror the build_data shape hatchling provides (force_include pre-created).
    build_data: dict[str, Any] = {"force_include": {}}
    hook.initialize("1", build_data)

    assert build_data["tag"] == "py3-none-manylinux_2_17_x86_64"
    assert build_data["pure_python"] is False
    (source, target) = next(iter(build_data["force_include"].items()))
    assert target == "strix/bin/strix-tui"
    assert source == str(tmp_path / "build" / "sidecar" / "strix-tui")


def test_mismatched_override_platform_tag_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A tag that contradicts the Go target must fail before packaging."""
    recorder = _RunRecorder("linux", "amd64")
    hook = _make_hook(monkeypatch, tmp_path, recorder)
    monkeypatch.setenv("STRIX_WHEEL_PLATFORM_TAG", "macosx_11_0_arm64")

    with pytest.raises(RuntimeError, match="macosx_11_0_arm64"):
        hook.initialize("1", {"force_include": {}})

    assert recorder.build_invocations == [], "go build ran despite a mismatched wheel tag"


def test_cross_target_sidecar_vs_native_tag_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Issue #1838: a Go target for another OS must not pass with the native tag."""
    recorder = _RunRecorder("darwin", "arm64")
    hook = _make_hook(monkeypatch, tmp_path, recorder)
    monkeypatch.delenv("STRIX_WHEEL_PLATFORM_TAG", raising=False)

    with pytest.raises(RuntimeError, match="darwin/arm64"):
        hook.initialize("1", {"force_include": {}})

    assert recorder.build_invocations == []


def test_unsupported_go_target_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Go targets without a wheel tag mapping fail loudly instead of guessing."""
    recorder = _RunRecorder("freebsd", "amd64")
    hook = _make_hook(monkeypatch, tmp_path, recorder)
    monkeypatch.delenv("STRIX_WHEEL_PLATFORM_TAG", raising=False)

    with pytest.raises(RuntimeError, match="freebsd/amd64"):
        hook.initialize("1", {"force_include": {}})


def test_editable_build_skips_sidecar(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Editable installs run the TUI with ``go run`` and bundle nothing."""
    recorder = _RunRecorder("linux", "amd64")
    hook = _make_hook(monkeypatch, tmp_path, recorder)

    build_data: dict[str, Any] = {}
    hook.initialize("editable", build_data)

    assert build_data == {}
    assert recorder.env_queries == 0
    assert recorder.build_invocations == []
