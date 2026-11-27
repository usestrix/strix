"""Hatchling build hook that compiles and bundles the Go TUI sidecar."""

from __future__ import annotations

import os
import shutil
import subprocess
import sysconfig
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


# Wheel builds are native-only: these variables select a Go cross-compilation
# target (and instruction-set baseline), so letting them leak in from the
# calling environment would bundle a sidecar for another platform while the
# wheel keeps advertising the build host's platform (issue #1838).
_GO_TARGET_VARS = ("GOOS", "GOARCH", "GOARM", "GO386", "GOAMD64", "GOPPC64")

# Wheel platform tags (sysconfig style) that each Go target can back. Only
# the platforms Strix ships (see the release build matrix) are mapped; a Go
# target outside this table fails the build instead of guessing a tag.
_GO_TARGET_TAG_OS = {
    "darwin": ("macosx",),
    "linux": ("linux", "manylinux"),
    "windows": ("win",),
}
_GO_TARGET_TAG_ARCH = {
    ("darwin", "amd64"): "x86_64",
    ("darwin", "arm64"): "arm64",
    ("linux", "amd64"): "x86_64",
    ("linux", "arm64"): "aarch64",
    ("windows", "amd64"): "amd64",
    ("windows", "arm64"): "arm64",
}


def _check_platform_consistency(goos: str, goarch: str, platform_tag: str) -> None:
    """Fail the build unless the wheel tag matches the effective Go target."""
    tag_os = _GO_TARGET_TAG_OS.get(goos)
    tag_arch = _GO_TARGET_TAG_ARCH.get((goos, goarch))
    if tag_os is None or tag_arch is None:
        raise RuntimeError(
            f"Go target {goos}/{goarch} has no matching wheel platform tag; the TUI "
            "sidecar wheel must be built on darwin, linux, or windows for amd64/arm64"
        )
    normalized = platform_tag.lower()
    # The first segment names the platform family and the tail carries the
    # architecture; arch tokens may themselves contain underscores (x86_64),
    # so match the architecture by suffix instead of splitting on "_".
    os_matches = any(normalized.split("_")[0].startswith(prefix) for prefix in tag_os)
    arch_matches = normalized == tag_arch or normalized.endswith(f"_{tag_arch}")
    if not os_matches or not arch_matches:
        raise RuntimeError(
            f"Wheel platform tag {platform_tag!r} does not match the effective Go "
            f"target {goos}/{goarch}, which needs a {' or '.join(tag_os)} tag ending "
            f"in {tag_arch}; build natively and set STRIX_WHEEL_PLATFORM_TAG only to "
            "rename the host platform family (e.g. manylinux)"
        )


class CustomBuildHook(BuildHookInterface):  # type: ignore[type-arg]
    """Compile the Bubble Tea sidecar and ship it inside the wheel.

    The sidecar is the only interactive interface, so every wheel is a
    platform wheel and a missing Go toolchain is a build failure.
    """

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        # Editable installs run from the checkout, where the TUI is started
        # with ``go run``; there is nothing to bundle.
        if version == "editable":
            return

        root = Path(self.root)
        executable = "strix-tui.exe" if os.name == "nt" else "strix-tui"
        output = root / "build" / "sidecar" / executable
        output.parent.mkdir(parents=True, exist_ok=True)

        go = shutil.which("go")
        if go is None:
            raise RuntimeError("Go 1.24 or newer is required to build the Bubble Tea TUI")
        env = os.environ.copy()
        # Strip any Go cross-compilation target inherited from the calling
        # environment so the sidecar always targets the build host (issue #1838).
        for var in _GO_TARGET_VARS:
            env.pop(var, None)
        env["CGO_ENABLED"] = "0"

        # Resolve the effective Go target and verify it agrees with the wheel
        # platform tag before spending time on compilation.
        env_query = subprocess.run(  # noqa: S603 - fixed query using the resolved Go binary
            [go, "env", "GOOS", "GOARCH"],
            cwd=root / "strix" / "interface" / "tui",
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        goos, goarch = env_query.stdout.split()
        platform_tag = os.environ.get("STRIX_WHEEL_PLATFORM_TAG")
        if not platform_tag:
            platform_tag = sysconfig.get_platform().replace("-", "_").replace(".", "_")
        _check_platform_consistency(goos, goarch, platform_tag)

        subprocess.run(  # noqa: S603 - fixed build command using the resolved Go binary
            [
                go,
                "build",
                "-trimpath",
                "-ldflags=-s -w",
                "-o",
                str(output),
                "./cmd/strix-tui",
            ],
            cwd=root / "strix" / "interface" / "tui",
            env=env,
            check=True,
        )

        build_data["force_include"][str(output)] = f"strix/bin/{executable}"
        build_data["pure_python"] = False
        build_data["tag"] = f"py3-none-{platform_tag}"
