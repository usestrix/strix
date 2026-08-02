"""Hatchling build hook that compiles and bundles the Go TUI sidecar."""

from __future__ import annotations

import os
import shutil
import subprocess
import sysconfig
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface[Any]):
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
        env["CGO_ENABLED"] = "0"
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
        platform_tag = os.environ.get("STRIX_WHEEL_PLATFORM_TAG")
        if not platform_tag:
            platform_tag = sysconfig.get_platform().replace("-", "_").replace(".", "_")
        build_data["tag"] = f"py3-none-{platform_tag}"
