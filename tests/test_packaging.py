from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_source_wheel_build_does_not_require_go(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required for the packaging smoke test")

    output = tmp_path / "dist"
    env = os.environ.copy()
    env.pop("STRIX_REQUIRE_TUI_SIDECAR", None)
    env["PATH"] = str(tmp_path / "path-without-go")
    subprocess.run(  # noqa: S603
        [uv, "build", "--wheel", "--out-dir", str(output)],
        cwd=PROJECT_ROOT,
        env=env,
        check=True,
    )

    wheels = list(output.glob("*.whl"))
    assert len(wheels) == 1
    assert wheels[0].name.endswith("-py3-none-any.whl")
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        assert "strix/bin/strix-tui" not in names
        assert "strix/bin/strix-tui.exe" not in names
        assert "strix/interface/go_tui.py" in names
        wheel_metadata = archive.read(
            next(name for name in names if name.endswith(".dist-info/WHEEL"))
        ).decode()
    assert "Root-Is-Purelib: true" in wheel_metadata
    assert "Tag: py3-none-any" in wheel_metadata


def test_strict_release_wheel_requires_go(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required for the packaging smoke test")

    env = os.environ.copy()
    env["STRIX_REQUIRE_TUI_SIDECAR"] = "1"
    env["PATH"] = str(tmp_path / "path-without-go")
    result = subprocess.run(  # noqa: S603
        [uv, "build", "--wheel", "--out-dir", str(tmp_path / "dist")],
        cwd=PROJECT_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Go 1.24 or newer is required" in result.stdout + result.stderr
