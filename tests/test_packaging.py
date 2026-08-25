from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = PROJECT_ROOT / "strix.spec"
CERTIFI_RTHOOK = PROJECT_ROOT / "hooks" / "rthooks" / "pyi_rth_certifi.py"


def test_wheel_build_requires_go(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required for the packaging smoke test")

    env = os.environ.copy()
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


def test_pyinstaller_spec_bundles_certifi_ca_and_runtime_hook() -> None:
    spec = SPEC_PATH.read_text(encoding="utf-8")
    assert "collect_data_files('certifi')" in spec
    assert "pyi_rth_certifi.py" in spec
    assert "runtime_hooks=[" in spec
    assert CERTIFI_RTHOOK.is_file()
    hook = CERTIFI_RTHOOK.read_text(encoding="utf-8")
    assert "SSL_CERT_FILE" in hook
    assert "REQUESTS_CA_BUNDLE" in hook
    assert "certifi.where()" in hook
