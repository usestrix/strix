from __future__ import annotations

import shutil
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="requires Bash at /bin/bash")


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.mark.parametrize("platform", ["Linux", "MINGW64_NT"])
@pytest.mark.parametrize("smoke_status", [0, 7])
def test_build_packages_binary_only_after_successful_smoke_test(
    tmp_path: Path, platform: str, smoke_status: int
) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    script = scripts / "build.sh"
    repository = Path(__file__).resolve().parents[1]
    shutil.copyfile(repository / "scripts/build.sh", script)
    (tmp_path / "strix/interface/tui").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "9.9.9"\n', encoding="utf-8")

    mock_bin = tmp_path / "mock-bin"
    mock_bin.mkdir()
    windows = platform == "MINGW64_NT"
    executable = "dist/strix.exe" if windows else "dist/strix"
    _write_executable(
        mock_bin / "uname",
        f"""#!/bin/sh
case "$1" in
  -s) echo {platform} ;;
  -m) echo x86_64 ;;
  *) exit 1 ;;
esac
""",
    )
    _write_executable(mock_bin / "go", '#!/bin/sh\n[ "$1" = build ]\n')
    _write_executable(mock_bin / "7z", '#!/bin/sh\n[ "$1" = a ] && cp "$3" "$2"\n')
    _write_executable(
        mock_bin / "uv",
        f"""#!/bin/sh
case "$*" in
  'sync --frozen') exit 0 ;;
  'run pyinstaller strix.spec --noconfirm')
    mkdir -p dist
    cat > {executable} <<'BINARY'
#!/bin/sh
[ "$1" = --help ] || exit 99
if [ {smoke_status} -ne 0 ]; then echo 'synthetic startup error' >&2; fi
exit {smoke_status}
BINARY
    chmod +x {executable} ;;
  *) exit 98 ;;
esac
""",
    )

    result = subprocess.run(  # noqa: S603
        ["/bin/bash", str(script)],
        cwd=tmp_path,
        env={"PATH": f"{mock_bin}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == smoke_status, result.stdout + result.stderr
    release = tmp_path / "dist/release"
    if smoke_status:
        assert "synthetic startup error" in result.stderr
        assert "Binary test failed" in result.stderr
        assert "Build successful" not in result.stdout
        assert not release.exists()
    else:
        platform_name = "windows" if windows else "linux"
        name = f"strix-9.9.9-{platform_name}-x86_64"
        assert "Build successful" in result.stdout
        assert "Binary test passed" in result.stdout
        if windows:
            assert (release / f"{name}.zip").read_bytes() == (release / f"{name}.exe").read_bytes()
        else:
            with tarfile.open(release / f"{name}.tar.gz") as archive:
                member = archive.extractfile(name)
                assert member is not None
                assert member.read() == (release / name).read_bytes()
