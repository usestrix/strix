from __future__ import annotations

import stat
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import NamedTuple

import pytest


DECOY_CONTENT = "#!/bin/sh\nprintf 'other-strix 1.2.3\\n'\n"

RELEASE_VERSION = "9.9.9"
RELEASE_TARGET = "linux-arm64"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="scripts/install.sh is a POSIX shell installer",
)


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _create_release_archive(tmp_path: Path) -> Path:
    binary_name = f"strix-{RELEASE_VERSION}-{RELEASE_TARGET}"
    binary_path = tmp_path / binary_name
    _write_executable(binary_path, f"#!/bin/sh\nprintf 'strix {RELEASE_VERSION}\\n'\n")

    archive_path = tmp_path / f"{binary_name}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(binary_path, arcname=binary_name)
    return archive_path


def _create_mock_commands(tmp_path: Path, machine: str) -> Path:
    mock_bin = tmp_path / "mock-bin"
    mock_bin.mkdir()
    _write_executable(
        mock_bin / "uname",
        f"""#!/bin/sh
case "$1" in
  -s) echo Linux ;;
  -m) echo {machine} ;;
  *) echo "unexpected uname argument: $*" >&2; exit 1 ;;
esac
""",
    )
    _write_executable(mock_bin / "docker", "#!/bin/sh\nexit 0\n")
    _write_executable(
        mock_bin / "curl",
        """#!/bin/sh
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  printf '%s\\n' "$1" >> "$STRIX_TEST_CURL_LOG"
  shift
done
cp "$STRIX_TEST_ARCHIVE" "$output"
""",
    )
    return mock_bin


def _create_installer_environment(
    tmp_path: Path,
    archive_path: Path,
    mock_bin: Path,
) -> tuple[dict[str, str], Path, Path]:
    """Build the installer environment explicitly.

    Every variable the installer reads is listed here, so no inherited value
    (`XDG_CONFIG_HOME`, `GITHUB_ACTIONS`, `TMPDIR`, ...) can send a write
    outside the sandbox or change the code path under test.
    """
    home_path = tmp_path / "home"
    home_path.mkdir()
    download_path = tmp_path / "downloads"
    download_path.mkdir()
    curl_log_path = tmp_path / "curl.log"
    environment = {
        "HOME": str(home_path),
        "XDG_CONFIG_HOME": str(home_path / ".config"),
        "PATH": f"{mock_bin}:/usr/bin:/bin",
        "SHELL": "/bin/bash",
        "TMPDIR": str(download_path),
        "STRIX_TEST_ARCHIVE": str(archive_path),
        "STRIX_TEST_CURL_LOG": str(curl_log_path),
        "VERSION": RELEASE_VERSION,
    }
    return environment, home_path, curl_log_path


def _run_installer(
    repository_root: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["/bin/bash", str(repository_root / "scripts/install.sh")],
        cwd=repository_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_installer_downloads_and_runs_linux_arm64_release(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    archive_path = _create_release_archive(tmp_path)
    mock_bin = _create_mock_commands(tmp_path, machine="aarch64")
    environment, home_path, curl_log_path = _create_installer_environment(
        tmp_path,
        archive_path,
        mock_bin,
    )

    result = _run_installer(repository_root, environment)

    assert result.returncode == 0, result.stderr
    expected_filename = f"strix-{RELEASE_VERSION}-{RELEASE_TARGET}.tar.gz"
    assert expected_filename in curl_log_path.read_text(encoding="utf-8")

    installed_binary = home_path / ".strix/bin/strix"
    installed_result = subprocess.run(  # noqa: S603
        [str(installed_binary), "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert installed_result.stdout.strip() == f"strix {RELEASE_VERSION}"


def test_installer_rejects_unsupported_architecture(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    archive_path = _create_release_archive(tmp_path)
    mock_bin = _create_mock_commands(tmp_path, machine="riscv64")
    environment, home_path, curl_log_path = _create_installer_environment(
        tmp_path,
        archive_path,
        mock_bin,
    )

    result = _run_installer(repository_root, environment)

    assert result.returncode != 0
    assert "Unsupported OS/Arch: linux/riscv64" in result.stdout
    assert not curl_log_path.exists()
    assert not (home_path / ".strix").exists()


class _DecoyRun(NamedTuple):
    decoy_path: Path
    pipx_log_path: Path
    home_path: Path
    stdout: str


def _install_with_decoy(
    tmp_path: Path,
    decoy_directory_name: str,
    *,
    pipx_owns_it: bool = False,
) -> _DecoyRun:
    """Run the installer with an unrelated `strix` ahead of it on `PATH`.

    The mock `pipx` answers the two ownership questions the installer asks and
    records every invocation, so a test can tell an ownership *query* apart
    from an `uninstall`.
    """
    repository_root = Path(__file__).resolve().parents[1]
    archive_path = _create_release_archive(tmp_path)
    mock_bin = _create_mock_commands(tmp_path, machine="aarch64")

    decoy_directory = tmp_path / decoy_directory_name
    decoy_directory.mkdir(parents=True)
    decoy_path = decoy_directory / "strix"
    _write_executable(decoy_path, DECOY_CONTENT)

    # When pipx "owns" the decoy it reports the decoy's own directory as its
    # bin dir and lists the package; otherwise it points somewhere else.
    pipx_bin_dir = decoy_directory if pipx_owns_it else tmp_path / "elsewhere"
    pipx_listing = "strix-agent 1.2.3" if pipx_owns_it else ""
    pipx_log_path = tmp_path / "pipx.log"
    _write_executable(
        mock_bin / "pipx",
        f"""#!/bin/sh
printf '%s\n' "$*" >> "{pipx_log_path}"
case "$1 $2" in
  "environment --value") printf '%s\n' "{pipx_bin_dir}" ;;
  "list --short") printf '%s' "{pipx_listing}" ;;
esac
""",
    )

    environment, home_path, _ = _create_installer_environment(tmp_path, archive_path, mock_bin)
    environment["PATH"] = f"{decoy_directory}:{environment['PATH']}"

    result = _run_installer(repository_root, environment)
    assert result.returncode == 0, result.stderr

    return _DecoyRun(decoy_path, pipx_log_path, home_path, result.stdout)


def _pipx_invocations(pipx_log_path: Path) -> list[str]:
    if not pipx_log_path.exists():
        return []
    return pipx_log_path.read_text(encoding="utf-8").splitlines()


def test_installer_leaves_unrelated_strix_executables_alone(tmp_path: Path) -> None:
    run = _install_with_decoy(tmp_path, "other-bin")

    assert run.decoy_path.exists()
    assert run.decoy_path.read_text(encoding="utf-8") == DECOY_CONTENT
    assert (run.home_path / ".strix/bin/strix").exists()


def test_installer_does_not_uninstall_a_pipx_managed_strix(tmp_path: Path) -> None:
    run = _install_with_decoy(tmp_path, ".local/bin", pipx_owns_it=True)

    assert run.decoy_path.exists()
    assert (run.home_path / ".strix/bin/strix").exists()
    # Querying pipx about ownership is fine; changing anything is not.
    assert not any(line.startswith("uninstall") for line in _pipx_invocations(run.pipx_log_path))


def _extract_shell_functions(repository_root: Path, names: tuple[str, ...]) -> str:
    """Pull named function definitions out of the installer.

    `describe_removal` only runs when another executable wins PATH resolution,
    which a successful install prevents, so driving it through a full install
    would assert nothing. Lift the functions out and call them directly.
    """
    source = (repository_root / "scripts/install.sh").read_text(encoding="utf-8")
    blocks = []
    for name in names:
        opening = f"{name}() {{\n"
        begin = source.index(opening)
        end = source.index("\n}\n", begin) + len("\n}\n")
        blocks.append(source[begin:end])
    return "".join(blocks)


def _describe_removal(
    tmp_path: Path,
    path: str,
    *,
    pipx_bin_dir: str | None = None,
    pipx_listing: str = "",
) -> str:
    """Run the installer's `describe_removal` against a mock `pipx`."""
    repository_root = Path(__file__).resolve().parents[1]
    mock_bin = tmp_path / "fn-bin"
    mock_bin.mkdir()
    if pipx_bin_dir is not None:
        _write_executable(
            mock_bin / "pipx",
            f"""#!/bin/sh
case "$1 $2" in
  "environment --value") printf '%s\\n' "{pipx_bin_dir}" ;;
  "list --short") printf '%s' "{pipx_listing}" ;;
esac
""",
        )

    script = tmp_path / "describe.sh"
    script.write_text(
        "set -euo pipefail\nMUTED=''\nNC=''\n"
        + _extract_shell_functions(repository_root, ("pipx_owns", "describe_removal"))
        + f'\ndescribe_removal "{path}"\n',
        encoding="utf-8",
    )

    result = subprocess.run(  # noqa: S603
        ["/bin/bash", str(script)],
        env={"PATH": f"{mock_bin}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def test_removal_advice_names_pipx_only_when_pipx_owns_the_executable(tmp_path: Path) -> None:
    pipx_bin = tmp_path / "pipx-bin"
    owned = _describe_removal(
        tmp_path,
        str(pipx_bin / "strix"),
        pipx_bin_dir=str(pipx_bin),
        pipx_listing="strix-agent 1.2.3",
    )
    assert "pipx uninstall strix-agent" in owned


def test_removal_advice_does_not_claim_pipx_owns_an_unrelated_local_bin_strix(
    tmp_path: Path,
) -> None:
    """A uv-managed or hand-placed strix in ~/.local/bin is not a pipx install.

    The old heuristic keyed off `.local/bin` appearing in the path, so it would
    tell the user to `pipx uninstall strix-agent` for a file pipx never
    installed. That either does nothing or removes a different package, and
    leaves the real PATH conflict in place.
    """
    local_bin = tmp_path / ".local" / "bin"
    advice = _describe_removal(
        tmp_path,
        str(local_bin / "strix"),
        pipx_bin_dir=str(tmp_path / "elsewhere"),
    )
    assert "pipx uninstall" not in advice
    assert "rm " in advice


def test_removal_advice_reports_rm_when_pipx_is_absent(tmp_path: Path) -> None:
    advice = _describe_removal(tmp_path, str(tmp_path / ".local" / "bin" / "strix"))
    assert "pipx" not in advice
    assert "rm " in advice


def test_removal_advice_quotes_paths_with_spaces_and_globs(tmp_path: Path) -> None:
    """A copied `rm` must survive spaces and globbing characters in the path."""
    awkward = tmp_path / "od d bin" / "strix*"
    advice = _describe_removal(tmp_path, str(awkward))

    assert f"rm {awkward}" not in advice, "the bare path was printed unquoted"
    command = advice.split("rm ", 1)[1].strip()
    # Re-expanding the printed argument must yield exactly the original path.
    expanded = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", f"printf '%s' {command}"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert expanded.stdout == str(awkward)
