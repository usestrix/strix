from __future__ import annotations

import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest


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
    # Shadow any real gh/cosign on PATH. Behaviour is driven by env flags.
    _write_executable(
        mock_bin / "gh",
        """#!/bin/sh
if [ -n "${STRIX_TEST_NO_VERIFIER:-}" ]; then
  exit 1
fi
if [ "$1" = "attestation" ] && [ "$2" = "verify" ]; then
  if [ "$3" = "--help" ]; then
    exit 0
  fi
  printf '%s\\n' "$*" >> "$STRIX_TEST_GH_LOG"
  if [ -n "${STRIX_TEST_GH_FAIL_VERIFY:-}" ]; then
    exit 1
  fi
  exit 0
fi
exit 1
""",
    )
    _write_executable(
        mock_bin / "cosign",
        """#!/bin/sh
if [ -n "${STRIX_TEST_NO_VERIFIER:-}" ]; then
  exit 1
fi
if [ "$1" = "verify-blob-attestation" ]; then
  if [ "$2" = "--help" ]; then
    [ -n "${STRIX_TEST_USE_COSIGN:-}" ] && exit 0
    exit 1
  fi
  printf '%s\\n' "$*" >> "$STRIX_TEST_COSIGN_LOG"
  [ -n "${STRIX_TEST_USE_COSIGN:-}" ] && exit 0
  exit 1
fi
exit 1
""",
    )
    _write_executable(
        mock_bin / "curl",
        """#!/bin/sh
output=""
url=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  case "$1" in
    http://*|https://*) url="$1" ;;
  esac
  printf '%s\\n' "$1" >> "$STRIX_TEST_CURL_LOG"
  shift
done
if [ -n "${STRIX_TEST_CURL_FAIL:-}" ]; then
  case "$url" in
    *"$STRIX_TEST_CURL_FAIL"*) exit 22 ;;
  esac
fi
case "$url" in
  */SHA256SUMS)
    name=$(basename "$STRIX_TEST_ARCHIVE")
    if [ -n "${STRIX_TEST_BAD_CHECKSUM:-}" ]; then
      printf '%s  %s\\n' "0" "$name" > "$output"
    elif [ -n "${STRIX_TEST_SUMS_WRONG_NAME:-}" ]; then
      hash=$(sha256sum "$STRIX_TEST_ARCHIVE" | awk '{print $1}')
      printf '%s  %s\\n' "$hash" "other-file.tar.gz" > "$output"
    else
      hash=$(sha256sum "$STRIX_TEST_ARCHIVE" | awk '{print $1}')
      printf '%s  %s\\n' "$hash" "$name" > "$output"
    fi
    ;;
  *.intoto.jsonl)
    printf '{"test":true}\\n' > "$output"
    ;;
  *)
    cp "$STRIX_TEST_ARCHIVE" "$output"
    ;;
esac
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
    gh_log_path = tmp_path / "gh.log"
    cosign_log_path = tmp_path / "cosign.log"
    environment = {
        "HOME": str(home_path),
        "XDG_CONFIG_HOME": str(home_path / ".config"),
        "PATH": f"{mock_bin}:/usr/bin:/bin",
        "SHELL": "/bin/bash",
        "TMPDIR": str(download_path),
        "STRIX_TEST_ARCHIVE": str(archive_path),
        "STRIX_TEST_CURL_LOG": str(curl_log_path),
        "STRIX_TEST_GH_LOG": str(gh_log_path),
        "STRIX_TEST_COSIGN_LOG": str(cosign_log_path),
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
    curl_log = curl_log_path.read_text(encoding="utf-8")
    assert expected_filename in curl_log
    assert f"releases/download/v{RELEASE_VERSION}/SHA256SUMS" in curl_log
    assert f"strix-{RELEASE_TARGET}.intoto.jsonl" in curl_log
    assert "Checksum verified" in result.stdout
    assert "Provenance verified" in result.stdout
    gh_log = (tmp_path / "gh.log").read_text(encoding="utf-8")
    assert "--repo usestrix/strix" in gh_log
    assert "--bundle strix-linux-arm64.intoto.jsonl" in gh_log
    assert "--signer-workflow usestrix/strix/.github/workflows/build-release.yml" in gh_log
    assert "--deny-self-hosted-runners" in gh_log
    assert not (tmp_path / "cosign.log").exists()

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


def test_installer_leaves_external_strix_on_checksum_failure(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    archive_path = _create_release_archive(tmp_path)
    mock_bin = _create_mock_commands(tmp_path, machine="aarch64")
    environment, home_path, _curl_log_path = _create_installer_environment(
        tmp_path,
        archive_path,
        mock_bin,
    )
    environment["STRIX_TEST_BAD_CHECKSUM"] = "1"

    other_bin = tmp_path / "other-bin"
    other_bin.mkdir()
    external = other_bin / "strix"
    _write_executable(external, "#!/bin/sh\nprintf 'strix 1.0.0\\n'\n")
    environment["PATH"] = f"{other_bin}:{environment['PATH']}"
    before = external.read_bytes()

    result = _run_installer(repository_root, environment)

    assert result.returncode != 0
    assert "Checksum mismatch" in result.stdout
    assert external.exists()
    assert external.read_bytes() == before
    assert not (home_path / ".strix/bin/strix").exists()
    installed_result = subprocess.run(  # noqa: S603
        [str(external), "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert installed_result.stdout.strip() == "strix 1.0.0"


def test_installer_leaves_existing_install_on_checksum_failure(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    archive_path = _create_release_archive(tmp_path)
    mock_bin = _create_mock_commands(tmp_path, machine="aarch64")
    environment, home_path, _curl_log_path = _create_installer_environment(
        tmp_path,
        archive_path,
        mock_bin,
    )
    environment["STRIX_TEST_BAD_CHECKSUM"] = "1"

    install_dir = home_path / ".strix" / "bin"
    install_dir.mkdir(parents=True)
    existing = install_dir / "strix"
    _write_executable(existing, "#!/bin/sh\nprintf 'strix 1.0.0\\n'\n")
    before = existing.read_bytes()

    result = _run_installer(repository_root, environment)

    assert result.returncode != 0
    assert "Checksum mismatch" in result.stdout
    assert "Existing Strix installation left unchanged" in result.stdout
    assert existing.read_bytes() == before
    assert not (install_dir / "strix.new").exists()
    installed_result = subprocess.run(  # noqa: S603
        [str(existing), "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert installed_result.stdout.strip() == "strix 1.0.0"


def test_installer_rejects_missing_checksum_manifest(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    archive_path = _create_release_archive(tmp_path)
    mock_bin = _create_mock_commands(tmp_path, machine="aarch64")
    environment, home_path, _curl_log_path = _create_installer_environment(
        tmp_path,
        archive_path,
        mock_bin,
    )
    environment["STRIX_TEST_CURL_FAIL"] = "SHA256SUMS"

    result = _run_installer(repository_root, environment)

    assert result.returncode != 0
    assert "Failed to download checksum manifest" in result.stdout
    assert not (home_path / ".strix/bin/strix").exists()


def test_installer_rejects_checksum_manifest_without_archive_entry(
    tmp_path: Path,
) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    archive_path = _create_release_archive(tmp_path)
    mock_bin = _create_mock_commands(tmp_path, machine="aarch64")
    environment, home_path, _curl_log_path = _create_installer_environment(
        tmp_path,
        archive_path,
        mock_bin,
    )
    environment["STRIX_TEST_SUMS_WRONG_NAME"] = "1"

    result = _run_installer(repository_root, environment)

    assert result.returncode != 0
    assert "No SHA256SUMS entry" in result.stdout
    assert not (home_path / ".strix/bin/strix").exists()


def test_installer_rejects_missing_provenance_bundle(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    archive_path = _create_release_archive(tmp_path)
    mock_bin = _create_mock_commands(tmp_path, machine="aarch64")
    environment, home_path, _curl_log_path = _create_installer_environment(
        tmp_path,
        archive_path,
        mock_bin,
    )
    environment["STRIX_TEST_CURL_FAIL"] = "intoto.jsonl"

    result = _run_installer(repository_root, environment)

    assert result.returncode != 0
    assert "Failed to download provenance bundle" in result.stdout
    assert "Checksum verified" in result.stdout
    assert not (home_path / ".strix/bin/strix").exists()


def test_installer_rejects_failed_gh_attestation_verify(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    archive_path = _create_release_archive(tmp_path)
    mock_bin = _create_mock_commands(tmp_path, machine="aarch64")
    environment, home_path, _curl_log_path = _create_installer_environment(
        tmp_path,
        archive_path,
        mock_bin,
    )
    environment["STRIX_TEST_GH_FAIL_VERIFY"] = "1"

    result = _run_installer(repository_root, environment)

    assert result.returncode != 0
    assert "gh attestation verify failed" in result.stdout
    assert not (home_path / ".strix/bin/strix").exists()
    assert not (tmp_path / "cosign.log").exists()


def test_installer_uses_cosign_when_gh_cannot_verify(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    archive_path = _create_release_archive(tmp_path)
    mock_bin = _create_mock_commands(tmp_path, machine="aarch64")
    environment, home_path, _curl_log_path = _create_installer_environment(
        tmp_path,
        archive_path,
        mock_bin,
    )
    environment["STRIX_TEST_USE_COSIGN"] = "1"
    _write_executable(
        mock_bin / "gh",
        "#!/bin/sh\nexit 1\n",
    )

    result = _run_installer(repository_root, environment)

    assert result.returncode == 0, result.stderr
    assert "Provenance verified" in result.stdout
    assert "(cosign)" in result.stdout
    cosign_log = (tmp_path / "cosign.log").read_text(encoding="utf-8")
    assert "--new-bundle-format" in cosign_log
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in (cosign_log)
    assert "build-release.yml" in cosign_log
    assert "--type slsaprovenance1" in cosign_log
    assert (home_path / ".strix/bin/strix").exists()


def test_installer_rejects_when_no_provenance_verifier_is_available(
    tmp_path: Path,
) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    archive_path = _create_release_archive(tmp_path)
    mock_bin = _create_mock_commands(tmp_path, machine="aarch64")
    environment, home_path, _curl_log_path = _create_installer_environment(
        tmp_path,
        archive_path,
        mock_bin,
    )
    environment["STRIX_TEST_NO_VERIFIER"] = "1"

    result = _run_installer(repository_root, environment)

    assert result.returncode != 0
    assert "Neither a usable 'gh' nor 'cosign'" in result.stdout
    assert not (home_path / ".strix/bin/strix").exists()


def test_installer_skip_verify_does_not_download_manifests(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    archive_path = _create_release_archive(tmp_path)
    mock_bin = _create_mock_commands(tmp_path, machine="aarch64")
    environment, home_path, curl_log_path = _create_installer_environment(
        tmp_path,
        archive_path,
        mock_bin,
    )
    environment["STRIX_INSTALL_SKIP_VERIFY"] = "1"

    result = _run_installer(repository_root, environment)

    assert result.returncode == 0, result.stderr
    curl_log = curl_log_path.read_text(encoding="utf-8")
    assert "SHA256SUMS" not in curl_log
    assert "intoto.jsonl" not in curl_log
    assert "skipping checksum and provenance checks" in result.stdout
    assert (home_path / ".strix/bin/strix").exists()
    assert not (tmp_path / "gh.log").exists()
