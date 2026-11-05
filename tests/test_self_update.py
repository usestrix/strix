"""Exercise binary updates with real archives and an isolated installation."""

from __future__ import annotations

import errno
import hashlib
import io
import json
import stat
import sys
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Self

import pytest
import requests
from rich.console import Console

from strix.interface import cli_args, update_check


if TYPE_CHECKING:
    from collections.abc import Iterator


VERSION = "1.8.0"
OLD_BINARY = b"previous executable"
NEW_BINARY = b"new executable"


@dataclass
class _Response:
    payload: object = None
    content: bytes = b""
    stream_error: Exception | None = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        pass

    def raise_for_status(self) -> None:
        pass

    def json(self) -> object:
        return self.payload

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset : offset + chunk_size]
        if self.stream_error:
            raise self.stream_error


@dataclass
class _Release:
    executable: Path
    target: str
    archive: bytes = b""
    digest: object = None
    metadata_error: Exception | None = None
    stream_error: Exception | None = None
    urls: list[str] = field(default_factory=list)
    output: io.StringIO = field(default_factory=io.StringIO)

    @property
    def binary_name(self) -> str:
        suffix = ".exe" if self.target.startswith("windows") else ""
        return f"strix-{VERSION}-{self.target}{suffix}"

    @property
    def filename(self) -> str:
        suffix = ".zip" if self.target.startswith("windows") else ".tar.gz"
        return f"strix-{VERSION}-{self.target}{suffix}"

    def set_archive(self, kind: str = "regular") -> None:
        buffer = io.BytesIO()
        name = "unexpected" if kind == "missing" else self.binary_name
        content = b"" if kind == "empty" else NEW_BINARY
        if self.target.startswith("windows"):
            with zipfile.ZipFile(buffer, "w") as archive:
                member = zipfile.ZipInfo(name)
                member.create_system = 3
                member.external_attr = (stat.S_IFREG | 0o755) << 16
                if kind == "symlink":
                    member.external_attr = (stat.S_IFLNK | 0o777) << 16
                elif kind == "directory":
                    member.external_attr = (stat.S_IFDIR | 0o755) << 16
                archive.writestr(member, content)
                if kind == "duplicate":
                    with pytest.warns(UserWarning, match="Duplicate name"):
                        archive.writestr(member, content)
        else:
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                member = tarfile.TarInfo(name)
                member.mode = 0o7777
                member.size = len(content)
                if kind in {"symlink", "hardlink"}:
                    member.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                    member.linkname = "payload"
                    member.size = 0
                    payload = tarfile.TarInfo("payload")
                    payload.size = len(content)
                    archive.addfile(payload, io.BytesIO(content))
                elif kind == "directory":
                    member.type = tarfile.DIRTYPE
                    member.size = 0
                archive.addfile(member, io.BytesIO(content))
                if kind == "duplicate":
                    archive.addfile(member, io.BytesIO(content))
        self.archive = buffer.getvalue()
        self.digest = "sha256:" + hashlib.sha256(self.archive).hexdigest()

    def get(self, url: str, **_kwargs: object) -> _Response:
        self.urls.append(url)
        if url == f"https://api.github.com/repos/usestrix/strix/releases/tags/v{VERSION}":
            if self.metadata_error:
                raise self.metadata_error
            return _Response(payload={"assets": [{"name": self.filename, "digest": self.digest}]})
        assert url == (
            f"https://github.com/usestrix/strix/releases/download/v{VERSION}/{self.filename}"
        )
        return _Response(content=self.archive, stream_error=self.stream_error)

    def update(self, version: str = VERSION) -> bool:
        return update_check.self_update(Console(file=self.output), version=version)

    def assert_preserved(self) -> None:
        assert self.executable.read_bytes() == OLD_BINARY
        assert list(self.executable.parent.iterdir()) == [self.executable]
        assert not update_check._CACHE_PATH.exists()


@pytest.fixture(params=["linux-x86_64", "macos-arm64", "windows-x86_64"])
def release(
    request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> _Release:
    install = tmp_path / "install with spaces"
    install.mkdir()
    executable = install / ("strix.exe" if request.param.startswith("windows") else "strix")
    executable.write_bytes(OLD_BINARY)
    executable.chmod(0o700)
    result = _Release(executable=executable, target=request.param)
    result.set_archive()
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(update_check, "is_binary_install", lambda: True)
    monkeypatch.setattr(update_check, "get_version", lambda: "1.7.0")
    monkeypatch.setattr(update_check, "_release_target", lambda: result.target)
    monkeypatch.setattr(update_check, "_CACHE_PATH", tmp_path / "cache.json")
    monkeypatch.setattr(update_check.requests, "get", result.get)
    return result


def test_verified_update_installs_only_expected_binary(release: _Release) -> None:
    assert release.update() is True
    assert release.executable.read_bytes() == NEW_BINARY
    assert release.urls[0].startswith("https://api.github.com/")
    if sys.platform != "win32":
        assert stat.S_IMODE(release.executable.stat().st_mode) == 0o700
    assert json.loads(update_check._CACHE_PATH.read_text())["latest_version"] == VERSION
    expected_paths = {release.executable}
    if release.target.startswith("windows"):
        backup = release.executable.with_name(release.executable.name + ".old")
        assert backup.read_bytes() == OLD_BINARY
        expected_paths.add(backup)
    assert set(release.executable.parent.iterdir()) == expected_paths


@pytest.mark.parametrize("digest", [None, "", "sha256:", "sha256:xyz", "md5:" + "a" * 32, 123])
def test_missing_or_invalid_checksum_never_downloads(release: _Release, digest: object) -> None:
    release.digest = digest
    assert release.update() is False
    assert len(release.urls) == 1
    assert "checksum" in release.output.getvalue().lower()
    release.assert_preserved()


@pytest.mark.parametrize("error", [requests.Timeout("offline"), requests.HTTPError("403")])
def test_metadata_failure_never_downloads(release: _Release, error: Exception) -> None:
    release.metadata_error = error
    assert release.update() is False
    assert len(release.urls) == 1
    release.assert_preserved()


def test_checksum_mismatch_preserves_installation(release: _Release) -> None:
    release.digest = "sha256:" + "0" * 64
    assert release.update() is False
    assert "checksum mismatch" in release.output.getvalue()
    release.assert_preserved()


def test_interrupted_download_preserves_installation(release: _Release) -> None:
    release.stream_error = requests.ConnectionError("download interrupted")
    assert release.update() is False
    release.assert_preserved()


@pytest.mark.parametrize("kind", ["missing", "empty", "directory", "symlink", "duplicate"])
def test_invalid_archive_member_preserves_installation(release: _Release, kind: str) -> None:
    release.set_archive(kind)
    assert release.update() is False
    release.assert_preserved()


def test_tar_hardlink_is_not_an_executable(release: _Release) -> None:
    if release.target.startswith("windows"):
        pytest.skip("ZIP does not have tar hardlinks")
    release.set_archive("hardlink")
    assert release.update() is False
    release.assert_preserved()


def test_corrupt_archive_preserves_installation(release: _Release) -> None:
    release.archive = b"not an archive"
    release.digest = "sha256:" + hashlib.sha256(release.archive).hexdigest()
    assert release.update() is False
    release.assert_preserved()


def test_update_does_not_overwrite_existing_staging_file(release: _Release) -> None:
    unrelated = release.executable.with_name(release.executable.name + ".new")
    unrelated.write_bytes(b"unrelated file")
    assert release.update() is True
    assert release.executable.read_bytes() == NEW_BINARY
    assert unrelated.read_bytes() == b"unrelated file"


def test_staging_write_failure_preserves_installation(
    release: _Release, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_copy(*_args: object, **_kwargs: object) -> None:
        raise OSError(errno.ENOSPC, "disk full")

    monkeypatch.setattr(update_check.shutil, "copyfileobj", fail_copy)
    assert release.update() is False
    release.assert_preserved()


@pytest.mark.parametrize("interrupted", [False, True])
def test_failed_replacement_restores_previous_binary(
    release: _Release, monkeypatch: pytest.MonkeyPatch, interrupted: bool
) -> None:
    original_replace = Path.replace

    def fail_install(path: Path, target: str | Path) -> Path:
        if Path(target) == release.executable and path.name != release.executable.name + ".old":
            assert path.parent.parent == release.executable.parent
            if interrupted:
                raise KeyboardInterrupt
            raise OSError(errno.EACCES, "replacement denied")
        return original_replace(path, target)

    monkeypatch.setattr(Path, "replace", fail_install)
    if interrupted:
        with pytest.raises(KeyboardInterrupt):
            release.update()
    else:
        assert release.update() is False
    release.assert_preserved()


@pytest.mark.parametrize("version", ["../../other", "1.8.0/other", "1.8.0?x=y", "garbage"])
def test_invalid_release_version_never_contacts_network(release: _Release, version: str) -> None:
    assert release.update(version) is False
    assert release.urls == []
    release.assert_preserved()


def test_uppercase_digest_and_prefixed_version_are_accepted(release: _Release) -> None:
    release.digest = "sha256:" + hashlib.sha256(release.archive).hexdigest().upper()
    assert release.update("v" + VERSION) is True
    assert release.executable.read_bytes() == NEW_BINARY


@pytest.mark.parametrize("metadata", [{"assets": []}, {"assets": None}, [], None])
def test_unusable_release_metadata_preserves_installation(
    release: _Release, monkeypatch: pytest.MonkeyPatch, metadata: object
) -> None:
    def get_metadata(url: str, **_kwargs: object) -> _Response:
        assert url.startswith("https://api.github.com/")
        return _Response(payload=metadata)

    monkeypatch.setattr(update_check.requests, "get", get_metadata)
    assert release.update() is False
    release.assert_preserved()


def test_failed_update_preserves_existing_cache(release: _Release) -> None:
    original_cache = json.dumps({"latest_version": VERSION, "skipped_version": "1.7.1"})
    update_check._CACHE_PATH.write_text(original_cache)
    release.digest = None
    assert release.update() is False
    assert update_check._CACHE_PATH.read_text() == original_cache
    assert release.executable.read_bytes() == OLD_BINARY


def test_existing_staging_symlink_is_not_followed(release: _Release, tmp_path: Path) -> None:
    unrelated = tmp_path / "unrelated"
    unrelated.write_bytes(b"keep this file")
    link = release.executable.with_name(release.executable.name + ".new")
    try:
        link.symlink_to(unrelated)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    assert release.update() is True
    assert unrelated.read_bytes() == b"keep this file"
    assert link.is_symlink()


@pytest.mark.parametrize("release", ["windows-x86_64"], indirect=True)
def test_windows_interruption_after_backup_move_restores_binary(
    release: _Release, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_rename = Path.rename

    def interrupt_after_move(path: Path, target: str | Path) -> Path:
        result = original_rename(path, target)
        if path == release.executable:
            raise KeyboardInterrupt
        return result

    monkeypatch.setattr(Path, "rename", interrupt_after_move)
    with pytest.raises(KeyboardInterrupt):
        release.update()
    release.assert_preserved()


@pytest.mark.parametrize("release", ["windows-x86_64"], indirect=True)
def test_windows_failed_rollback_retains_backup_and_reports_location(
    release: _Release, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_rename = Path.rename

    def deny_replace(_path: Path, _target: str | Path) -> Path:
        raise PermissionError("replacement denied")

    def deny_restore(path: Path, target: str | Path) -> Path:
        if Path(target) == release.executable:
            raise PermissionError("restore denied")
        return original_rename(path, target)

    monkeypatch.setattr(Path, "replace", deny_replace)
    monkeypatch.setattr(Path, "rename", deny_restore)
    assert release.update() is False
    backup = release.executable.with_name(release.executable.name + ".old")
    assert backup.read_bytes() == OLD_BINARY
    assert not release.executable.exists()
    assert "restore the previous binary" in release.output.getvalue()
    assert backup.name in release.output.getvalue()
    assert set(release.executable.parent.iterdir()) == {backup}


@pytest.mark.parametrize("verified", [True, False])
def test_update_cli_exits_without_requiring_a_scan_target(
    release: _Release, monkeypatch: pytest.MonkeyPatch, verified: bool
) -> None:
    monkeypatch.setattr(sys, "argv", ["strix", "--update"])
    monkeypatch.setattr(update_check, "_fetch_latest_version", lambda: VERSION)
    if not verified:
        release.digest = None
    with pytest.raises(SystemExit) as exc:
        cli_args.parse_arguments()
    assert exc.value.code == (0 if verified else 1)
    assert release.executable.read_bytes() == (NEW_BINARY if verified else OLD_BINARY)
