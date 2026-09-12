"""Privacy-conscious local source packaging for managed scans."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import shutil
import stat
import subprocess  # nosec B404
import tempfile
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

import strix.interface.cloud.http as http  # noqa: PLR0402


if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import Protocol

    class _ScandirIterator(Iterator[os.DirEntry[str]], Protocol):
        def close(self) -> None: ...


MAX_FILES = 20_000
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_TOTAL_BYTES = 250 * 1024 * 1024
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_CANDIDATE_PATHS = 200_000
MAX_IGNORE_BYTES = 64 * 1024
MAX_IGNORE_PATTERNS = 1_000
MAX_IGNORE_PATTERN_CHARS = 1_024

_ALWAYS_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "vendor",
        "venv",
        ".venv",
        "env",
        "__pycache__",
        ".tox",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "dist",
        "build",
        "coverage",
        "target",
        ".next",
        ".nuxt",
        ".gradle",
    }
)
_SENSITIVE_NAMES = frozenset(
    {
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "credentials.json",
        "service-account.json",
        "service_account.json",
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
        "application_default_credentials.json",
    }
)
_SENSITIVE_PATTERNS = (
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.keystore",
    "*.jks",
    "secrets.*",
    "secret.*",
    ".env.*",
)
_SENSITIVE_PATH_SUFFIXES = (
    (".aws", "credentials"),
    (".aws", "config"),
    (".docker", "config.json"),
    (".config", "gcloud", "credentials.db"),
    (".azure", "accesstokens.json"),
    (".azure", "azureprofile.json"),
    (".kube", "config"),
)
_ARCHIVE_SUFFIXES = (
    ".zip",
    ".tar",
    ".tgz",
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".7z",
    ".rar",
    ".gz",
    ".bz2",
    ".xz",
    ".jar",
    ".war",
    ".whl",
    ".nupkg",
    ".apk",
    ".ipa",
)
_ARCHIVE_MAGIC_PREFIXES = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
)


@dataclass(frozen=True)
class SelectedFile:
    path: Path
    archive_name: str
    size: int
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class SourceManifest:
    source: Path
    files: tuple[SelectedFile, ...]
    excluded: Counter[str]
    include_hidden: bool
    include_sensitive: bool
    include_archives: bool

    @property
    def total_bytes(self) -> int:
        return sum(item.size for item in self.files)

    def as_dict(
        self,
        *,
        show_files: bool,
        archive_bytes: int | None = None,
        archive_sha256: str | None = None,
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "source": str(self.source),
            "file_count": len(self.files),
            "uncompressed_bytes": self.total_bytes,
            "excluded_count": sum(self.excluded.values()),
            "excluded_by_reason": dict(sorted(self.excluded.items())),
            "include_hidden": self.include_hidden,
            "include_sensitive": self.include_sensitive,
            "include_archives": self.include_archives,
        }
        if archive_bytes is not None:
            result["archive_bytes"] = archive_bytes
        if archive_sha256 is not None:
            result["archive_sha256"] = archive_sha256
        if show_files:
            result["files"] = [item.archive_name for item in self.files]
        return result


@dataclass(frozen=True)
class SourceBundle:
    manifest: SourceManifest
    archive_path: Path
    archive_bytes: int
    archive_sha256: str

    def summary(self, *, show_files: bool) -> dict[str, object]:
        return self.manifest.as_dict(
            show_files=show_files,
            archive_bytes=self.archive_bytes,
            archive_sha256=self.archive_sha256,
        )


def prepare_source(
    value: str,
    *,
    include_hidden: bool,
    include_sensitive: bool,
    include_archives: bool,
    exclude: list[str],
) -> SourceBundle:
    """Select safe source files and build a bounded temporary ZIP archive."""
    source = Path(value).expanduser().resolve()
    if not source.is_dir():
        if source.is_file() and (
            source.name.lower().endswith(_ARCHIVE_SUFFIXES) or _has_archive_magic(source)
        ):
            raise http.CloudError(
                f"--source must be a directory, not an archive: {source}",
                next_step=(
                    "Extract the archive and pass the directory to --source. Strix packs the "
                    "directory and excludes dependencies, build output, and secret-like files. "
                    "Add --dry-run --show-files to review the selection first."
                ),
            )
        raise http.CloudError(f"--source must be a directory: {source}")
    manifest = select_source(
        source,
        include_hidden=include_hidden,
        include_sensitive=include_sensitive,
        include_archives=include_archives,
        exclude=exclude,
    )
    if not manifest.files:
        raise http.CloudError("no files remain after applying source upload exclusions.")

    with tempfile.NamedTemporaryFile(prefix="strix-source-", suffix=".zip", delete=False) as handle:
        archive_path = Path(handle.name)
    try:
        _write_archive(archive_path, manifest.files)
    except BaseException:
        archive_path.unlink(missing_ok=True)
        raise
    archive_bytes = archive_path.stat().st_size
    if archive_bytes > MAX_ARCHIVE_BYTES:
        archive_path.unlink(missing_ok=True)
        raise _archive_too_large_error(manifest, archive_bytes)
    digest = _sha256(archive_path)
    return SourceBundle(manifest, archive_path, archive_bytes, digest)


_LARGEST_FILES_SHOWN = 5


def _format_mib(size: int) -> str:
    return f"{size / (1024 * 1024):.1f} MiB"


def _archive_too_large_error(manifest: SourceManifest, archive_bytes: int) -> http.CloudError:
    """Name the largest selected files so the user knows what to exclude."""
    largest = sorted(manifest.files, key=lambda item: item.size, reverse=True)
    listed = ", ".join(
        f"{item.archive_name} ({_format_mib(item.size)})" for item in largest[:_LARGEST_FILES_SHOWN]
    )
    return http.CloudError(
        f"the source archive is {_format_mib(archive_bytes)}, larger than the "
        f"{_format_mib(MAX_ARCHIVE_BYTES)} upload limit. Largest files: {listed}.",
        next_step=(
            "Add --exclude patterns for large files or directories, or point --source at a "
            "smaller directory. Run with --dry-run --show-files to review the selection."
        ),
    )


def select_source(
    source: Path,
    *,
    include_hidden: bool = False,
    include_sensitive: bool = False,
    include_archives: bool = False,
    exclude: list[str] | None = None,
) -> SourceManifest:
    excluded: Counter[str] = Counter()
    selected: list[SelectedFile] = []
    patterns = [*_load_ignore_patterns(source), *(exclude or [])]
    _validate_patterns(patterns)
    total_bytes = 0
    for relative in _candidate_paths(
        source,
        include_hidden=include_hidden,
        patterns=patterns,
        excluded=excluded,
    ):
        archive_name = relative.as_posix()
        reason = _exclusion_reason(
            relative,
            include_hidden=include_hidden,
            include_sensitive=include_sensitive,
            include_archives=include_archives,
            patterns=patterns,
        )
        if reason:
            excluded[reason] += 1
            continue
        path = source / relative
        try:
            info = path.lstat()
        except OSError:
            excluded["unreadable"] += 1
            continue
        if not stat.S_ISREG(info.st_mode):
            excluded["symlink_or_non_file"] += 1
            continue
        if not include_archives and _has_archive_magic(path):
            excluded["nested_archive"] += 1
            continue
        if info.st_size > MAX_FILE_BYTES:
            raise http.CloudError(
                f"{archive_name} is larger than the 25 MB per-file limit; exclude it explicitly."
            )
        selected.append(
            SelectedFile(
                path=path,
                archive_name=archive_name,
                size=info.st_size,
                device=info.st_dev,
                inode=info.st_ino,
                mtime_ns=info.st_mtime_ns,
                ctime_ns=info.st_ctime_ns,
            )
        )
        total_bytes += info.st_size
        if len(selected) > MAX_FILES:
            raise http.CloudError(
                f"source contains more than {MAX_FILES:,} files; narrow --source or add exclusions."
            )
        if total_bytes > MAX_TOTAL_BYTES:
            raise http.CloudError(
                "selected source is larger than the 250 MB expanded-size limit; narrow --source "
                "or add --exclude patterns."
            )
    selected.sort(key=lambda item: item.archive_name)
    return SourceManifest(
        source,
        tuple(selected),
        excluded,
        include_hidden,
        include_sensitive,
        include_archives,
    )


def remove_bundle(bundle: SourceBundle) -> None:
    bundle.archive_path.unlink(missing_ok=True)


def _candidate_paths(
    source: Path,
    *,
    include_hidden: bool,
    patterns: list[str],
    excluded: Counter[str],
) -> Iterator[Path]:
    git_root = _git_root(source)
    if git_root is not None:
        git = shutil.which("git")
        if git is not None:
            yield from _git_candidate_paths(git, git_root, source)
            return
    yield from _walk_candidate_paths(
        source,
        include_hidden=include_hidden,
        patterns=patterns,
        excluded=excluded,
    )


def _git_candidate_paths(git: str, git_root: Path, source: Path) -> Iterator[Path]:
    """Stream Git's NUL-delimited manifest without buffering an unbounded repository."""
    relative_source = source.relative_to(git_root)
    command = [
        git,
        "-C",
        str(git_root),
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
    ]
    if relative_source != Path():
        command.append(relative_source.as_posix())
    try:
        process = subprocess.Popen(  # noqa: S603  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise http.CloudError(f"could not enumerate Git source files: {exc}") from exc
    assert process.stdout is not None
    buffer = b""
    count = 0
    try:
        while chunk := process.stdout.read(64 * 1024):
            buffer += chunk
            records = buffer.split(b"\0")
            buffer = records.pop()
            for raw in records:
                relative = _git_relative_path(raw, relative_source)
                if relative is None:
                    continue
                count += 1
                _check_candidate_limit(count)
                yield relative
        if buffer:
            raise http.CloudError("Git returned a malformed source file manifest.")
        if process.wait() != 0:
            raise http.CloudError("Git could not enumerate the source directory.")
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def _git_relative_path(raw: bytes, relative_source: Path) -> Path | None:
    repo_relative = Path(os.fsdecode(raw))
    try:
        relative = repo_relative.relative_to(relative_source)
    except ValueError:
        return None
    if relative.is_absolute() or ".." in relative.parts:
        raise http.CloudError("Git returned an unsafe source path.")
    return relative


def _walk_candidate_paths(
    source: Path,
    *,
    include_hidden: bool,
    patterns: list[str],
    excluded: Counter[str],
) -> Iterator[Path]:
    """Walk top-down so excluded dependency, VCS, and hidden trees are never traversed."""
    count = 0
    stack: list[tuple[Path, _ScandirIterator]] = []
    try:
        stack.append((source, os.scandir(source)))
        while stack:
            root_path, entries = stack[-1]
            try:
                entry = next(entries)
            except StopIteration:
                entries.close()
                stack.pop()
                continue
            count += 1
            _check_candidate_limit(count)
            path = root_path / entry.name
            relative = path.relative_to(source)
            try:
                is_directory = entry.is_dir(follow_symlinks=False)
                is_symlink = entry.is_symlink()
            except OSError:
                excluded["unreadable"] += 1
                continue
            if is_directory:
                reason = _pruned_directory_reason(
                    relative,
                    include_hidden=include_hidden,
                    patterns=patterns,
                )
                if reason:
                    excluded[reason] += 1
                    continue
                try:
                    stack.append((path, os.scandir(path)))
                except OSError:
                    excluded["unreadable"] += 1
                continue
            if is_symlink:
                excluded["symlink_or_non_file"] += 1
                continue
            yield relative
    except OSError as exc:
        raise http.CloudError(f"could not enumerate source directory {source}: {exc}") from exc
    finally:
        for _, entries in stack:
            entries.close()


def _pruned_directory_reason(
    relative: Path,
    *,
    include_hidden: bool,
    patterns: list[str],
) -> str | None:
    lower_parts = tuple(part.lower() for part in relative.parts)
    if any(part == ".git" for part in lower_parts):
        return "git_metadata"
    if any(part in _ALWAYS_EXCLUDED_DIRS for part in lower_parts):
        return "dependency_or_build_output"
    if not include_hidden and any(part.startswith(".") for part in relative.parts):
        return "hidden"
    if any(_matches_user_pattern(relative, pattern) for pattern in patterns):
        return "user_pattern"
    return None


def _check_candidate_limit(count: int) -> None:
    if count > MAX_CANDIDATE_PATHS:
        raise http.CloudError(
            f"source enumeration exceeded {MAX_CANDIDATE_PATHS:,} paths before filtering; "
            "narrow --source or add directory exclusions."
        )


def _git_root(source: Path) -> Path | None:
    git = shutil.which("git")
    if git is None:
        return None
    result = subprocess.run(  # noqa: S603  # nosec B603
        [git, "-C", str(source), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        return Path(result.stdout.strip()).resolve()
    except OSError:
        return None


def _exclusion_reason(  # noqa: PLR0911
    relative: Path,
    *,
    include_hidden: bool,
    include_sensitive: bool,
    include_archives: bool,
    patterns: list[str],
) -> str | None:
    parts = relative.parts
    lower_parts = tuple(part.lower() for part in parts)
    if any(part == ".git" for part in lower_parts):
        return "git_metadata"
    if any(part in _ALWAYS_EXCLUDED_DIRS for part in lower_parts[:-1]):
        return "dependency_or_build_output"
    if not include_hidden and any(part.startswith(".") for part in parts):
        return "hidden"
    if any(_matches_user_pattern(relative, pattern) for pattern in patterns):
        return "user_pattern"
    name = relative.name.lower()
    if not include_sensitive and (
        name in _SENSITIVE_NAMES
        or any(fnmatch.fnmatch(name, pattern) for pattern in _SENSITIVE_PATTERNS)
        or any(
            lower_parts[-len(suffix) :] == suffix
            for suffix in _SENSITIVE_PATH_SUFFIXES
            if len(lower_parts) >= len(suffix)
        )
    ):
        return "sensitive_filename"
    if not include_archives and name.endswith(_ARCHIVE_SUFFIXES):
        return "nested_archive"
    return None


def _matches_user_pattern(relative: Path, pattern: str) -> bool:
    """Match exclude globs, including intuitive trailing-slash directory rules."""
    relative_posix = relative.as_posix()
    posix = PurePosixPath(relative_posix)
    if pattern.endswith("/"):
        directory_pattern = pattern.rstrip("/")
        if not directory_pattern:
            return False
        return (
            posix.match(directory_pattern)
            or fnmatch.fnmatch(relative_posix, directory_pattern)
            or any(
                PurePosixPath(parent.as_posix()).match(directory_pattern)
                or fnmatch.fnmatch(parent.as_posix(), directory_pattern)
                for parent in posix.parents
                if parent != PurePosixPath(".")
            )
        )
    return posix.match(pattern) or fnmatch.fnmatch(relative_posix, pattern)


def _write_archive(destination: Path, files: tuple[SelectedFile, ...]) -> None:
    with zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
    ) as archive:
        for item in files:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(item.path, flags)
            except OSError as exc:
                raise http.CloudError(f"could not safely read {item.archive_name}: {exc}") from exc
            with os.fdopen(descriptor, "rb") as source_file:
                current = os.fstat(source_file.fileno())
                if (
                    not stat.S_ISREG(current.st_mode)
                    or current.st_size != item.size
                    or current.st_dev != item.device
                    or current.st_ino != item.inode
                    or current.st_mtime_ns != item.mtime_ns
                    or current.st_ctime_ns != item.ctime_ns
                ):
                    raise http.CloudError(
                        f"{item.archive_name} changed while the source archive was being built; "
                        "retry."
                    )
                info = zipfile.ZipInfo(item.archive_name)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                with archive.open(info, "w", force_zip64=True) as target:
                    remaining = item.size
                    while remaining:
                        chunk = source_file.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise http.CloudError(
                                f"{item.archive_name} changed while the source archive was being "
                                "built; retry."
                            )
                        target.write(chunk)
                        remaining -= len(chunk)
                    final = os.fstat(source_file.fileno())
                    if (
                        source_file.read(1)
                        or not stat.S_ISREG(final.st_mode)
                        or final.st_size != item.size
                        or final.st_dev != item.device
                        or final.st_ino != item.inode
                        or final.st_mtime_ns != item.mtime_ns
                        or final.st_ctime_ns != item.ctime_ns
                    ):
                        raise http.CloudError(
                            f"{item.archive_name} changed while the source archive was being "
                            "built; retry."
                        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _has_archive_magic(path: Path) -> bool:
    """Recognize common archive containers even when their suffix is disguised."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            header = stream.read(512)
    except OSError:
        return False
    return header.startswith(_ARCHIVE_MAGIC_PREFIXES) or header[257:262] == b"ustar"


def _load_ignore_patterns(source: Path) -> list[str]:
    path = source / ".strixignore"
    raw_text = _read_ignore_file(path)
    if raw_text is None:
        return []
    if len(raw_text) > MAX_IGNORE_BYTES:
        raise http.CloudError(f"{path} is larger than the {MAX_IGNORE_BYTES:,}-byte limit.")
    try:
        lines = raw_text.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise http.CloudError(f"{path} must be UTF-8 text.") from exc
    patterns: list[str] = []
    for line_number, raw in enumerate(lines, start=1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        if value.startswith("!"):
            raise http.CloudError(
                f"{path}:{line_number}: negated patterns are not supported; use exclude-only globs."
            )
        patterns.append(value)
        if len(patterns) > MAX_IGNORE_PATTERNS:
            raise http.CloudError(
                f"{path} contains more than {MAX_IGNORE_PATTERNS:,} exclusion patterns."
            )
    return patterns


def _read_ignore_file(path: Path) -> bytes | None:
    """Read a bounded regular ignore file without blocking on a FIFO or device."""
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise http.CloudError(f"could not read {path}: {exc}") from exc
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        os.close(descriptor)
        raise http.CloudError(f"could not inspect {path}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise http.CloudError(f"{path} must be a regular file.")
    try:
        stream = os.fdopen(descriptor, "rb")
    except OSError as exc:
        os.close(descriptor)
        raise http.CloudError(f"could not read {path}: {exc}") from exc
    try:
        return stream.read(MAX_IGNORE_BYTES + 1)
    except OSError as exc:
        raise http.CloudError(f"could not read {path}: {exc}") from exc
    finally:
        stream.close()


def _validate_patterns(patterns: list[str]) -> None:
    if len(patterns) > MAX_IGNORE_PATTERNS:
        raise http.CloudError(
            f"source upload accepts at most {MAX_IGNORE_PATTERNS:,} exclusion patterns."
        )
    for pattern in patterns:
        if len(pattern) > MAX_IGNORE_PATTERN_CHARS:
            raise http.CloudError(
                "source exclusion patterns must be at most "
                f"{MAX_IGNORE_PATTERN_CHARS:,} characters each."
            )
        if "\x00" in pattern:
            raise http.CloudError("source exclusion patterns cannot contain NUL bytes.")
