"""Persistent sandbox operations and safe repair checkpoints for artifact delivery."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


def clone_fix_workspace(source: Path, destination: Path) -> None:
    """Create a job-owned checkout without modifying the caller's repository."""
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git is required to prepare a fix.")
    status = subprocess.check_output(  # noqa: S603 - resolved Git executable, literal subcommand.
        [git, "status", "--porcelain=v1"], cwd=source, timeout=30
    )
    if status.strip():
        raise ValueError("Commit or stash repository changes before preparing a fix.")
    commit = (
        subprocess.check_output(  # noqa: S603 - resolved Git executable, literal subcommand.
            [git, "rev-parse", "HEAD"], cwd=source, timeout=30
        )
        .decode()
        .strip()
    )
    subprocess.run(  # noqa: S603
        [git, "clone", "--no-local", "--no-checkout", "--", str(source), str(destination)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    subprocess.run(  # noqa: S603
        [git, "checkout", "--detach", commit],
        cwd=destination,
        check=True,
        capture_output=True,
        timeout=60,
    )


def git_metadata_archive(workspace: Path) -> bytes:
    """Keep actual revisions/tags without forwarding Git credentials or hooks."""
    with tempfile.TemporaryDirectory(prefix="strix-fix-git-") as temporary:
        clone = Path(temporary) / "metadata"
        subprocess.run(  # noqa: S603
            [
                "/usr/bin/git",
                "clone",
                "--local",
                "--bare",
                "--no-hardlinks",
                "--dissociate",
                str(workspace),
                str(clone),
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )
        object_format = (
            subprocess.check_output(  # noqa: S603
                ["/usr/bin/git", "-C", str(clone), "rev-parse", "--show-object-format"], timeout=30
            )
            .decode()
            .strip()
        )
        config = "[core]\nrepositoryformatversion = 0\nbare = false\n"
        if object_format == "sha256":
            config = config.replace("= 0", "= 1") + "[extensions]\nobjectFormat = sha256\n"
        (clone / "config").write_text(config)
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            # Packed refs can leave refs/ empty; Git still requires the directory.
            refs = tarfile.TarInfo(".git/refs")
            refs.type, refs.mode = tarfile.DIRTYPE, 0o755
            archive.addfile(refs)
            for path in sorted(clone.rglob("*")):
                relative = path.relative_to(clone)
                if relative.parts[0] in {"hooks", "logs"} or not path.is_file():
                    continue
                if path.is_symlink():
                    raise ValueError("Git metadata snapshot cannot contain symbolic links.")
                info = archive.gettarinfo(str(path), arcname=f".git/{relative.as_posix()}")
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                with path.open("rb") as stream:
                    archive.addfile(info, stream)
        return output.getvalue()


def source_archive(workspace: Path) -> bytes:
    paths = (
        subprocess.check_output(
            ["/usr/bin/git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=workspace,
            timeout=60,
        )
        .decode()
        .split("\0")
    )
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for relative in sorted(set(paths) - {""}):
            path = workspace / relative
            if not path.is_file() and not path.is_symlink():
                continue
            if not path.parent.resolve().is_relative_to(workspace.resolve()):
                raise ValueError("Source path escapes the repository")
            info = archive.gettarinfo(str(path), arcname=relative)
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            if info.issym():
                # Preserve the link itself; never read outside the source tree.
                info.linkname = str(path.readlink())
                archive.addfile(info)
            elif info.isfile():
                with path.open("rb") as stream:
                    archive.addfile(info, stream)
    return output.getvalue()


# Include original tracked paths even if an agent commits changes or alters ignore rules.
_PATHS = r"""
import io, json, pathlib, subprocess, sys, tarfile

root = pathlib.Path(sys.argv[1]).resolve()
base = sys.argv[2]


def git(*args):
    return subprocess.check_output(["git", "-C", str(root), *args])


original = set(git("ls-tree", "-rz", "--name-only", base).decode().split("\0")) - {""}
current = set(
    git("ls-files", "--cached", "--others", "--exclude-standard", "-z")
    .decode()
    .split("\0")
) - {""}
paths = original | current

# Only untracked environment artifacts are excluded. A tracked dependency,
# generated file, or genuine source symlink remains part of the source delta.
environment_roots = {
    "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "coverage", ".coverage", ".nyc_output",
}
current = {
    name for name in current
    if name in original or not environment_roots.intersection(pathlib.PurePosixPath(name).parts)
}


def safe(name):
    p = root / name
    if (
        pathlib.PurePosixPath(name).is_absolute()
        or ".." in pathlib.PurePosixPath(name).parts
        or ".git" in pathlib.PurePosixPath(name).parts
    ):
        raise ValueError("Unsafe source path")
    if not p.parent.resolve().is_relative_to(root):
        raise ValueError("Source parent escapes repository")
    return p
"""
SOURCE_EXPORT = (
    _PATHS
    + r"""
changed = set(
    git("diff", "--name-only", "--no-renames", "-z", base).decode().split("\0")
) - {""}
changed |= current - original
changed = {
    name for name in changed
    if name in original or not environment_roots.intersection(pathlib.PurePosixPath(name).parts)
}
changed.discard(str(pathlib.Path(sys.argv[3]).relative_to(root)))
manifest = []
with tarfile.open(sys.argv[3], "w") as archive:
    for index, name in enumerate(sorted(changed)):
        p = safe(name)
        if p.is_symlink():
            raise ValueError("Changed symlinks require manual delivery: " + name)
        item = {"path": name, "delete": not p.exists(), "blob": str(index)}
        if p.exists():
            if not p.is_file():
                raise ValueError("Unsupported changed source: " + name)
            archive.add(p, arcname=str(index), recursive=False)
        manifest.append(item)
    body = json.dumps(manifest).encode()
    info = tarfile.TarInfo("manifest.json")
    info.size = len(body)
    archive.addfile(info, io.BytesIO(body))
"""
)


def apply_checkpoint(workspace: Path, content: bytes) -> None:
    """Apply only a validated delta to the controller-owned artifact mirror."""
    root = workspace.resolve()
    with tarfile.open(fileobj=io.BytesIO(content)) as archive:
        stream = archive.extractfile("manifest.json")
        if stream is None:
            raise ValueError("Missing checkpoint manifest")
        manifest = json.load(stream)
        validated: list[tuple[Path, bytes | None, int]] = []
        seen: set[str] = set()
        for item in manifest:
            name = item["path"]
            parts = PurePosixPath(name).parts
            if (
                not name
                or name in seen
                or PurePosixPath(name).is_absolute()
                or any(part in {"..", ".git"} for part in parts)
                or "\\" in name
                or "\0" in name
            ):
                raise ValueError("Unsafe checkpoint path")
            seen.add(name)
            path = root / name
            if not path.parent.resolve().is_relative_to(root) or path.is_symlink():
                raise ValueError("Checkpoint path escapes repository")
            if item["delete"]:
                validated.append((path, None, 0))
                continue
            member = archive.getmember(item["blob"])
            if not member.isfile():
                raise ValueError("Checkpoint files must be regular files")
            body = archive.extractfile(member)
            if body is None:
                raise ValueError("Missing checkpoint file")
            validated.append((path, body.read(), member.mode & 0o777))
    # The host mirror is owned by this job; it is never the customer's working tree.
    untracked = (
        subprocess.check_output(  # noqa: S603, RUF100
            ["/usr/bin/git", "ls-files", "--others", "--exclude-standard", "-z"],
            cwd=root,
            timeout=30,
        )
        .decode()
        .split("\0")
    )
    for name in filter(None, untracked):
        path = root / name
        if not path.parent.resolve().is_relative_to(root):
            raise ValueError("Unsafe prior checkpoint")
        path.unlink(missing_ok=True)
    subprocess.run(  # noqa: S603, RUF100
        ["/usr/bin/git", "restore", "--source=HEAD", "--staged", "--worktree", "."],
        cwd=root,
        check=True,
        capture_output=True,
        timeout=30,
    )
    for path, file_bytes, mode in validated:
        if file_bytes is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(file_bytes)
            path.chmod(mode)
