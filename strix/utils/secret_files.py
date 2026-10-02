from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Generator
    from typing import BinaryIO


SECRET_FILE_MODE = 0o600


@contextmanager
def open_secret_file(path: Path) -> Generator[BinaryIO, None, None]:
    """Write through a private sibling file and publish it atomically on success."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # mkstemp creates the inode with mode 0600, before any caller writes content.
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            yield handle
        tmp.replace(path)
    except BaseException as exc:
        _cleanup_tmp(tmp, exc)
        raise


def write_secret_text(path: Path, text: str) -> None:
    with open_secret_file(path) as handle:
        handle.write(text.encode("utf-8"))


def _cleanup_tmp(tmp: Path, cause: BaseException) -> None:
    """Delete the temporary secret file. A failed delete must not stay silent."""
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        message = (
            f"could not store the secret, and the temporary file {tmp} "
            f"still holds it. Delete the file manually."
        )
        raise OSError(message) from cause
