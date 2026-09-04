from __future__ import annotations

import contextlib
import os
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from pathlib import Path


SECRET_FILE_MODE = 0o600


def write_secret_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    tmp = path.with_suffix(path.suffix + ".tmp")
    with contextlib.suppress(FileNotFoundError):
        tmp.unlink()

    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, SECRET_FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    except BaseException as exc:
        _cleanup_tmp(tmp, exc)
        raise

    try:
        tmp.replace(path)
    except BaseException as exc:
        _cleanup_tmp(tmp, exc)
        raise


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
