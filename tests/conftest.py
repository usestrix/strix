from __future__ import annotations

import os
from collections.abc import Generator

import pytest


@pytest.fixture
def clean_env() -> Generator[None, None, None]:
    """Remove Strix/Docker env vars that influence backend selection."""
    saved = {
        k: v
        for k, v in os.environ.items()
        if k in ("STRIX_RUNTIME_SOCKET", "DOCKER_HOST", "XDG_RUNTIME_DIR", "TMPDIR")
    }
    for k in saved:
        del os.environ[k]
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
