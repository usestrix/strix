"""Tests for interface message cleanups.

Covers three cosmetic-correctness fixes:
    * dead ``STRIX_REASONING_EFFORT`` branches removed from ``validate_environment``;
    * stale ``claude-opus-4-7`` model name replaced with ``claude-sonnet-4-6``;
    * ``_resolve_sandbox_image`` reports the env var with correct ``STRIX_IMAGE`` casing.
"""

import inspect
import types

import pytest

from strix.interface import cli
from strix.interface.main import validate_environment, warm_up_llm


def test_reasoning_effort_branches_removed() -> None:
    source = inspect.getsource(validate_environment)
    assert "STRIX_REASONING_EFFORT" not in source


def test_model_name_uses_sonnet_recommendation() -> None:
    source = inspect.getsource(validate_environment) + inspect.getsource(warm_up_llm)
    assert "claude-opus-4-7" not in source
    assert "claude-sonnet-4-6" in source


def test_resolve_sandbox_image_uses_correct_env_casing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_settings = types.SimpleNamespace(runtime=types.SimpleNamespace(image=""))
    monkeypatch.setattr(cli, "load_settings", lambda: fake_settings)
    with pytest.raises(RuntimeError, match="STRIX_IMAGE"):
        cli._resolve_sandbox_image()
