"""Tests for the get_credential tool."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock


def _make_ctx(credentials: dict) -> MagicMock:
    ctx = MagicMock()
    ctx.context = {"credentials": credentials}
    return ctx


def test_returns_value_for_known_credential():
    from strix.tools.credentials.tool import _get_credential_impl

    ctx = _make_ctx({"PASSWORD": "s3cr3t"})
    result = asyncio.run(_get_credential_impl(ctx, "PASSWORD"))
    data = json.loads(result)
    assert data == {"value": "s3cr3t"}


def test_returns_error_for_unknown_credential():
    from strix.tools.credentials.tool import _get_credential_impl

    ctx = _make_ctx({"PASSWORD": "s3cr3t", "USER": "admin"})
    result = asyncio.run(_get_credential_impl(ctx, "UNKNOWN"))
    data = json.loads(result)
    assert "error" in data
    assert "UNKNOWN" in data["error"]
    assert sorted(data["available"]) == ["PASSWORD", "USER"]


def test_returns_error_when_no_credentials_in_context():
    from strix.tools.credentials.tool import _get_credential_impl

    ctx = MagicMock()
    ctx.context = {}  # no credentials key
    result = asyncio.run(_get_credential_impl(ctx, "PASSWORD"))
    data = json.loads(result)
    assert "error" in data
    assert data["available"] == []


def test_returns_error_when_context_is_not_dict():
    from strix.tools.credentials.tool import _get_credential_impl

    ctx = MagicMock()
    ctx.context = None
    result = asyncio.run(_get_credential_impl(ctx, "PASSWORD"))
    data = json.loads(result)
    assert "error" in data


def test_get_credential_is_registered_as_function_tool():
    """Verify the tool is a FunctionTool with the expected name."""
    from agents.tool import FunctionTool

    from strix.tools.credentials.tool import get_credential

    assert isinstance(get_credential, FunctionTool)
    assert get_credential.name == "get_credential"


def test_get_credential_has_description():
    from strix.tools.credentials.tool import get_credential

    assert get_credential.description, "Tool description must not be empty"
