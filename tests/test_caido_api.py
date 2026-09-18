from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from strix.tools.proxy.caido_api import (
    _SITEMAP_ROOTS_QUERY,
    _normalize_optional_id,
    list_requests_with_client,
    list_sitemap_with_client,
)


@pytest.mark.parametrize("value", ["", "  ", "null", "None", "UNDEFINED", "none", "undefined"])
def test_normalize_optional_id_treats_llm_null_sentinels_as_none(value: str) -> None:
    assert _normalize_optional_id(value, name="scope_id") is None


def test_normalize_optional_id_accepts_valid_integers() -> None:
    assert _normalize_optional_id("123", name="scope_id") == "123"
    assert _normalize_optional_id(" 456 ", name="scope_id") == "456"
    assert _normalize_optional_id("-1", name="scope_id") == "-1"


def test_normalize_optional_id_rejects_non_numeric_value() -> None:
    with pytest.raises(ValueError, match="integer-shaped Caido ID"):
        _normalize_optional_id("all", name="scope_id")


def test_normalize_optional_id_rejects_overflow() -> None:
    with pytest.raises(ValueError, match="signed 32-bit integer"):
        _normalize_optional_id(str(2**31), name="scope_id")

    with pytest.raises(ValueError, match="signed 32-bit integer"):
        _normalize_optional_id(str(-(2**31) - 1), name="scope_id")


@pytest.mark.asyncio
async def test_list_requests_with_client_omits_sentinel_scope() -> None:
    mock_client = MagicMock()
    mock_builder = MagicMock()
    mock_builder.first.return_value = mock_builder
    mock_builder.descending.return_value = mock_builder
    mock_builder.ascending.return_value = mock_builder
    mock_builder.execute = AsyncMock(return_value={"data": []})
    mock_client.request.list.return_value = mock_builder

    await list_requests_with_client(mock_client, scope_id="null")

    mock_builder.scope.assert_not_called()


@pytest.mark.asyncio
async def test_list_sitemap_with_client_sentinel_parent_queries_roots() -> None:
    mock_client = MagicMock()
    mock_client.graphql.query = AsyncMock(return_value={"sitemapRootEntries": {"edges": [], "count": {"value": 0}}})

    res = await list_sitemap_with_client(mock_client, scope_id="null", parent_id="none")

    assert res["success"] is True
    mock_client.graphql.query.assert_called_once_with(
        _SITEMAP_ROOTS_QUERY,
        variables={"scopeId": None},
    )
