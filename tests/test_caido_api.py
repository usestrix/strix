"""Tests for Caido proxy API helpers."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from strix.tools.proxy.caido_api import list_sitemap_with_client


@pytest.mark.asyncio
async def test_list_sitemap_omits_blank_root_scope_id() -> None:
    query = AsyncMock(return_value={"sitemapRootEntries": {"edges": [], "count": {"value": 0}}})
    client = SimpleNamespace(graphql=SimpleNamespace(query=query))

    result = await list_sitemap_with_client(client, scope_id="   ")

    assert result["success"] is True
    assert result["entries"] == []
    assert query.await_args.kwargs["variables"] == {"scopeId": None}
