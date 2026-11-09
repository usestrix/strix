"""In-memory bearer refresh for HTTP MCP connections."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import httpx


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable


logger = logging.getLogger(__name__)


class RefreshingBearerAuth(httpx.Auth):
    def __init__(
        self, token: str | None, refresh_token: Callable[[], Awaitable[str | None]]
    ) -> None:
        self._token = token
        self._refresh_token = refresh_token
        self._lock = asyncio.Lock()
        self._refresh_generation = 0

    def _authorize(self, request: httpx.Request, token: str | None) -> None:
        if token:
            request.headers["Authorization"] = f"Bearer {token}"
        else:
            request.headers.pop("Authorization", None)

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        sent_token = self._token
        sent_generation = self._refresh_generation
        self._authorize(request, sent_token)
        response = yield request
        if response.status_code != 401:
            return
        async with self._lock:
            if self._token == sent_token and self._refresh_generation == sent_generation:
                try:
                    token = await self._refresh_token()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("MCP bearer refresh failed (%s)", type(exc).__name__)
                    token = None
                self._refresh_generation += 1
                if token and token != sent_token:
                    self._token = token
            retry_token = self._token
        if retry_token and retry_token != sent_token:
            self._authorize(request, retry_token)
            yield request
