"""Caido client bootstrap.

The Caido CLI runs as an in-container sidecar listening on
``127.0.0.1:48080`` *inside* the sandbox. Guest mode grabs a token by
``session.exec()``-ing curl from inside the container. Account login uses a
personal access token. An in-memory :class:`TokenCache` captures the access
token the SDK saves after login and refresh, and publishes only that token
into the container for in-sandbox ``caido_api``. Nothing is written on the host.
The host-side :class:`caido_sdk_client.Client` always talks to the runtime's
exposed-port URL.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from strix.tools.proxy.caido_api import ACCESS_TOKEN_PATH


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession
    from caido_sdk_client import Client
    from caido_sdk_client.auth.cache.types import CachedToken


logger = logging.getLogger(__name__)


_LOGIN_AS_GUEST_BODY = (
    '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}'
)


async def _login_as_guest(
    session: BaseSandboxSession,
    *,
    container_url: str,
    attempts: int = 10,
) -> str:
    """``session.exec`` curl to fetch a guest token; retry until ready.

    Caido's GraphQL listener may not be up the instant the container
    starts. The retry loop also doubles as the Caido readiness probe —
    no separate TCP healthcheck needed.
    """
    last_err: str | None = None
    for i in range(1, attempts + 1):
        result = await session.exec(
            "curl",
            "-fsS",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            _LOGIN_AS_GUEST_BODY,
            f"{container_url}/graphql",
            timeout=15,
        )
        if result.ok():
            try:
                payload = json.loads(result.stdout)
                token = (
                    payload.get("data", {})
                    .get("loginAsGuest", {})
                    .get("token", {})
                    .get("accessToken")
                )
                if token:
                    return str(token)
                last_err = f"loginAsGuest returned no token: {payload}"
            except json.JSONDecodeError as exc:
                last_err = f"unparseable response: {exc}: {result.stdout!r}"
        else:
            stderr = result.stderr.decode("utf-8", errors="replace")[:200]
            last_err = f"curl exit {result.exit_code}: {stderr}"
        logger.debug("loginAsGuest attempt %d/%d failed: %s", i, attempts, last_err)
        await asyncio.sleep(min(2.0 * i, 8.0))

    raise RuntimeError(f"loginAsGuest failed after {attempts} attempts: {last_err}")


class _RunTokenCache:
    """Capture the access token the SDK saves. Never reload it.

    ``load`` stays empty so each ephemeral instance logs in with the PAT.
    ``save`` runs after login and again after a refresh.
    """

    def __init__(self, session: BaseSandboxSession) -> None:
        self._session = session

    async def load(self) -> CachedToken | None:
        return None

    async def save(self, token: CachedToken) -> None:
        access_token = token.access_token.strip()
        if not access_token:
            raise RuntimeError("Caido login returned no access token")
        await self._session.write(Path(ACCESS_TOKEN_PATH), io.BytesIO(access_token.encode()))

    async def clear(self) -> None:
        return None


async def bootstrap_caido(
    session: BaseSandboxSession,
    *,
    host_url: str,
    container_url: str,
    pat: str | None = None,
) -> Client:
    """Connect to the in-container Caido sidecar and select a fresh project.

    ``pat`` selects account login via :class:`PATAuthOptions` and an in-memory
    cache. Omit it for the guest token flow.
    """
    # The Caido SDK (and its generated GraphQL schema) is slow to import and is
    # only needed once a sandbox is actually being bootstrapped, so it is
    # imported here rather than at module scope.
    from caido_sdk_client.types import CreateProjectOptions

    logger.info("Bootstrapping Caido client (host=%s, container=%s)", host_url, container_url)

    if pat:
        from caido_sdk_client import Client, PATAuthOptions

        client = Client(host_url, auth=PATAuthOptions(pat=pat, cache=_RunTokenCache(session)))
    else:
        from caido_sdk_client import Client, TokenAuthOptions

        access_token = await _login_as_guest(session, container_url=container_url)
        client = Client(host_url, auth=TokenAuthOptions(token=access_token))
    try:
        # connect() is inside the guard as well: a cancellation there (scan
        # teardown while the bootstrap is still in flight) would otherwise
        # leave the half-connected transport behind.
        await client.connect()
        project = await client.project.create(
            CreateProjectOptions(name="sandbox", temporary=True),
        )
        await client.project.select(project.id)
    except BaseException:
        # The client never reaches the session bundle if connect or project
        # setup fails, so close it here to avoid leaking the transport.
        with contextlib.suppress(Exception):
            await client.aclose()
        raise
    logger.info("Caido project selected: %s", project.id)
    return client
