"""Caido client bootstrap.

The Caido CLI runs as an in-container sidecar listening on
``127.0.0.1:48080`` *inside* the sandbox. We grab a guest token by
``session.exec()``-ing curl from inside the container, then construct
a host-side :class:`caido_sdk_client.Client` against the runtime's
exposed-port URL for all subsequent SDK calls.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession
    from caido_sdk_client import Client


logger = logging.getLogger(__name__)


_LOGIN_AS_GUEST_BODY = (
    '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}'
)

# The guest-login loop below doubles as Caido's readiness probe, so its budget
# must outlast the slowest part of container bring-up. When the host UID differs
# from the image's ``pentester`` UID, ``docker-entrypoint.sh`` recursively chowns
# the (large, tool-laden) home directory *before* it launches ``caido-cli``, so
# on a big image or slow storage the listener can take well over a minute to
# appear. A fixed ~60s budget loses that race and the failure is cached for the
# whole scan, silently disabling the proxy. Probe generously by default and let
# it be tuned via the environment.
_LOGIN_TIMEOUT_DEFAULT_S = 180.0
_LOGIN_POLL_INTERVAL_S = 3.0
_LOGIN_TIMEOUT_ENV = "STRIX_CAIDO_BOOTSTRAP_TIMEOUT"


def _login_timeout_s() -> float:
    """Guest-login / readiness budget in seconds (``STRIX_CAIDO_BOOTSTRAP_TIMEOUT``)."""
    raw = os.environ.get(_LOGIN_TIMEOUT_ENV, "").strip()
    if raw:
        try:
            value = float(raw)
        except ValueError:
            logger.warning(
                "Invalid %s=%r; using %.0fs", _LOGIN_TIMEOUT_ENV, raw, _LOGIN_TIMEOUT_DEFAULT_S
            )
        else:
            if value > 0:
                return value
    return _LOGIN_TIMEOUT_DEFAULT_S


async def _login_as_guest(
    session: BaseSandboxSession,
    *,
    container_url: str,
    timeout_s: float | None = None,
) -> str:
    """``session.exec`` curl to fetch a guest token; poll until Caido is ready.

    Caido's GraphQL listener may not be up the instant the container starts, and
    when the host UID differs from the image UID ``docker-entrypoint.sh``
    recursively chowns the home directory before launching ``caido-cli`` — so on
    a large image the listener can take well over a minute to appear. Poll until
    a guest token is obtained or ``timeout_s`` (default
    :data:`_LOGIN_TIMEOUT_DEFAULT_S`, overridable via ``STRIX_CAIDO_BOOTSTRAP_TIMEOUT``)
    elapses. This loop doubles as Caido's readiness probe — no separate TCP
    healthcheck needed.
    """
    budget = _login_timeout_s() if timeout_s is None else timeout_s
    loop = asyncio.get_running_loop()
    deadline = loop.time() + budget
    attempt = 0
    last_err: str | None = None
    while True:
        attempt += 1
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
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        logger.debug(
            "loginAsGuest attempt %d failed (%.0fs of %.0fs left): %s",
            attempt,
            remaining,
            budget,
            last_err,
        )
        await asyncio.sleep(min(_LOGIN_POLL_INTERVAL_S, remaining))

    raise RuntimeError(f"loginAsGuest failed after {attempt} attempts / {budget:.0f}s: {last_err}")


async def bootstrap_caido(
    session: BaseSandboxSession,
    *,
    host_url: str,
    container_url: str,
) -> Client:
    """Connect to the in-container Caido sidecar and select a fresh project."""
    # The Caido SDK (and its generated GraphQL schema) is slow to import and is
    # only needed once a sandbox is actually being bootstrapped, so it is
    # imported here rather than at module scope.
    from caido_sdk_client import Client, TokenAuthOptions
    from caido_sdk_client.types import CreateProjectOptions

    logger.info("Bootstrapping Caido client (host=%s, container=%s)", host_url, container_url)

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
