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
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession
    from caido_sdk_client import Client


logger = logging.getLogger(__name__)


_LOGIN_AS_GUEST_BODY = (
    '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}'
)

_PERMANENT_EXIT_CODES = frozenset({
    2,  # curl: failed to initialize / bad command-line syntax
    3,  # curl: malformed URL
    126,  # command invoked cannot execute (permission denied)
    127,  # command not found (curl is not installed in the sandbox image)
})


def _is_permanent_transport_error(exc: BaseException) -> bool:
    """Return True if the sandbox transport has failed permanently and cannot recover."""
    if isinstance(exc, asyncio.CancelledError):
        return True

    if getattr(exc, "retryable", None) is False:
        return True

    try:
        from agents.sandbox.errors import ExecTransportError, WorkspaceStopError

        if isinstance(exc, WorkspaceStopError):
            return True
        if isinstance(exc, ExecTransportError) and not exc.context.get("retry_safe", False):
            return True
    except ImportError:
        pass

    try:
        from docker import errors as docker_errors  # type: ignore[import-untyped, unused-ignore]

        if isinstance(exc, (docker_errors.NotFound, docker_errors.APIError)):
            return True
    except ImportError:
        pass

    return False


def _extract_access_token(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    login = data.get("loginAsGuest")
    if not isinstance(login, dict):
        return None
    token_obj = login.get("token")
    if not isinstance(token_obj, dict):
        return None
    token = token_obj.get("accessToken")
    if isinstance(token, str) and token.strip():
        return token.strip()
    return None


def _format_stderr(raw_stderr: Any, max_len: int = 200) -> str:
    if isinstance(raw_stderr, (bytes, bytearray)):
        return raw_stderr.decode("utf-8", errors="replace")[:max_len]
    if raw_stderr is not None:
        return str(raw_stderr)[:max_len]
    return ""


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
        try:
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
        except Exception as exc:
            if _is_permanent_transport_error(exc):
                raise RuntimeError(
                    f"loginAsGuest failed permanently: session.exec failed: {exc}"
                ) from exc
            last_err = f"session.exec failed: {exc}"
            logger.debug("loginAsGuest attempt %d/%d failed: %s", i, attempts, last_err)
            await asyncio.sleep(min(2.0 * i, 8.0))
            continue

        if result.ok():
            try:
                payload = json.loads(result.stdout)
                token = _extract_access_token(payload)
                if token:
                    return token
                last_err = f"loginAsGuest returned no token: {payload}"
            except (json.JSONDecodeError, AttributeError, TypeError) as exc:
                last_err = f"unparseable response: {exc}: {result.stdout!r}"
        else:
            stderr = _format_stderr(result.stderr)
            if result.exit_code in _PERMANENT_EXIT_CODES:
                raise RuntimeError(
                    f"loginAsGuest failed permanently: curl exit {result.exit_code}: {stderr}"
                )
            last_err = f"curl exit {result.exit_code}: {stderr}"
        logger.debug("loginAsGuest attempt %d/%d failed: %s", i, attempts, last_err)
        await asyncio.sleep(min(2.0 * i, 8.0))

    raise RuntimeError(f"loginAsGuest failed after {attempts} attempts: {last_err}")


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
