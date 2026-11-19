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
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession
    from caido_sdk_client import Client


logger = logging.getLogger(__name__)


_LOGIN_AS_GUEST_BODY = (
    '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}'
)
_PROJECT_SETUP_TIMEOUT_MS = 45_000
_BOOTSTRAP_ATTEMPTS = 3


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


async def _find_sandbox_project(client: Client) -> str | None:
    """Look for a project a create that timed out client-side may have left behind."""
    with contextlib.suppress(Exception):
        projects = [item for item in await client.project.list() if item.name == "sandbox"]
        if projects:
            return str(max(projects, key=lambda item: item.id).id)
    return None


async def _setup_project(host_url: str, access_token: str) -> None:
    """Select the sandbox project, retrying the whole connect/create/select sequence.

    Each attempt gets a fresh client with a deadline well past the SDK default:
    these mutations are slow on a cold Caido, while the long-lived client the
    scan uses keeps the short default so a traffic poll cannot stall on it.
    Until a project is selected Caido answers every proxied request with a 500,
    so giving up here costs the whole run, not just the traffic capture.
    """
    from caido_sdk_client import Client, TokenAuthOptions
    from caido_sdk_client.types import CreateProjectOptions

    project_id: str | None = None
    last_exc: Exception | None = None
    for attempt in range(1, _BOOTSTRAP_ATTEMPTS + 1):
        client = Client(
            host_url,
            auth=TokenAuthOptions(token=access_token),
            timeout_ms=_PROJECT_SETUP_TIMEOUT_MS,
        )
        try:
            await client.connect()
            if project_id is None:
                try:
                    created = await client.project.create(
                        CreateProjectOptions(name="sandbox", temporary=True),
                    )
                except Exception:
                    # A create that timed out client-side may still have landed.
                    project_id = await _find_sandbox_project(client)
                    raise
                project_id = created.id
            await client.project.select(project_id)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            logger.warning(
                "Caido project setup attempt %d/%d failed: %s",
                attempt,
                _BOOTSTRAP_ATTEMPTS,
                exc,
            )
            if attempt < _BOOTSTRAP_ATTEMPTS:
                await asyncio.sleep(min(2.0 * attempt, 8.0))
        else:
            logger.info("Caido project selected: %s", project_id)
            return
        finally:
            with contextlib.suppress(Exception):
                await client.aclose()
    raise RuntimeError(
        f"Caido project setup failed after {_BOOTSTRAP_ATTEMPTS} attempts"
    ) from last_exc


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

    logger.info("Bootstrapping Caido client (host=%s, container=%s)", host_url, container_url)

    access_token = await _login_as_guest(session, container_url=container_url)

    await _setup_project(host_url, access_token)

    last_exc: Exception | None = None
    for attempt in range(1, _BOOTSTRAP_ATTEMPTS + 1):
        client = Client(host_url, auth=TokenAuthOptions(token=access_token))
        try:
            # A cancellation while connecting can leave a half-connected
            # transport behind, so close the client before propagating it.
            await client.connect()
        except Exception as exc:  # noqa: BLE001
            with contextlib.suppress(Exception):
                await client.aclose()
            last_exc = exc
            logger.warning(
                "Caido client connect attempt %d/%d failed: %s",
                attempt,
                _BOOTSTRAP_ATTEMPTS,
                exc,
            )
            if attempt < _BOOTSTRAP_ATTEMPTS:
                await asyncio.sleep(min(2.0 * attempt, 8.0))
        except BaseException:
            # Teardown can cancel the bootstrap at any await; do not retry.
            with contextlib.suppress(Exception):
                await client.aclose()
            raise
        else:
            return client
    raise RuntimeError(
        f"Caido client connect failed after {_BOOTSTRAP_ATTEMPTS} attempts"
    ) from last_exc
