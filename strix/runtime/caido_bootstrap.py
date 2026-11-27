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
import re
import shlex
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession
    from caido_sdk_client import Client


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


_UPSTREAM_RE = re.compile(r"[A-Za-z0-9.-]+:\d{1,5}")

_FALLBACK_SCRIPT = """
port_open() {{ (exec 3<>/dev/tcp/127.0.0.1/{port}) 2>/dev/null; }}
# The entrypoint exits if Caido dies before it has written the proxy settings.
for _ in $(seq 120); do [ -e /etc/profile.d/proxy.sh ] && break; sleep 0.25; done
sudo pkill -x caido-cli
for _ in $(seq 40); do port_open || break; sleep 0.25; done
{proxy}
setsid nohup "$@" >/dev/null 2>&1 </dev/null &
for _ in $(seq 80); do port_open && exit 0; sleep 0.25; done
exit 1
"""


async def start_proxy_fallback(
    session: BaseSandboxSession,
    *,
    port: int,
    upstream: str | None = None,
) -> bool:
    """Replace a Caido that never got a project with a pass-through proxy.

    Caido rejects every proxied request until a project is selected, so after a
    failed bootstrap the sandbox would have no network. The pass-through listens
    on Caido's port, so running shells keep their proxy settings. With
    ``upstream`` (``host:port``) it only relays to that proxy and never dials a
    destination itself.
    """
    if upstream is None:
        # mitmdump tunnels ignored hosts, so TLS is not intercepted. ncat's own
        # HTTP proxy rejects plain-HTTP methods other than GET, HEAD and POST, and
        # listens on every interface, so it needs --allow.
        proxy = (
            "if command -v mitmdump >/dev/null; then"
            f" set -- mitmdump -q --listen-host 127.0.0.1 -p {port} --ignore-hosts '.*';"
            f" else set -- ncat -l 127.0.0.1 {port} -k --proxy-type http --allow 127.0.0.1; fi"
        )
    elif _UPSTREAM_RE.fullmatch(upstream):
        host, _, upstream_port = upstream.rpartition(":")
        relay = shlex.quote(f"ncat {host} {upstream_port}")
        proxy = f"set -- ncat -l 127.0.0.1 {port} -k --sh-exec {relay}"
    else:
        raise ValueError(f"Invalid proxy upstream: {upstream!r}")

    result = await session.exec(
        "bash", "-c", _FALLBACK_SCRIPT.format(port=port, proxy=proxy), timeout=60
    )
    return bool(result.ok())
