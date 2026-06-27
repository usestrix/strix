"""Run a bundled subscription proxy app on a loopback port in a daemon thread."""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

import uvicorn


if TYPE_CHECKING:
    from typing import Any


class ProxyStartupError(RuntimeError):
    """Raised when the subscription proxy cannot bind or become ready."""


class SubscriptionProxy:
    """A uvicorn server hosting a subscription proxy app on ``127.0.0.1``.

    The server runs in a daemon thread so it survives Strix's separate
    ``asyncio.run()`` phases and never blocks interpreter exit.
    """

    def __init__(self, app: Any, *, host: str = "127.0.0.1") -> None:
        self._host = host
        self._port: int | None = None
        config = uvicorn.Config(
            app,
            host=host,
            port=0,
            log_level="warning",
            access_log=False,
            loop="asyncio",
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(
            target=self._server.run,
            name="strix-subscription-proxy",
            daemon=True,
        )

    @property
    def base_url(self) -> str:
        """Loopback base URL (with the ``/v1`` suffix) once the proxy is running."""
        return f"http://{self._host}:{self._require_port()}/v1"

    def start(self, *, timeout: float = 15.0) -> None:
        """Launch the proxy thread and block until it is bound and ready."""
        self._thread.start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._server.started and self._server.servers:
                self._port = self._read_bound_port()
                return
            if not self._thread.is_alive():
                raise ProxyStartupError("subscription proxy thread exited during startup")
            time.sleep(0.05)
        self.stop()
        raise ProxyStartupError(f"subscription proxy was not ready within {timeout:.0f}s")

    def stop(self, *, timeout: float = 5.0) -> None:
        """Signal the server to exit and join its thread."""
        self._server.should_exit = True
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _require_port(self) -> int:
        if self._port is None:
            raise ProxyStartupError("subscription proxy port requested before start()")
        return self._port

    def _read_bound_port(self) -> int:
        sock = self._server.servers[0].sockets[0]
        return int(sock.getsockname()[1])
