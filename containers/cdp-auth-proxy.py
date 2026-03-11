#!/usr/bin/env python3
"""CDP authentication proxy.

Replaces the raw socat forwarder with an auth-aware TCP proxy.  Every
connection (HTTP *and* WebSocket upgrade) must carry a valid token —
either as an ``Authorization: Bearer <token>`` header or a
``?token=<token>`` query parameter.  The latter is needed for WebSocket
clients (e.g. Playwright) that don't support custom headers on the
upgrade request.

Auth credentials are stripped before the request is forwarded to
Chromium so the upstream sees a clean, standard CDP request.

Environment variables:
    TOOL_SERVER_TOKEN   — required, shared secret
    CDP_PORT            — listen port (default 9222)
    CDP_INTERNAL_PORT   — upstream Chromium port (default 19222)
"""

from __future__ import annotations

import asyncio
import os
import re
import sys


TOKEN: str = os.environ["TOOL_SERVER_TOKEN"]
LISTEN_PORT: int = int(os.environ.get("CDP_PORT", "9222"))
UPSTREAM_PORT: int = int(os.environ.get("CDP_INTERNAL_PORT", "19222"))

# Maximum bytes to buffer while looking for the end-of-headers marker.
# Prevents memory exhaustion from slow-loris / oversized-header attacks.
_MAX_HEADER_SIZE: int = 16 * 1024  # 16 KiB — plenty for CDP requests


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _check_auth(header_bytes: bytes) -> bool:
    text = header_bytes.decode("latin-1", errors="replace")

    # 1) Authorization: Bearer <token>
    m = re.search(r"(?i)Authorization:\s*Bearer\s+(\S+)", text)
    if m and m.group(1) == TOKEN:
        return True

    # 2) ?token=<token> or &token=<token> query param
    m = re.search(r"[?&]token=([^&\s]+)", text)
    return bool(m and m.group(1) == TOKEN)


def _sanitize(header_bytes: bytes) -> bytes:
    """Strip auth credentials before forwarding upstream."""
    text = header_bytes.decode("latin-1", errors="replace")

    # Remove Authorization header line
    text = re.sub(r"(?im)^Authorization:[^\r\n]*\r\n", "", text)

    # Remove token query param — handle all positions:
    #   ?token=val&rest  → ?rest       (first of many)
    #   ?token=val       → (nothing)   (sole param)
    #   &token=val       → (nothing)   (not first)
    text = re.sub(r"\?token=[^&\s]+&", "?", text)
    text = re.sub(r"\?token=[^&\s]+", "", text)
    text = re.sub(r"&token=[^&\s]+", "", text)

    return text.encode("latin-1")


_REJECT = (
    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 12\r\nConnection: close\r\n\r\nUnauthorized"
)


# ---------------------------------------------------------------------------
# TCP proxy
# ---------------------------------------------------------------------------


async def _pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Forward bytes until EOF or error."""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except OSError:
            pass


async def _handle(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
) -> None:
    up_writer: asyncio.StreamWriter | None = None
    try:
        # --- Read HTTP headers (up to the blank line) ---
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = await asyncio.wait_for(client_reader.read(8192), timeout=10)
            if not chunk:
                return
            buf += chunk
            if len(buf) > _MAX_HEADER_SIZE:
                client_writer.write(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n"
                )
                await client_writer.drain()
                return

        sep = buf.index(b"\r\n\r\n") + 4
        headers = buf[:sep]
        remainder = buf[sep:]

        # --- Authenticate ---
        if not _check_auth(headers):
            client_writer.write(_REJECT)
            await client_writer.drain()
            return

        # --- Strip credentials & forward ---
        headers = _sanitize(headers)

        up_reader, up_writer = await asyncio.open_connection("127.0.0.1", UPSTREAM_PORT)
        up_writer.write(headers)
        if remainder:
            up_writer.write(remainder)
        await up_writer.drain()

        # --- Bidirectional pipe ---
        done, pending = await asyncio.wait(
            [
                asyncio.create_task(_pipe(client_reader, up_writer)),
                asyncio.create_task(_pipe(up_reader, client_writer)),
            ],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()

    except (ConnectionResetError, BrokenPipeError, OSError, TimeoutError):
        pass
    finally:
        for w in (client_writer, up_writer):
            if w is not None:
                with _suppress_os():
                    w.close()


class _suppress_os:  # noqa: N801
    """Tiny context manager — cheaper than contextlib.suppress(OSError)."""

    def __enter__(self) -> None:
        pass

    def __exit__(self, *exc: object) -> bool:
        return isinstance(exc[1], OSError) if exc[1] is not None else False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def _main() -> None:
    server = await asyncio.start_server(_handle, "0.0.0.0", LISTEN_PORT)  # nosec B104
    print(
        f"CDP auth proxy: 0.0.0.0:{LISTEN_PORT} -> 127.0.0.1:{UPSTREAM_PORT}",
        flush=True,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        sys.exit(0)
