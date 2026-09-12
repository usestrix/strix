"""Launch, authenticate, and supervise the Go TUI sidecar process."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import os
import secrets
import socket
import subprocess
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any


_WINDOWS_AUTH_TIMEOUT = 10.0
_PROCESS_EXIT_TIMEOUT = 5.0
_SENSITIVE_ENV_SUFFIXES = ("_API_KEY", "_ACCESS_KEY")
_SENSITIVE_ENV_PARTS = frozenset(
    {"CREDENTIAL", "CREDENTIALS", "PASSWORD", "SECRET", "SECRETS", "TOKEN", "TOKENS"}
)
_SENSITIVE_ENV_NAMES = {
    "AWS_ACCESS_KEY_ID",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "LLM_API_KEY",
    "STRIX_TUI_ADDR",
    "STRIX_TUI_FD",
    "STRIX_TUI_TOKEN",
}


def tui_executable() -> str:
    return "strix-tui.exe" if os.name == "nt" else "strix-tui"


def project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def tui_source_dir() -> Path:
    return Path(__file__).resolve().parent


def child_environment() -> dict[str, str]:
    """Copy only non-secret process state needed by the terminal sidecar."""
    child: dict[str, str] = {}
    for key, value in os.environ.items():
        normalized = key.upper()
        if normalized in _SENSITIVE_ENV_NAMES:
            continue
        if normalized.endswith(_SENSITIVE_ENV_SUFFIXES):
            continue
        if set(normalized.split("_")) & _SENSITIVE_ENV_PARTS:
            continue
        child[key] = value
    return child


def _recv_exactly(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise ConnectionError("TUI IPC peer closed during authentication")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _authenticate_connection(
    connection: socket.socket,
    address: tuple[Any, ...],
    expected_token: str,
) -> None:
    if address[0] not in {"127.0.0.1", "::1"}:
        raise ConnectionError("TUI IPC connection did not originate from loopback")
    connection.settimeout(_WINDOWS_AUTH_TIMEOUT)
    supplied = _recv_exactly(connection, len(expected_token)).decode("ascii")
    if not hmac.compare_digest(supplied, expected_token):
        raise PermissionError("TUI IPC authentication failed")
    connection.settimeout(None)


def _accept_authenticated_connection(
    listener: socket.socket,
    expected_token: str,
) -> socket.socket:
    """Accept and authenticate the one Windows loopback connection."""
    listener.settimeout(_WINDOWS_AUTH_TIMEOUT)
    connection, address = listener.accept()
    try:
        _authenticate_connection(connection, address, expected_token)
    except BaseException:
        connection.close()
        raise
    return connection


async def wait_process(
    process: asyncio.subprocess.Process | subprocess.Popen[bytes],
) -> int:
    if isinstance(process, asyncio.subprocess.Process):
        return await process.wait()
    return await asyncio.to_thread(process.wait)


async def terminate_process(
    process: asyncio.subprocess.Process | subprocess.Popen[bytes] | None,
) -> None:
    if process is None or process.returncode is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        process.terminate()
    wait_task = asyncio.create_task(wait_process(process))
    try:
        await asyncio.wait_for(asyncio.shield(wait_task), _PROCESS_EXIT_TIMEOUT)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await asyncio.wait_for(asyncio.shield(wait_task), _PROCESS_EXIT_TIMEOUT)


async def launch_tui_process(
    command: list[str],
    env: dict[str, str],
    cwd: str | None,
) -> tuple[asyncio.subprocess.Process | subprocess.Popen[bytes], socket.socket]:
    if os.name == "nt":
        return await _launch_windows_tui_process(command, env, cwd)
    return await _launch_posix_tui_process(command, env, cwd)


async def _launch_posix_tui_process(
    command: list[str],
    env: dict[str, str],
    cwd: str | None,
) -> tuple[asyncio.subprocess.Process, socket.socket]:
    backend_socket, child_socket = socket.socketpair()
    try:
        env["STRIX_TUI_FD"] = str(child_socket.fileno())
        process = await asyncio.create_subprocess_exec(
            *command, env=env, cwd=cwd, pass_fds=(child_socket.fileno(),)
        )
    except BaseException:
        backend_socket.close()
        raise
    finally:
        child_socket.close()
    return process, backend_socket


async def _launch_windows_tui_process(
    command: list[str],
    env: dict[str, str],
    cwd: str | None,
) -> tuple[subprocess.Popen[bytes], socket.socket]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    windows_process: subprocess.Popen[bytes] | None = None
    connection: socket.socket | None = None
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        token = secrets.token_hex(32)
        host, port = listener.getsockname()[:2]
        env.update({"STRIX_TUI_ADDR": f"{host}:{port}", "STRIX_TUI_TOKEN": token})
        windows_process = subprocess.Popen(command, env=env, cwd=cwd)  # noqa: S603
        connection = await asyncio.to_thread(_accept_authenticated_connection, listener, token)
    except BaseException:
        await terminate_process(windows_process)
        raise
    finally:
        listener.close()
    assert windows_process is not None and connection is not None
    return windows_process, connection


def check_return_code(return_code: int) -> None:
    if return_code != 0:
        raise RuntimeError(f"Bubble Tea TUI exited with status {return_code}")


def package_version() -> str:
    """Report the installed package version for the Go splash/stats
    ("dev" when metadata is unavailable)."""
    try:
        return version("strix-agent")
    except PackageNotFoundError:
        return "dev"
