"""File-based Human-in-the-Loop input manager.

Instead of relying on ``input()`` or Caido proxy copy-paste (which breaks
for large outputs), the agent writes a *request* file into a shared inbox
directory and the operator drops a *response* file.  The agent polls for
the response and returns its contents once available.

Directory layout::

    <inbox>/
        req_<task_id>.txt   -- written by agent (prompt / instructions)
        resp_<task_id>.txt  -- written by operator (tool output / answer)
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path


logger = logging.getLogger(__name__)

# Prefix constants for request and response filenames.
_REQ_PREFIX = "req_"
_RESP_PREFIX = "resp_"
_FILE_SUFFIX = ".txt"

# Default polling interval in seconds.
_DEFAULT_POLL_INTERVAL = 2

# Default timeout in seconds (5 minutes).
_DEFAULT_TIMEOUT = 300


class HILTimeoutError(TimeoutError):
    """Raised when the operator does not respond within the timeout window."""


def get_inbox_path() -> Path:
    """Return the resolved inbox directory path.

    The path is determined by (in order of precedence):
    1. The ``HIL_INBOX_PATH`` environment variable.
    2. The ``strix/hil/inbox`` directory relative to the package root.

    The directory is created (``mkdir -p``) if it does not yet exist.
    """
    env_path = os.getenv("HIL_INBOX_PATH")
    inbox = Path(env_path) if env_path else Path(__file__).resolve().parent / "inbox"

    inbox.mkdir(parents=True, exist_ok=True)
    return inbox


def request_input(task_id: str, prompt: str, *, inbox: Path | None = None) -> Path:
    """Write a request file that tells the operator what is needed.

    Args:
        task_id: Unique identifier for this request (e.g. a UUID hex string).
        prompt: Human-readable instructions for the operator.
        inbox: Override inbox directory (defaults to :func:`get_inbox_path`).

    Returns:
        The :class:`~pathlib.Path` of the created request file.
    """
    inbox_dir = inbox or get_inbox_path()
    req_file = inbox_dir / f"{_REQ_PREFIX}{task_id}{_FILE_SUFFIX}"
    req_file.write_text(prompt, encoding="utf-8")
    logger.info("[HIL] Request written: %s", req_file)
    logger.info("[HIL] Drop answer as: %s/%s%s%s", inbox_dir, _RESP_PREFIX, task_id, _FILE_SUFFIX)
    return req_file


def wait_for_response(
    task_id: str,
    *,
    timeout: int = _DEFAULT_TIMEOUT,
    poll_interval: int = _DEFAULT_POLL_INTERVAL,
    inbox: Path | None = None,
    cleanup: bool = True,
) -> str:
    """Block until the operator drops a response file, then return its contents.

    Args:
        task_id: The same identifier used in :func:`request_input`.
        timeout: Maximum seconds to wait before raising :class:`HILTimeoutError`.
        poll_interval: Seconds between filesystem polls.
        inbox: Override inbox directory (defaults to :func:`get_inbox_path`).
        cleanup: If ``True``, delete both the request and response files
            after a successful read.

    Returns:
        The full text content of the response file.

    Raises:
        HILTimeoutError: If the response file is not found within *timeout*.
    """
    inbox_dir = inbox or get_inbox_path()
    resp_file = inbox_dir / f"{_RESP_PREFIX}{task_id}{_FILE_SUFFIX}"
    req_file = inbox_dir / f"{_REQ_PREFIX}{task_id}{_FILE_SUFFIX}"

    elapsed = 0
    while elapsed < timeout:
        if resp_file.exists():
            data = resp_file.read_text(encoding="utf-8")
            logger.info("[HIL] Response received for task %s (%d bytes)", task_id, len(data))
            if cleanup:
                resp_file.unlink(missing_ok=True)
                req_file.unlink(missing_ok=True)
            return data
        time.sleep(poll_interval)
        elapsed += poll_interval

    msg = f"No response for task {task_id} within {timeout}s"
    logger.warning("[HIL] %s", msg)
    raise HILTimeoutError(msg)


def list_pending_requests(*, inbox: Path | None = None) -> list[dict[str, str]]:
    """Return a list of pending (unanswered) request files in the inbox.

    Each entry is a dict with keys ``task_id`` and ``prompt``.
    """
    inbox_dir = inbox or get_inbox_path()
    pending: list[dict[str, str]] = []
    for req_file in sorted(inbox_dir.glob(f"{_REQ_PREFIX}*{_FILE_SUFFIX}")):
        task_id = req_file.stem.removeprefix(_REQ_PREFIX)
        resp_file = inbox_dir / f"{_RESP_PREFIX}{task_id}{_FILE_SUFFIX}"
        if not resp_file.exists():
            prompt = req_file.read_text(encoding="utf-8")
            pending.append({"task_id": task_id, "prompt": prompt})
    return pending


def clear_inbox(*, inbox: Path | None = None) -> int:
    """Remove all request and response files from the inbox.

    Returns:
        The number of files deleted.
    """
    inbox_dir = inbox or get_inbox_path()
    count = 0
    for pattern in (f"{_REQ_PREFIX}*{_FILE_SUFFIX}", f"{_RESP_PREFIX}*{_FILE_SUFFIX}"):
        for f in inbox_dir.glob(pattern):
            f.unlink(missing_ok=True)
            count += 1
    logger.info("[HIL] Cleared %d file(s) from inbox", count)
    return count


class InputManager:
    """Stateful wrapper around the HIL inbox for a single agent session.

    Provides a convenient interface for agents that need to make multiple
    operator requests during a single run.

    Args:
        inbox: Override inbox directory (defaults to :func:`get_inbox_path`).
        default_timeout: Default timeout in seconds for :meth:`ask`.
    """

    def __init__(
        self,
        *,
        inbox: Path | None = None,
        default_timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        self._inbox = inbox or get_inbox_path()
        self._default_timeout = default_timeout
        self._history: list[dict[str, str]] = []

    @property
    def inbox(self) -> Path:
        """The resolved inbox directory."""
        return self._inbox

    def ask(
        self,
        task_id: str,
        prompt: str,
        *,
        timeout: int | None = None,
        cleanup: bool = True,
    ) -> str:
        """Request input from the operator and wait for the response.

        This is a convenience method that calls :func:`request_input`
        followed by :func:`wait_for_response`.

        Args:
            task_id: Unique identifier for this request.
            prompt: Instructions for the operator.
            timeout: Override timeout (defaults to the instance default).
            cleanup: Delete request/response files after reading.

        Returns:
            The operator's response text.
        """
        request_input(task_id, prompt, inbox=self._inbox)
        response = wait_for_response(
            task_id,
            timeout=timeout or self._default_timeout,
            inbox=self._inbox,
            cleanup=cleanup,
        )
        self._history.append({"task_id": task_id, "prompt": prompt, "response": response})
        return response

    def pending(self) -> list[dict[str, str]]:
        """List pending (unanswered) requests in the inbox."""
        return list_pending_requests(inbox=self._inbox)

    def clear(self) -> int:
        """Clear all files from the inbox."""
        return clear_inbox(inbox=self._inbox)

    @property
    def history(self) -> list[dict[str, str]]:
        """Return the list of completed request/response pairs from this session."""
        return list(self._history)
