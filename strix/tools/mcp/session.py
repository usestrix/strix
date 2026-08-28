"""Own each MCP connection's live session on its own supervising task.

The bug this fixes: the streamable-HTTP transport (the ``mcp`` SDK) opens an
internal anyio task group when ``server.connect()`` runs, and that task group's
cancel scope is entered on whatever task called ``connect()`` and stays open for
the session's whole life. In the old code that task was the run's main task, the
one the agent loop runs on. So when a provider returned an HTTP error on one of
the transport's background tasks (for example a ``403`` on a background POST),
the task group cancelled its scope, the cancellation
propagated to the main task, and the whole scan died with a bare
``CancelledError`` (mislabeled as a user interrupt). Teardown then raised
"Attempted to exit cancel scope in a different task than it was entered in"
because cleanup ran on a different task than connect.

The fix, mirroring how child agents run on their own ``asyncio.create_task``
(see :func:`strix.core.execution.spawn_child_agent`): give each connection its
own dedicated supervising task that owns ``connect()``, the session's held-open
lifetime, and ``cleanup()``. Three consequences:

- **Containment.** The transport's cancel scope is now entered on the supervising
  task, so a background failure cancels only that task. The run and every other
  connection keep going.
- **Co-located teardown.** ``connect()`` and ``cleanup()`` run on the same task,
  so the "exit cancel scope in a different task" error cannot happen.
- **A value, not a cancellation, reaches the caller.** The agent never touches the
  live session directly. It hands a call to the supervising task over a queue and
  awaits the result as a value; if the session task dies, the caller gets a
  "connection unavailable" value instead of a cancellation propagating into the
  agent loop.

When a call fails the supervisor classifies it, retries boundedly, and temporarily
quarantines transient failures before lazily reviving the session. Authentication
failures and repeated transient exhaustion permanently retire a connection.

Security: the connection's :class:`~strix.tools.mcp.config.McpConnectionConfig`
holds a live bearer credential and is kept here in memory only, on the same
in-process object that already holds the live session. It is never logged,
serialized into the run's event stream, or written to disk; :meth:`__repr__`
omits it and the token field's own ``repr`` is already suppressed.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import secrets
import time
from typing import TYPE_CHECKING, Any, cast

from strix.tools.mcp.failures import FailureInfo, HttpStatusRecorder, classify


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from agents.mcp import MCPServer
    from mcp.types import Tool as MCPTool

    from strix.tools.mcp.client import ResultTransform
    from strix.tools.mcp.config import McpConnectionConfig

    # One operation to run against the live session, e.g. ``list_tools`` or a tool
    # call. Runs on the supervising task (supervised sessions) or inline (adopted
    # sessions), and its return value becomes the caller's result.
    Job = Callable[[MCPServer], Awaitable[Any]]


logger = logging.getLogger(__name__)

# How long a graceful (sentinel) shutdown waits for the serve loop to drain
# before the supervising task is cancelled instead. Bounds teardown so a slow or
# hung in-flight call cannot stall it forever.
_SHUTDOWN_TIMEOUT = 10.0
_MAX_ATTEMPTS = 3
_SETTLE_DELAY = 0.05
_SEMAPHORES: dict[str, asyncio.Semaphore] = {}
_JITTER = secrets.SystemRandom()


def _retry_delay(attempt: int, retry_after: float | None) -> float:
    if retry_after is not None:
        return retry_after
    base = min(8.0, 0.5 * (2 ** (attempt - 1)))
    return base + _JITTER.uniform(0.0, base * 0.1)  # type: ignore[no-any-return]


class McpConnectionUnavailableError(RuntimeError):
    """A dead MCP connection could not be reached and did not come back.

    Raised by :meth:`SupervisedMcpSession.list_tools` when the connection is dead
    so the read-only dispatch tools (``describe_mcp``) can report it cleanly.
    :meth:`SupervisedMcpSession.dispatch` does not raise it: a call to a dead
    connection returns the standard failed-tool output instead.
    """


@dataclasses.dataclass
class _Outcome:
    """What running one job resolved to: a value, or the connection being dead."""

    value: Any = None
    dead: bool = False


@dataclasses.dataclass
class _Request:
    """One job handed to the supervising task, with the future its result lands in."""

    job: Job
    future: asyncio.Future[_Outcome]


class SupervisedMcpSession:
    """One MCP connection whose live session is owned by a dedicated task.

    Built two ways:

    - :meth:`__init__` + :meth:`start` for a *supervised* session: the engine owns
      connecting. ``start`` spawns the supervising task, which builds and connects
      the server on itself and then serves calls handed to it over a queue. This is
      the path that contains a background session failure to one task.
    - :meth:`adopt` for an *adopted* session: the caller already holds a connected
      server (strix-pro's cloud sessions, and the test fakes). There is no
      supervising task; calls run inline against the given server. Reconnect works
      only when a config was supplied.

    Public async API used by the dispatch tools: :meth:`list_tools` and
    :meth:`dispatch`. Lifecycle: :meth:`start`, :meth:`aclose`. Read-only:
    :attr:`name`, :attr:`server`, :attr:`config`, :attr:`is_dead`.
    """

    def __init__(self, config: McpConnectionConfig) -> None:
        self._name = config.name
        self._config: McpConnectionConfig | None = config
        self._server: MCPServer | None = None
        self._supervised = True
        self._task: asyncio.Task[None] | None = None
        self._queue: asyncio.Queue[_Request | None] | None = None
        self._ready: asyncio.Future[bool] | None = None
        self._pending: set[asyncio.Future[_Outcome]] = set()
        self._dead = False
        self._closing = False
        self._on_dead: Callable[[], None] | None = None
        self._recorder: HttpStatusRecorder | None = None
        self._unavailable_until: float | None = None
        self._quarantine_count = 0
        self._last_failure = FailureInfo("unknown", reason="connection unavailable")
        self._reconnect_lock = asyncio.Lock()
        self._call_semaphore = _SEMAPHORES.setdefault(
            self._name, asyncio.Semaphore(config.max_concurrent_calls)
        )
        # Guards the idle-death self-heal against a flapping server: set after an
        # idle reconnect, cleared once a real call runs. If the session dies idle
        # again before serving anything, we give up instead of reconnecting in a
        # tight loop.
        self._healed_without_progress = False

    @classmethod
    def adopt(
        cls,
        server: MCPServer,
        *,
        name: str,
        config: McpConnectionConfig | None = None,
    ) -> SupervisedMcpSession:
        """Wrap an already-connected server without a supervising task.

        Calls run inline against ``server`` on the caller's task, matching the old
        direct-dispatch behavior. Reconnect is available only when ``config`` is
        given; otherwise a failed call marks the connection dead.
        """
        self = cls.__new__(cls)
        self._name = name
        self._config = config
        self._server = server
        self._supervised = False
        self._task = None
        self._queue = None
        self._ready = None
        self._pending = set()
        self._dead = False
        self._closing = False
        self._on_dead = None
        self._recorder = None
        self._unavailable_until = None
        self._quarantine_count = 0
        self._last_failure = FailureInfo("unknown", reason="connection unavailable")
        self._reconnect_lock = asyncio.Lock()
        self._call_semaphore = _SEMAPHORES.setdefault(
            name, asyncio.Semaphore(config.max_concurrent_calls if config else 4)
        )
        self._healed_without_progress = False
        return self

    # -- read-only accessors --------------------------------------------------

    @property
    def name(self) -> str:
        return self._name

    @property
    def server(self) -> MCPServer | None:
        """The current live server, or ``None`` once dead. Swapped on reconnect."""
        return self._server

    @property
    def config(self) -> McpConnectionConfig | None:
        """The connection config kept for reconnect. Carries the bearer token, so
        never log or serialize this."""
        return self._config

    @property
    def is_dead(self) -> bool:
        return self._dead

    @property
    def is_unavailable(self) -> bool:
        """Whether the connection is temporarily quarantined."""
        return (
            not self._dead
            and self._unavailable_until is not None
            and time.monotonic() < self._unavailable_until
        )

    def set_on_dead(self, callback: Callable[[], None] | None) -> None:
        """Register a one-shot callback fired when the connection transitions to dead.

        The callback runs on whatever task marks the connection dead (the
        supervising task for a supervised session, the caller's task for an
        adopted one), so it must not block. It fires at most once, on the
        healthy->dead edge, and never for a connection that only ever shut down
        cleanly. The interfaces use it to push a live "offline" status without
        polling. Exceptions from the callback are swallowed (logged) so a status
        push can never take down the session task.
        """
        self._on_dead = callback

    def _mark_dead(self, failure: FailureInfo | None = None, *, attempt: int = 1) -> None:
        """Flip the connection to dead and fire ``on_dead`` once on the transition."""
        if self._dead:
            return
        failure = failure or self._last_failure
        self._dead = True
        self._unavailable_until = None
        logger.error(
            "MCP connection %r permanently unavailable kind=%s status=%s reason=%s "
            "attempt=%d delay=0",
            self._name,
            failure.kind,
            failure.status,
            failure.reason,
            attempt,
        )
        callback = self._on_dead
        if callback is None:
            return
        try:
            callback()
        except Exception:
            logger.exception("MCP on_dead callback for %r failed", self._name)

    def __repr__(self) -> str:
        # Deliberately omits the config so the bearer token can never reach a log
        # line through an accidental repr of this object.
        return f"SupervisedMcpSession(name={self._name!r}, dead={self._dead})"

    # -- lifecycle ------------------------------------------------------------

    async def start(self) -> bool:
        """Spawn the supervising task, connect on it, and wait until it is ready.

        Returns ``True`` when the session connected, ``False`` when the initial
        connect failed (the caller then skips this connection, fail-open). Only
        valid for a supervised session.
        """
        loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue()
        self._ready = loop.create_future()
        self._task = asyncio.create_task(self._supervise(), name=f"mcp-session-{self._name}")
        return await self._ready

    async def aclose(self) -> None:
        """Shut the connection down and clean up its session on its owning task.

        For a connected supervised session this signals the supervising task with a
        sentinel so ``cleanup()`` runs on the same task that ran ``connect()``,
        giving an orderly shutdown the supervisor tells apart from a session death.
        Teardown is always bounded: if the serve loop cannot drain the sentinel in
        time (a slow or hung in-flight call), or the session never finished
        connecting (including a connect cancelled mid-await), the task is cancelled
        instead. ``_closing`` is set first, so the supervisor treats that
        cancellation as shutdown and still cleans up on its own task.
        """
        self._closing = True
        if self._supervised and self._task is not None:
            if not self._task.done():
                # A cancelled readiness future (the connect was cancelled mid-await)
                # counts as "not connected": never call ``.result()`` on it, which
                # would raise here and skip the cleanup below.
                connected = (
                    self._ready is not None
                    and self._ready.done()
                    and not self._ready.cancelled()
                    and self._ready.result()
                )
                if connected and self._queue is not None:
                    # Reached the serve loop: a sentinel gives a clean, cancel-free
                    # teardown, with cleanup() running on the supervising task. Bound
                    # it, though: a hung in-flight call would otherwise leave the
                    # sentinel queued behind it forever, so cancel the task if the
                    # drain does not finish in time (wait_for cancels it on timeout).
                    with contextlib.suppress(Exception):
                        await self._queue.put(None)
                    with contextlib.suppress(
                        asyncio.TimeoutError, asyncio.CancelledError, Exception
                    ):
                        await asyncio.wait_for(self._task, _SHUTDOWN_TIMEOUT)
                else:
                    # Still stuck in connect(), never connected, or connect
                    # cancelled: cancel to unstick it.
                    self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
        else:
            await self._safe_cleanup()
        self._fail_pending()

    # -- caller-facing operations --------------------------------------------

    async def list_tools(self) -> list[MCPTool]:
        """List the connection's tools, retrying transient session failures.

        Raises :class:`McpConnectionUnavailableError` when the connection is dead.
        """
        outcome = await self._run_job(lambda server: server.list_tools())
        if outcome.dead:
            raise McpConnectionUnavailableError(self._unavailable_message())
        return cast("list[MCPTool]", outcome.value)

    async def dispatch(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        label: str,
        result_transform: ResultTransform | None = None,
    ) -> Any:
        """Run one tool call with bounded retries for transient session failures.

        Returns the tool output on success, or the standard failed-tool output
        (``success: False``) with a "connection unavailable" message when the
        connection is dead.
        """
        from strix.tools.mcp.client import dispatch_mcp_call

        async def job(server: MCPServer) -> Any:
            return await dispatch_mcp_call(
                server,
                tool_name,
                arguments,
                label=label,
                result_transform=result_transform,
            )

        outcome = await self._run_job(job)
        if outcome.dead:
            from strix.tools.mcp.client import _errored_tool_output

            return _errored_tool_output(self._unavailable_message())
        return outcome.value

    # -- job routing ----------------------------------------------------------

    async def _run_job(self, job: Job) -> _Outcome:
        """Route one job to the owning task (supervised) or run it inline (adopted)."""
        if self._supervised:
            return await self._submit(job)
        return await self._execute(job)

    async def _submit(self, job: Job) -> _Outcome:
        """Hand a job to the supervising task and await its result as a value."""
        if self._dead or self._closing or self._task is None or self._task.done():
            return _Outcome(dead=True)
        loop = asyncio.get_running_loop()
        future: asyncio.Future[_Outcome] = loop.create_future()
        self._pending.add(future)
        if self._queue is None:
            self._pending.discard(future)
            return _Outcome(dead=True)
        await self._queue.put(_Request(job=job, future=future))
        # The task may have ended between the guard above and the put; ``_fail_pending``
        # would then never see this future, so resolve it here.
        if self._task.done() and not future.done():
            self._pending.discard(future)
            return _Outcome(dead=True)
        return await future

    # -- the supervising task -------------------------------------------------

    async def _supervise(self) -> None:
        """Own the session for its whole life on one task: connect, serve, clean up."""
        try:
            self._server = await self._open()
        except asyncio.CancelledError:
            # The connect was cancelled (the run is going down, or the transport
            # scope cancelled mid-connect). Report not-ready so the attach path
            # treats it as a skipped connection; do not propagate.
            self._report_ready(value=False)
            await self._safe_cleanup()
            self._fail_pending()
            return
        except BaseException as exc:  # noqa: BLE001 - classify cancellation groups
            failure = classify(exc)
            logger.warning(
                "Skipping MCP connection %r kind=%s status=%s attempt=1 delay=0",
                self._name,
                failure.kind,
                failure.status,
            )
            self._report_ready(value=False)
            await self._safe_cleanup()
            self._fail_pending()
            return

        self._report_ready(value=True)
        try:
            await self._serve_loop()
        finally:
            await self._safe_cleanup()
            self._fail_pending()

    async def _serve_loop(self) -> None:
        assert self._queue is not None
        while True:
            try:
                request = await self._queue.get()
            except asyncio.CancelledError:
                # A cancellation while idle is the transport's task group cancelling
                # this supervising task because a background session task failed.
                # Contained here. If we are closing, this is an ordinary shutdown,
                # so let it propagate. Otherwise try to self-heal once: reconnect a
                # fresh session and keep serving. The flag stops a flapping server
                # (one that dies again before serving any call) from reconnecting in
                # a tight loop; there we give up and mark the connection dead. Later
                # calls then short-circuit to the dead output without this task.
                if self._closing:
                    raise
                failure = self._recorder.take() if self._recorder is not None else None
                failure = failure or FailureInfo("transport", reason="session cancelled")
                self._last_failure = failure
                if not self._healed_without_progress:
                    logger.warning(
                        "MCP connection %r session died while idle kind=%s status=%s "
                        "attempt=1 delay=0; reconnecting",
                        self._name,
                        failure.kind,
                        failure.status,
                    )
                    self._healed_without_progress = True
                    reconnected, reconnect_failure = await self._reconnect()
                    if reconnected:
                        logger.info(
                            "MCP connection %r revived kind=%s status=%s attempt=1 delay=%.2f",
                            self._name,
                            failure.kind,
                            failure.status,
                            _SETTLE_DELAY,
                        )
                        continue
                    if reconnect_failure is not None:
                        failure = reconnect_failure
                else:
                    logger.warning(
                        "MCP connection %r died again before serving a call; "
                        "marking it permanently unavailable kind=%s status=%s "
                        "attempt=1 delay=0",
                        self._name,
                        failure.kind,
                        failure.status,
                    )
                self._mark_dead(failure)
                await self._safe_cleanup()
                return
            if request is None:  # shutdown sentinel
                return
            outcome = await self._execute(request.job)
            # A served call is real progress: clear the idle-heal guard so a future
            # idle death is again allowed one reconnect.
            self._healed_without_progress = False
            if not request.future.done():
                request.future.set_result(outcome)
            self._pending.discard(request.future)
            if self._dead:
                return

    # -- run one job with bounded classified retries --------------------------

    async def _execute(self, job: Job) -> _Outcome:  # noqa: PLR0911, PLR0912
        """Run one job with classified retries and temporary quarantine."""
        if self._dead:
            return _Outcome(dead=True)
        if self._unavailable_until is not None:
            remaining = self._unavailable_until - time.monotonic()
            if remaining > 0:
                return _Outcome(dead=True)
            self._unavailable_until = None
            logger.info(
                "MCP connection %r revive started kind=%s status=%s attempt=1 delay=%.2f",
                self._name,
                self._last_failure.kind,
                self._last_failure.status,
                remaining,
            )

        failure: FailureInfo | None = None
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            if self._server is None:
                reconnected, reconnect_failure = await self._reconnect()
                if not reconnected:
                    failure = reconnect_failure or FailureInfo(
                        "transport", reason="reconnect failed"
                    )
                    self._last_failure = failure
                    if failure.kind == "auth":
                        self._mark_dead(failure, attempt=attempt)
                        return _Outcome(dead=True)
                    if attempt == _MAX_ATTEMPTS:
                        self._quarantine(failure, attempt=attempt)
                        return _Outcome(dead=True)
                    delay = _retry_delay(attempt, failure.retry_after)
                    self._log_retry(failure, attempt, delay)
                    await asyncio.sleep(delay)
                    continue
            assert self._server is not None
            try:
                async with self._call_semaphore:
                    return _Outcome(value=await self._run_job_call(job))
            except asyncio.CancelledError:
                if not self._supervised or self._closing:
                    raise
                failure = (
                    self._recorder.take() if self._recorder is not None else None
                ) or FailureInfo("transport", reason="session cancelled")
            except BaseException as exc:  # noqa: BLE001 - classify SDK groups
                failure = classify(exc)
                if failure.kind == "unknown" and self._recorder is not None:
                    failure = self._recorder.take() or failure

            self._last_failure = failure
            if failure.kind == "auth":
                self._mark_dead(failure, attempt=attempt)
                return _Outcome(dead=True)
            if attempt == _MAX_ATTEMPTS:
                self._quarantine(failure, attempt=attempt)
                return _Outcome(dead=True)
            delay = _retry_delay(attempt, failure.retry_after)
            self._log_retry(failure, attempt, delay)
            await asyncio.sleep(delay)
            reconnected, reconnect_failure = await self._reconnect()
            if not reconnected and reconnect_failure is not None:
                self._mark_dead(reconnect_failure, attempt=attempt)
                return _Outcome(dead=True)
        return _Outcome(dead=True)

    async def _run_job_call(self, job: Job) -> Any:
        return await job(self._server)  # type: ignore[arg-type]

    def _log_retry(self, failure: FailureInfo, attempt: int, delay: float) -> None:
        logger.warning(
            "MCP connection %r retryable failure kind=%s status=%s attempt=%d delay=%.2f",
            self._name,
            failure.kind,
            failure.status,
            attempt,
            delay,
        )

    def _quarantine(self, failure: FailureInfo, *, attempt: int) -> None:
        self._quarantine_count += 1
        if self._quarantine_count >= 3:
            self._mark_dead(failure, attempt=attempt)
            return
        cooldown = 30.0 * (2 ** (self._quarantine_count - 1))
        self._unavailable_until = time.monotonic() + cooldown
        logger.warning(
            "MCP connection %r quarantined kind=%s status=%s attempt=%d delay=%.2f",
            self._name,
            failure.kind,
            failure.status,
            attempt,
            cooldown,
        )

    async def _reconnect(self) -> tuple[bool, FailureInfo | None]:
        """Rebuild and reconnect, reusing the stored config and settling briefly."""
        async with self._reconnect_lock:
            await self._safe_cleanup()
            if self._config is None:
                return False, FailureInfo("transport", reason="no reconnect config")
            try:
                server = await self._open()
            except asyncio.CancelledError:
                if self._closing:
                    raise
                self._server = None
                return False, FailureInfo("transport", reason="reconnect cancelled")
            except BaseException as exc:  # noqa: BLE001 - classify SDK groups
                self._server = None
                failure = classify(exc)
                if failure.kind == "unknown" and self._recorder is not None:
                    failure = self._recorder.take() or failure
                return False, failure
            # connect() is the only readiness surface exposed by the SDK.
            self._server = server
            try:
                await asyncio.sleep(_SETTLE_DELAY)
            except asyncio.CancelledError:
                self._server = None
                with contextlib.suppress(BaseException):
                    await server.cleanup()  # type: ignore[no-untyped-call]
                if self._closing:
                    raise
                return False, FailureInfo("transport", reason="reconnect cancelled")
            return True, None

    async def _open(self) -> MCPServer:
        """Build and connect the SDK server, reusing the existing setup steps.

        If ``connect()`` fails, the just-built server is cleaned up here on this
        same task before the error propagates, so a failed connect never orphans
        an MCP subprocess or half-open HTTP session.
        """
        from strix.tools.mcp.client import _build_server

        if self._config is None:
            raise RuntimeError(f"MCP connection {self._name!r} has no config to connect")
        server = _build_server(self._config)
        self._recorder = getattr(server, "_strix_http_status_recorder", None)
        try:
            await server.connect()  # type: ignore[no-untyped-call]
        except BaseException:
            with contextlib.suppress(Exception):
                await server.cleanup()  # type: ignore[no-untyped-call]
            raise
        return server

    # -- helpers --------------------------------------------------------------

    async def _safe_cleanup(self) -> None:
        server = self._server
        self._server = None
        if server is None:
            return
        with contextlib.suppress(Exception):
            await server.cleanup()  # type: ignore[no-untyped-call]

    def _report_ready(self, value: bool) -> None:
        if self._ready is not None and not self._ready.done():
            self._ready.set_result(value)

    def _fail_pending(self) -> None:
        for future in self._pending:
            if not future.done():
                future.set_result(_Outcome(dead=True))
        self._pending.clear()

    def _unavailable_message(self) -> str:
        if self._unavailable_until is not None:
            remaining = max(0.0, self._unavailable_until - time.monotonic())
            return (
                f"MCP connection {self._name!r} is temporarily unavailable "
                f"(kind={self._last_failure.kind}, status={self._last_failure.status}); "
                f"retrying in about {remaining:.0f} seconds."
            )
        return (
            f"MCP connection {self._name!r} is unavailable "
            f"(kind={self._last_failure.kind}, status={self._last_failure.status}); "
            "it will not be retried."
        )
