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

When a call fails the supervisor rebuilds and reconnects the session once (reusing
the same config, so the same bearer token, never re-fetching credentials) and
re-runs the one failed call once. If that still fails, the connection is marked
dead: every later call returns the standard failed-tool output.

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
from typing import TYPE_CHECKING, Any, cast


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

    def _mark_dead(self) -> None:
        """Flip the connection to dead and fire ``on_dead`` once on the transition."""
        if self._dead:
            return
        self._dead = True
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
        """List the connection's tools, reconnecting once if the session died.

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
        """Run one tool call, reconnecting once and retrying once on session death.

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
        except Exception:
            logger.exception("Skipping MCP connection %r", self._name)
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
                if not self._healed_without_progress:
                    logger.warning(
                        "MCP connection %r session died while idle; reconnecting once",
                        self._name,
                    )
                    if await self._reconnect():
                        logger.info(
                            "MCP connection %r reconnected after an idle death", self._name
                        )
                        self._healed_without_progress = True
                        continue
                else:
                    logger.warning(
                        "MCP connection %r died again before serving a call; "
                        "marking it unavailable",
                        self._name,
                    )
                self._mark_dead()
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

    # -- run one job with reconnect-once + retry-once -------------------------

    async def _execute(self, job: Job) -> _Outcome:
        """Run one job; on a session failure reconnect once and retry it once."""
        if self._dead or self._server is None:
            return _Outcome(dead=True)
        try:
            return _Outcome(value=await job(self._server))
        except asyncio.CancelledError:
            # For a supervised session a cancellation here is the transport scope
            # dying under an in-flight call: a session death, not a real cancel
            # (shutdown never cancels the task, it uses the sentinel). For an
            # adopted session there is no such scope, so a cancel is real.
            if not self._supervised or self._closing:
                raise
            logger.warning(
                "MCP connection %r was cancelled mid-call (session died); reconnecting once",
                self._name,
            )
        except Exception:  # noqa: BLE001 - any call failure is treated as a session death
            logger.warning(
                "MCP connection %r failed mid-call; reconnecting once", self._name
            )

        if not await self._reconnect():
            self._mark_dead()
            return _Outcome(dead=True)

        try:
            return _Outcome(value=await job(self._server))
        except asyncio.CancelledError:
            if not self._supervised or self._closing:
                raise
            logger.warning(
                "MCP connection %r was cancelled again after reconnect; marking it unavailable",
                self._name,
            )
            self._mark_dead()
            return _Outcome(dead=True)
        except Exception:  # noqa: BLE001 - any retry failure means the connection is dead
            logger.warning(
                "MCP connection %r failed again after reconnect; marking it unavailable",
                self._name,
            )
            self._mark_dead()
            return _Outcome(dead=True)

    async def _reconnect(self) -> bool:
        """Rebuild and reconnect the session once, reusing the stored config/token."""
        await self._safe_cleanup()
        if self._config is None:
            return False
        try:
            self._server = await self._open()
        except asyncio.CancelledError:
            if self._closing:
                raise
            logger.warning("MCP reconnect for %r was cancelled; giving up", self._name)
            self._server = None
            return False
        except Exception:
            logger.exception("MCP reconnect for %r failed", self._name)
            self._server = None
            return False
        logger.info("MCP connection %r reconnected", self._name)
        return True

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
        return (
            f"MCP connection {self._name!r} is unavailable: its live session could "
            "not be reached and a reconnect attempt failed. It is marked unavailable "
            "for the rest of this run."
        )
