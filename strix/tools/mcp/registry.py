"""Per-run registry of the MCP connections a scan may reach.

Replaces per-tool registration. The old model turned every tool of every
connected MCP server into its own agent tool, so a run with a handful of
connections put dozens of provider tool schemas on the root agent's first LLM
request. Instead, a run holds its live connections here, keyed by the name the
user gave each connection, and every agent reaches them through three generic
dispatch tools: ``list_mcps`` to discover the available connections, ``describe_mcp``
to learn one connection's tool schemas on demand, and ``call_mcp`` to run one of
its tools.

One :class:`McpRegistry` is built per run in :mod:`strix.core.runner`, stored in
the run context under :data:`MCP_REGISTRY_CONTEXT_KEY`, and shared by the root
agent and every child (the child context is a copy of the parent's, so it
carries the same registry object).

strix-pro imports :class:`McpRegistry` to add its cloud connections into the
same registry and to attach a per-connection ``result_transform`` (its
sanitizer), which :func:`strix.tools.mcp.client.dispatch_mcp_call` applies at the
single dispatch point.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import time
from typing import TYPE_CHECKING, Any, Literal, NamedTuple

from strix.tools.mcp.session import McpConnectionUnavailableError, SupervisedMcpSession


if TYPE_CHECKING:
    from collections.abc import Callable

    from agents.mcp import MCPServer

    from strix.tools.mcp.client import ResultTransform
    from strix.tools.mcp.config import McpConnectionConfig


# The run-context key under which the runner stores the per-run registry, and
# the two dispatch tools read it back. Kept here so the tools, the runner, and
# strix-pro all agree on one name.
MCP_REGISTRY_CONTEXT_KEY = "mcp_registry"


# The two connection-scoped dispatch tools an interface attributes to a specific
# MCP connection. ``call_mcp`` runs one tool on a connection; ``describe_mcp``
# lists a connection's tool schemas. (``list_mcps`` is deliberately not here: it
# names no single connection, so it renders as an ordinary tool call.) Kept here
# (not in the interface layer) so the engine, the OSS viewer, and strix-pro's
# tracer all recognise a connection-scoped dispatch call by the same names.
CALL_MCP_TOOL = "call_mcp"
DESCRIBE_MCP_TOOL = "describe_mcp"
SEARCH_MCP_TOOLS_TOOL = "search_mcp_tools"
GET_MCP_TOOL_SCHEMA_TOOL = "get_mcp_tool_schema"
MCP_DISPATCH_TOOLS = frozenset(
    {
        CALL_MCP_TOOL,
        DESCRIBE_MCP_TOOL,
        SEARCH_MCP_TOOLS_TOOL,
        GET_MCP_TOOL_SCHEMA_TOOL,
    }
)

McpConnectionState = Literal[
    "configured",
    "connecting",
    "connected",
    "catalog_loading",
    "catalog_ready",
    "unavailable",
]
_RETRY_DELAY_SECONDS = 5.0


@dataclasses.dataclass
class McpConnectionEntry:
    """One configured MCP connection a scan may reach, keyed by ``name``.

    Registration is inert. The first warm-up, search, schema lookup, or call
    creates one shared connection task; the first catalog operation creates one
    shared listing task. Root and child agents therefore reuse the same session
    and catalog even when they request a cold connection concurrently.
    """

    name: str
    connection_config: McpConnectionConfig | None = dataclasses.field(
        default=None,
        repr=False,
    )
    session: SupervisedMcpSession | None = dataclasses.field(default=None, repr=False)
    purpose: str | None = None
    tool_count: int = 0
    result_transform: ResultTransform | None = None
    provider: str | None = None
    state: McpConnectionState = "configured"
    _catalog: list[Any] | None = dataclasses.field(default=None, repr=False)
    _connect_task: asyncio.Task[SupervisedMcpSession] | None = dataclasses.field(
        default=None,
        repr=False,
    )
    _catalog_task: asyncio.Task[list[Any]] | None = dataclasses.field(
        default=None,
        repr=False,
    )
    _retry_after: float = dataclasses.field(default=0.0, repr=False)
    _status_sink: Callable[[], None] | None = dataclasses.field(default=None, repr=False)

    @property
    def server(self) -> MCPServer | None:
        """The current live server behind the session (swapped on reconnect).

        Kept so existing callers that read ``entry.server`` keep working; new code
        should call through ``entry.session`` so reconnect and containment apply.
        """
        return self.session.server if self.session is not None else None

    @property
    def config(self) -> McpConnectionConfig | None:
        """The reconnect config. Carries the bearer token; never log it."""
        if self.connection_config is not None:
            return self.connection_config
        return self.session.config if self.session is not None else None

    @property
    def active_tools(self) -> frozenset[str]:
        config = self.config
        return frozenset(config.active_tools if config is not None else ())

    def set_status_sink(self, sink: Callable[[], None] | None) -> None:
        self._status_sink = sink
        if self.session is not None:
            self.session.set_on_dead(self._on_dead)

    def _set_state(self, state: McpConnectionState) -> None:
        if self.state == state:
            return
        self.state = state
        if self._status_sink is not None:
            self._status_sink()

    def _on_dead(self) -> None:
        self.session = None
        self._catalog = None
        self._catalog_task = None
        self._retry_after = time.monotonic() + _RETRY_DELAY_SECONDS
        self._set_state("unavailable")

    async def ensure_connected(self) -> SupervisedMcpSession:
        """Return this entry's live session, connecting it once when needed."""
        if self.session is not None:
            return self.session
        if self.connection_config is None:
            raise McpConnectionUnavailableError(
                f"MCP connection {self.name!r} is unavailable and cannot reconnect."
            )
        if self._connect_task is None:
            if self.state == "unavailable" and time.monotonic() < self._retry_after:
                raise McpConnectionUnavailableError(
                    f"MCP connection {self.name!r} is temporarily unavailable."
                )
            self._connect_task = asyncio.create_task(
                self._connect(),
                name=f"mcp-connect-{self.name}",
            )
        task = self._connect_task
        try:
            return await asyncio.shield(task)
        finally:
            if self._connect_task is task and task.done():
                self._connect_task = None

    async def _connect(self) -> SupervisedMcpSession:
        config = self.connection_config
        if config is None:
            raise McpConnectionUnavailableError(
                f"MCP connection {self.name!r} has no connection configuration."
            )
        self._set_state("connecting")
        session = SupervisedMcpSession(config)
        try:
            started = await session.start()
        except BaseException:
            with contextlib.suppress(BaseException):
                await session.aclose()
            self._retry_after = time.monotonic() + _RETRY_DELAY_SECONDS
            self._set_state("unavailable")
            raise
        if not started:
            await session.aclose()
            self._retry_after = time.monotonic() + _RETRY_DELAY_SECONDS
            self._set_state("unavailable")
            raise McpConnectionUnavailableError(f"MCP connection {self.name!r} could not connect.")
        self.session = session
        session.set_on_dead(self._on_dead)
        self._retry_after = 0.0
        self._set_state("connected")
        return session

    async def ensure_catalog(self) -> list[Any]:
        """Return the filtered catalog, listing it once on first use."""
        if (
            self._catalog is not None
            and self.session is not None
            and not self.session.is_dead
            and not self.session.is_unavailable
        ):
            return self._catalog
        if self.session is not None and (self.session.is_dead or self.session.is_unavailable):
            self._catalog = None
        if self._catalog_task is None:
            self._catalog_task = asyncio.create_task(
                self._load_catalog(),
                name=f"mcp-catalog-{self.name}",
            )
        task = self._catalog_task
        try:
            return await asyncio.shield(task)
        finally:
            if self._catalog_task is task and task.done():
                self._catalog_task = None

    async def _load_catalog(self) -> list[Any]:
        session = await self.ensure_connected()
        self._set_state("catalog_loading")
        try:
            catalog = await session.list_tools()
        except BaseException:
            if session.is_dead:
                self._set_state("unavailable")
            else:
                self._set_state("connected")
            raise
        self._catalog = list(catalog)
        self.tool_count = len(self._catalog)
        self._set_state("catalog_ready")
        return self._catalog

    async def close(self) -> None:
        """Cancel pending initialization and close an opened session."""
        tasks = [task for task in (self._catalog_task, self._connect_task) if task is not None]
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(BaseException):
                await task
        self._catalog_task = None
        self._connect_task = None
        if self.session is not None:
            with contextlib.suppress(BaseException):
                await self.session.aclose()
        self.session = None


@dataclasses.dataclass(frozen=True)
class McpConnectionSummary:
    """One connection summary ``list_mcps`` returns: what an agent needs to decide
    whether to ``describe_mcp`` a connection, with no tool schemas."""

    name: str
    purpose: str | None
    tool_count: int
    provider: str | None = None
    state: McpConnectionState = "configured"


@dataclasses.dataclass(frozen=True)
class McpConnectionStatus:
    """One connection's live status for the interfaces (the TUI panel, the app
    strip, and the roster signal the app consumes).

    Non-secret by construction: only the connection ``name``, its ``provider``
    label, its ``tool_count``, and whether its live session is currently ``dead``
    (its reconnect-retry gave up). No config, token, url, or purpose rides here.
    ``dead`` is read live off the connection's session at the moment this is
    built, so a fresh :meth:`McpRegistry.statuses` reflects the current health.
    """

    name: str
    provider: str | None
    tool_count: int
    dead: bool
    state: McpConnectionState


@dataclasses.dataclass(frozen=True)
class McpConnectionRequest:
    """A source-agnostic request to attach one MCP connection to a run.

    The caller hands the engine an inert ``config`` (how to reach the server, its
    name, and any auth token) plus metadata, and never a live session: the engine
    owns connecting and cleaning up. ``provider`` is an optional source label
    (e.g. ``"supabase"``; empty for the command-line path). ``result_transform``
    is an optional per-connection transform run on each call's structured result
    at the single dispatch point (strix-pro's sanitizer; empty for the
    command-line path). ``purpose`` is the human label ``list_mcps`` reports as the
    connection's description; when unset it falls back to ``config.notes``.
    """

    config: McpConnectionConfig
    provider: str | None = None
    result_transform: ResultTransform | None = None
    purpose: str | None = None


class McpCallInfo(NamedTuple):
    """What one MCP dispatch call resolved to: the connection name, the
    underlying tool (empty for ``describe_mcp``), and the connection's provider
    label (``None`` when unknown or untagged)."""

    connection: str
    tool: str
    provider: str | None


class McpRegistry:
    """Connection name -> live MCP connection, built per run and shared by every
    agent in the run.

    Public API (strix-pro builds against it): the constructor, :meth:`add`,
    :meth:`get`, and :meth:`summaries`.
    """

    def __init__(self) -> None:
        self._entries: dict[str, McpConnectionEntry] = {}
        self._status_sink: Callable[[], None] | None = None
        self._warmup_task: asyncio.Task[None] | None = None

    def register(self, request: McpConnectionRequest) -> McpConnectionEntry:
        """Register an inert request without opening a network connection."""
        entry = McpConnectionEntry(
            name=request.config.name,
            connection_config=request.config,
            purpose=request.purpose or request.config.notes,
            result_transform=request.result_transform,
            provider=request.provider,
        )
        entry.set_status_sink(self._status_sink)
        self._entries[entry.name] = entry
        return entry

    def add(
        self,
        *,
        name: str,
        session: SupervisedMcpSession | None = None,
        server: MCPServer | None = None,
        config: McpConnectionConfig | None = None,
        purpose: str | None = None,
        tool_count: int = 0,
        result_transform: ResultTransform | None = None,
        provider: str | None = None,
    ) -> McpConnectionEntry:
        """Register one connection under ``name`` (last write wins).

        Pass ``session`` for a session the engine already supervises (the attach
        path does this). Pass ``server`` for an already-connected server the caller
        owns (strix-pro's cloud sessions): it is adopted into a session that runs
        calls inline against it, and reconnects only when a ``config`` is also
        given. Exactly one of ``session`` or ``server`` is required.
        """
        if session is None:
            if server is None:
                raise ValueError("McpRegistry.add requires either 'session' or 'server'")
            session = SupervisedMcpSession.adopt(server, name=name, config=config)
        entry = McpConnectionEntry(
            name=name,
            connection_config=config or session.config,
            session=session,
            purpose=purpose,
            tool_count=tool_count,
            result_transform=result_transform,
            provider=provider,
            state="connected",
        )
        entry.set_status_sink(self._status_sink)
        self._entries[name] = entry
        return entry

    def get(self, name: str) -> McpConnectionEntry | None:
        """The connection registered under ``name``, or ``None``."""
        return self._entries.get(name)

    def names(self) -> list[str]:
        """The registered connection names, in insertion order."""
        return list(self._entries)

    def summaries(self) -> list[McpConnectionSummary]:
        """One inventory summary per connection, in insertion order."""
        return [
            McpConnectionSummary(
                name=entry.name,
                purpose=entry.purpose,
                tool_count=entry.tool_count,
                provider=entry.provider,
                state=entry.state,
            )
            for entry in self._entries.values()
        ]

    def statuses(self) -> list[McpConnectionStatus]:
        """One live status per connection, in insertion order.

        Reads each connection's ``dead`` flag off its session at call time, so the
        interfaces (the TUI panel via the Python backend projection, and the
        roster signal the app consumes) get the current health each time they
        rebuild. Non-secret: name, provider, tool_count, dead only."""
        return [
            McpConnectionStatus(
                name=entry.name,
                provider=entry.provider,
                tool_count=entry.tool_count,
                dead=entry.state == "unavailable"
                or (entry.session is not None and entry.session.is_dead),
                state=entry.state,
            )
            for entry in self._entries.values()
        ]

    def clear(self) -> None:
        """Drop every connection (the sessions themselves are closed by the
        runner)."""
        self._entries.clear()

    def set_status_sink(self, sink: Callable[[], None] | None) -> None:
        """Receive a callback after any connection lifecycle transition."""
        self._status_sink = sink
        for entry in self._entries.values():
            entry.set_status_sink(sink)

    def start_warmup(self, *, max_concurrency: int = 6) -> asyncio.Task[None]:
        """Connect every configured entry in the background with a fixed bound."""
        if self._warmup_task is not None:
            return self._warmup_task

        async def warm() -> None:
            semaphore = asyncio.Semaphore(max(1, max_concurrency))

            async def connect(entry: McpConnectionEntry) -> None:
                async with semaphore:
                    with contextlib.suppress(McpConnectionUnavailableError):
                        await entry.ensure_connected()

            await asyncio.gather(*(connect(entry) for entry in self._entries.values()))

        self._warmup_task = asyncio.create_task(warm(), name="mcp-warmup")
        return self._warmup_task

    async def close(self) -> None:
        """Stop warm-up and close only sessions this registry opened."""
        if self._warmup_task is not None:
            self._warmup_task.cancel()
            with contextlib.suppress(BaseException):
                await self._warmup_task
            self._warmup_task = None
        await asyncio.gather(
            *(entry.close() for entry in self._entries.values()),
            return_exceptions=True,
        )

    def __len__(self) -> int:
        return len(self._entries)

    def __bool__(self) -> bool:
        return bool(self._entries)


def resolve_mcp_call(
    tool_name: str,
    args: dict[str, Any],
    registry: McpRegistry | None = None,
) -> McpCallInfo | None:
    """Resolve one tool call to the MCP connection/tool/provider it went out to.

    The single resolver both the OSS viewer and strix-pro's tracer read a
    dispatch call through, so a call is attributed the same way everywhere. Every
    MCP call an agent makes goes through ``call_mcp`` or ``describe_mcp``, and the
    connection (and, for ``call_mcp``, the server's own tool name) ride in the
    call's ``args`` rather than the tool name, so they are read from there.

    Returns ``None`` when ``tool_name`` is not one of the two dispatch tools, when
    the call carries no connection name, or when a ``registry`` is supplied and
    has no connection under that name. ``tool`` is the underlying tool for
    ``call_mcp`` and empty for ``describe_mcp`` (which inspects the connection
    itself). ``provider`` comes from the registry entry; it is ``None`` when no
    ``registry`` is supplied (the viewer projects calls without one) or when the
    connection carries no provider label.
    """
    if tool_name not in MCP_DISPATCH_TOOLS:
        return None
    connection = args.get("connection")
    if not isinstance(connection, str) or not connection:
        return None
    provider: str | None = None
    if registry is not None:
        entry = registry.get(connection)
        if entry is None:
            return None
        provider = entry.provider
    raw_tool = args.get("tool") if tool_name in {CALL_MCP_TOOL, GET_MCP_TOOL_SCHEMA_TOOL} else ""
    tool = raw_tool if isinstance(raw_tool, str) else ""
    return McpCallInfo(connection=connection, tool=tool, provider=provider)
