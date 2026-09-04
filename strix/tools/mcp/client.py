"""Connect to MCP servers so a run can reach their tools on demand.

Given one :class:`McpConnectionConfig` per server, :func:`connect_mcp_servers`
connects each server, counts the tools it offers (honoring the connection's
allowlist), and returns the live sessions. It does NOT register anything as an
agent tool: under the generic-dispatch model the run holds these sessions in a
per-run :class:`~strix.tools.mcp.registry.McpRegistry`, and the agent reaches
them through the two dispatch tools (``describe_mcp`` / ``call_mcp``), which call
:func:`dispatch_mcp_call` here to run one tool and serialize its result.

A server that cannot connect is logged and skipped, so one bad connection never
fails the run.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple, cast

from agents.mcp import (
    MCPServer,
    MCPServerStdio,
    MCPServerStdioParams,
    MCPServerStreamableHttp,
    MCPServerStreamableHttpParams,
    create_static_tool_filter,
)
from mcp.client.stdio import stdio_client
from mcp.shared._httpx_utils import create_mcp_http_client

from strix.tools.mcp.failures import HttpStatusRecorder
from strix.tools.mcp.session import McpConnectionUnavailableError, SupervisedMcpSession


if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx

    from strix.tools.mcp.config import McpConnectionConfig
    from strix.tools.mcp.registry import McpConnectionRequest, McpRegistry

    # Runs on one tool call's structured result before it reaches the agent.
    # Called ``result_transform(label, structured_result)`` and its return value
    # becomes the tool's output. ``label`` is the model-facing
    # ``<connection>_<tool>`` name so a transform keyed on names still resolves
    # the same way it did under per-tool registration; ``structured_result`` is
    # the parsed ``CallToolResult`` as a dict (not a serialized string), so the
    # transform can project or drop individual fields.
    ResultTransform = Callable[[str, Any], Any]


logger = logging.getLogger(__name__)


class ConnectedMcpServer(NamedTuple):
    """One successfully connected MCP connection and how many tools it offers.

    ``session`` is the :class:`~strix.tools.mcp.session.SupervisedMcpSession` that
    owns the live connection on its own task, so the caller cleans it up when the
    run ends (``await session.aclose()``) and hands it to the run's
    :class:`~strix.tools.mcp.registry.McpRegistry`; ``name`` and ``tool_count``
    let the caller show the user a startup summary and fill the prompt inventory;
    ``notes`` carries the connection's optional free-text description so the
    caller can surface it as the connection's purpose in the inventory.
    """

    session: SupervisedMcpSession
    name: str
    tool_count: int
    notes: str | None = None


class BuiltMcpServer(NamedTuple):
    """A constructed SDK server and its optional HTTP failure recorder."""

    server: MCPServer
    recorder: HttpStatusRecorder | None


def _auth_headers(config: McpConnectionConfig) -> dict[str, str]:
    """Build the per-server request headers from the connection's auth."""
    auth = config.auth
    if auth is None:
        return {}
    return {"Authorization": f"Bearer {auth.token}"}


@contextlib.asynccontextmanager
async def _quiet_stdio_streams(params: Any) -> Any:
    """Run a stdio MCP server with its stderr sent to the void.

    A stdio MCP server chats on stderr as it boots (the filesystem server, for
    one, prints ``Allowed directories: [ ... ]``). The mcp library forwards that
    stderr to the parent's ``sys.stderr`` by default, which is the terminal the
    TUI is drawing on, so the banner corrupts the display. Pointing ``errlog`` at
    ``os.devnull`` drops that chatter. Connection failures are unaffected: they
    still raise from ``connect`` and are logged by :func:`connect_mcp_servers`.
    """
    with Path(os.devnull).open("w", encoding="utf-8") as errlog:
        async with stdio_client(params, errlog=errlog) as streams:
            yield streams


class _QuietMCPServerStdio(MCPServerStdio):
    """``MCPServerStdio`` whose subprocess stderr is kept off the terminal.

    The SDK's ``create_streams`` calls ``stdio_client(self.params)`` with no
    ``errlog``, so the subprocess stderr defaults to ``sys.stderr`` and paints
    server banners over the running TUI. Overriding it lets us redirect that
    stream; everything else about the stdio transport is unchanged.
    """

    def create_streams(self) -> Any:
        return _quiet_stdio_streams(self.params)


def _build_server(config: McpConnectionConfig) -> BuiltMcpServer:
    """Construct (but do not connect) the SDK server for one connection.

    The returned tuple carries the server and, for HTTP connections, a recorder
    that retains sanitized response metadata for the owning session.

    When ``allowed_tools`` is a list the static filter means the server will not
    even list tools outside it, so it is the authoritative gate on what
    ``describe_mcp`` and ``call_mcp`` can see. When it is ``None`` no filter is
    applied and every listed tool is reachable.
    """
    tool_filter = (
        create_static_tool_filter(allowed_tool_names=config.allowed_tools)
        if config.allowed_tools is not None
        else None
    )

    if config.transport == "stdio":
        stdio_params: MCPServerStdioParams = {
            "command": cast("str", config.command),
            "args": config.args,
            "env": config.env,
        }
        return BuiltMcpServer(
            _QuietMCPServerStdio(
                params=stdio_params,
                name=config.name,
                tool_filter=tool_filter,
                cache_tools_list=True,
            ),
            None,
        )

    recorder = HttpStatusRecorder()

    def httpx_client_factory(
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
    ) -> httpx.AsyncClient:
        client = create_mcp_http_client(headers=headers, timeout=timeout, auth=auth)
        client.event_hooks.setdefault("response", []).append(recorder)
        return client

    http_params: MCPServerStreamableHttpParams = {
        "url": cast("str", config.url),
        "headers": _auth_headers(config),
        "timeout": config.http_timeout_seconds,
        "sse_read_timeout": config.sse_read_timeout_seconds,
        "httpx_client_factory": httpx_client_factory,
    }
    return BuiltMcpServer(
        MCPServerStreamableHttp(
            params=http_params,
            name=config.name,
            tool_filter=tool_filter,
            cache_tools_list=True,
            client_session_timeout_seconds=config.session_timeout_seconds,
        ),
        recorder,
    )


def _mcp_result_to_tool_output(server: MCPServer, result: Any) -> Any:
    """Serialize a ``CallToolResult`` to a tool output, mirroring the agents SDK.

    This reproduces the serialization in ``agents.mcp.util.MCPUtil.invoke_mcp_tool``
    (structured-content JSON when the server asks for it, otherwise text/image
    content blocks, unwrapping a single block). Because the dispatch tool routes
    its own call, this is what makes the agent see byte-identical content to what
    the SDK would have produced building the tool itself.
    """
    if getattr(server, "use_structured_content", False) and result.structuredContent:
        return json.dumps(result.structuredContent)

    outputs: list[dict[str, Any]] = []
    for item in result.content:
        if item.type == "text":
            outputs.append({"type": "text", "text": item.text})
        elif item.type == "image":
            outputs.append(
                {"type": "image", "image_url": f"data:{item.mimeType};base64,{item.data}"}
            )
        else:
            outputs.append({"type": "text", "text": str(item.model_dump(mode="json"))})
    if len(outputs) == 1:
        return outputs[0]
    return outputs


async def dispatch_mcp_call(
    server: MCPServer,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    label: str,
    result_transform: ResultTransform | None = None,
) -> Any:
    """Run one MCP tool call and convert its result to a tool output.

    Shared single dispatch point for the generic ``call_mcp`` tool. Calls
    ``server.call_tool`` with the tool's unprefixed name, then:

    - with a ``result_transform`` (strix-pro's sanitizer), hands the parsed
      :class:`CallToolResult` to it as ``result_transform(label, structured)`` and
      returns whatever the transform returns; or
    - without one, serializes the result the way the agents SDK does (see
      :func:`_mcp_result_to_tool_output`) and, when the result is an MCP error,
      normalizes it through :func:`_errored_tool_output` so the failure reaches
      the interfaces (see that function for the representation and why it does not
      corrupt the content the agent receives).
    """
    result = await server.call_tool(tool_name, arguments)
    if result_transform is not None:
        return result_transform(label, result.model_dump(mode="json"))
    tool_output = _mcp_result_to_tool_output(server, result)
    if getattr(result, "isError", False):
        return _errored_tool_output(tool_output)
    return tool_output


def _errored_tool_output(tool_output: Any) -> dict[str, Any]:
    """Tag a serialized MCP error so the interfaces render it as failed.

    Both the TUI and the run viewer decide a tool call failed by reading a
    ``success`` key off a top-level dict in the result (``success is False`` means
    failed). :func:`_mcp_result_to_tool_output` returns a dict only for a single
    content block; a structured-content result comes back as a string and a
    multi-block result as a list, and on those the failure flag had nowhere to
    ride, so the interfaces showed a failed call as done. This normalizes every
    errored result to a top-level dict carrying ``success: False``:

    - a single content block (already a dict) keeps its ``type``/``text`` and gains
      ``success: False`` alongside. The SDK's ToolOutput projection keeps the known
      ``type``/``text`` fields and drops ``success`` before the agent sees it, so
      the agent still receives exactly the error content;
    - a list (multiple blocks) or a string (structured content) is placed under a
      stable ``content`` key so the flag has a top-level dict to ride on. The agent
      still receives the full error content, under ``content``, rather than losing
      it.
    """
    if isinstance(tool_output, dict):
        return {**tool_output, "success": False}
    return {"success": False, "content": tool_output}


async def _count_session_tools(config: McpConnectionConfig, session: SupervisedMcpSession) -> int:
    """Count a connected session's reachable tools for the startup summary.

    ``allowed_tools`` of ``None`` counts every listed tool; a list counts only
    those names. The count matches what ``describe_mcp`` will show, because the
    static tool filter built in :func:`_build_server` restricts the server's own
    ``list_tools`` to the same allowlist. The listing goes through the session's
    owning task like every other call.
    """
    allowed = config.allowed_tools
    mcp_tools = await session.list_tools()
    return sum(1 for mcp_tool in mcp_tools if allowed is None or mcp_tool.name in allowed)


async def connect_mcp_servers(
    configs: list[McpConnectionConfig],
) -> list[ConnectedMcpServer]:
    """Connect each MCP config on its own supervising task and return the sessions.

    Each connection becomes a :class:`~strix.tools.mcp.session.SupervisedMcpSession`
    that owns ``connect()``, the held-open session, and ``cleanup()`` on one
    dedicated task, so a later background failure in one session is contained to
    that task and never cancels the run. Returns one :class:`ConnectedMcpServer`
    per session that connected, carrying the session (the caller closes it with
    ``await session.aclose()`` when the run ends and hands it to the run's
    registry) plus the connection name, tool count, and notes. A connection whose
    initial connect fails is skipped rather than raised (fail-open).

    If this coroutine is itself cancelled mid-attach (the run going down), every
    session started so far is closed on its own task before the cancellation is
    re-raised, so nothing is orphaned.

    Nothing is registered as an agent tool: the caller builds a per-run
    :class:`~strix.tools.mcp.registry.McpRegistry` from these sessions, and the
    agent reaches each tool on demand through ``describe_mcp`` / ``call_mcp``.
    """
    connected: list[ConnectedMcpServer] = []
    sessions: list[SupervisedMcpSession] = []
    try:
        for config in configs:
            session = SupervisedMcpSession(config)
            sessions.append(session)
            if not await session.start():
                # Initial connect failed; already logged inside the session. Drop it.
                await session.aclose()
                sessions.remove(session)
                continue
            try:
                tool_count = await _count_session_tools(config, session)
            except McpConnectionUnavailableError:
                # The session died between connecting and its first listing; skip it.
                logger.warning("MCP connection %r died before its first listing", config.name)
                await session.aclose()
                sessions.remove(session)
                continue
            logger.info("Connected MCP server %r (%d tools)", config.name, tool_count)
            connected.append(
                ConnectedMcpServer(
                    session=session, name=config.name, tool_count=tool_count, notes=config.notes
                )
            )
    except BaseException:
        # Cancelled or errored mid-attach: close every session started so far,
        # each on its own task, then re-raise. The runner only receives the list
        # on a clean return, so on an abnormal exit this function owns the cleanup.
        for session in sessions:
            with contextlib.suppress(BaseException):
                await session.aclose()
        raise

    return connected


async def attach_mcp_requests(
    requests: list[McpConnectionRequest],
    registry: McpRegistry,
) -> list[ConnectedMcpServer]:
    """Connect a caller's MCP requests and populate the run's registry.

    The one shared attach-and-populate path both the command-line and the
    SaaS/pro product go through, so all connecting and cleanup lives in one owner.
    The caller supplies inert :class:`McpConnectionRequest` objects (a config plus
    a provider label, an optional per-connection ``result_transform``, and an
    optional ``purpose``) and never a live session: the engine connects each
    config here, reusing :func:`connect_mcp_servers` so the fail-open behavior (a
    connection that will not connect is logged and skipped) and the cancellation
    cleanup are preserved unchanged.

    For each connection that came up, this registers it under its config name with
    its tool count, its ``provider`` label, its ``result_transform``, and a purpose
    of ``request.purpose`` when set else the connection's notes. Returns the
    connected servers (the runner records them and cleans them up when the run
    ends).
    """
    request_by_name = {request.config.name: request for request in requests}
    connections = await connect_mcp_servers([request.config for request in requests])
    for connection in connections:
        request = request_by_name[connection.name]
        registry.add(
            name=connection.name,
            session=connection.session,
            tool_count=connection.tool_count,
            purpose=request.purpose or connection.notes,
            provider=request.provider,
            result_transform=request.result_transform,
        )
    return connections
