"""``strix mcp-server`` — expose Strix's tools over the MCP stdio transport.

Lets an MCP client (Claude Code, Cursor, Zed, ...) call Strix's existing tools
directly. The client supplies the model and the orchestration loop, so this
mode needs neither ``STRIX_LLM`` nor ``LLM_API_KEY``. Strix contributes the
sandbox container, the proxy, the skill packs, and the reporting tools.

This is additive: ``strix --target ...`` still runs the native agent graph
against a configured LLM, unchanged.

Strix's orchestration and bookkeeping tools (agent graph, ``finish_scan``,
``wait_for_user``, notes, todos, ``think``) are intentionally not exposed — the
MCP client brings its own planning, memory, and control flow.

stdio transport owns stdout, so all logging here goes to stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import sys
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

# ExecCommandTool / WriteStdinTool are not re-exported from the capabilities
# package, so they are imported from their defining module. Strix pins the
# agents SDK to >=0.19,<0.20 (see pyproject), so this internal path is stable
# for the supported SDK range.
from agents.sandbox.capabilities.shell import (  # type: ignore[attr-defined]
    ExecCommandTool,
    WriteStdinTool,
)
from agents.tool_context import ToolContext
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent
from mcp.types import Tool as MCPTool

from strix.config import load_settings
from strix.core.paths import run_dir_for, runtime_state_dir
from strix.interface.cli_args import get_version
from strix.interface.utils import derive_local_base_name
from strix.report.state import (
    ReportState,
    get_global_report_state,
    set_global_report_state,
)
from strix.runtime import session_manager
from strix.tools.coverage.tools import (
    hydrate_coverage_from_disk,
    list_coverage,
    record_coverage,
    update_coverage,
)
from strix.tools.load_skill.tool import load_skill
from strix.tools.proxy.tools import (
    list_requests,
    list_sitemap,
    repeat_request,
    scope_rules,
    view_request,
    view_sitemap_entry,
)
from strix.tools.reporting.tool import (
    create_dependency_report,
    create_vulnerability_report,
    delete_vulnerability_report,
    get_report,
    list_reports,
    update_vulnerability_report,
)
from strix.tools.threat_model.tools import (
    amend_threat_model,
    get_threat_model,
    hydrate_threat_models_from_disk,
    save_threat_model,
)
from strix.tools.web_search.tool import web_get_contents, web_search


if TYPE_CHECKING:
    from agents.tool import FunctionTool


logger = logging.getLogger(__name__)

SERVER_NAME = "strix"
_CALL_ID_PREFIX = "mcp"

# Cap on a single tool result sent to the client; larger output is trimmed to a
# preview and the full text is spilled to the run directory (see ``_invoke``).
_MAX_RESULT_CHARS = 50_000

# Subdirectory under the run dir where oversized results are spilled, and the
# name of the exposed tool that reads them back.
_SPILL_SUBDIR = "mcp_outputs"
_READ_OUTPUT_TOOL = "read_tool_output"

_INSTRUCTIONS = (
    "Strix tools over MCP. Shell tools (exec_command, write_stdin) run inside "
    "an isolated Strix sandbox container that is started on first use. Proxy "
    "tools expose the HTTP history captured by the sandbox's built-in proxy. "
    "Reporting tools record CVSS-scored findings. load_skill loads Strix's "
    "internal knowledge packs. Only operate against targets you are authorized "
    "to test."
)


def _host_tools() -> list[FunctionTool]:
    """Host-side tools that need no live sandbox session.

    These read their run state from a plain ``ctx.context`` dict and degrade
    gracefully when optional keys (coordinator, caido client) are absent, so
    they are safe to expose with the minimal context this server builds.
    """
    return [
        load_skill,
        web_search,
        web_get_contents,
        list_requests,
        view_request,
        repeat_request,
        list_sitemap,
        view_sitemap_entry,
        scope_rules,
        create_vulnerability_report,
        update_vulnerability_report,
        delete_vulnerability_report,
        create_dependency_report,
        get_report,
        list_reports,
        get_threat_model,
        save_threat_model,
        amend_threat_model,
        list_coverage,
        record_coverage,
        update_coverage,
    ]


# Sandbox tools run commands inside the container. Their input schemas are
# static, so they can be advertised without a live session; only execution
# needs one. apply_patch is a CustomTool (a different invoke contract) and
# view_image returns image bytes that don't fit an MCP text result, so neither
# is exposed here — the shell covers file edits and inspection inside the box.
def _sandbox_tool_specs() -> list[FunctionTool]:
    """Unbound sandbox tools, built only to read their name and schema."""
    return [
        ExecCommandTool(session=None),  # type: ignore[arg-type]  # schema-only, never invoked
        WriteStdinTool(session=None),  # type: ignore[arg-type]  # schema-only, never invoked
    ]


SANDBOX_TOOL_NAMES = frozenset(t.name for t in _sandbox_tool_specs())

# Proxy tools read their Caido client from the live sandbox session; the host
# branch must bring the sandbox up before invoking one, or they report the
# proxy as unavailable until an unrelated shell call happens to start it.
PROXY_TOOL_NAMES = frozenset(
    t.name
    for t in (
        list_requests,
        view_request,
        repeat_request,
        list_sitemap,
        view_sitemap_entry,
        scope_rules,
    )
)


def _init_run_state(run_name: str) -> Path:
    """Wire up host-side run state so the reporting, threat-model, and coverage
    tools persist to a run directory and survive a server restart, mirroring the
    native CLI. Without it they return success but keep nothing on disk, and
    ``list_reports`` stays empty.

    ``run_name`` is stable across restarts (it is not the ephemeral sandbox id),
    so relaunching the server with the same name resumes the same run directory
    and its reports, coverage, and threat models. Returns that run directory.
    """
    run_dir = run_dir_for(run_name)
    run_dir.mkdir(parents=True, exist_ok=True)
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)

    report_state = ReportState(run_name)
    report_state.hydrate_from_run_dir()
    set_global_report_state(report_state)

    hydrate_coverage_from_disk(state_dir)
    hydrate_threat_models_from_disk(state_dir)
    logger.info("Run state ready at %s", run_dir)
    return run_dir


def _build_local_sources(target_paths: list[str]) -> list[dict[str, Any]]:
    """Turn host repo paths into Strix ``local_sources`` mount entries.

    Each path is mounted **read-only** at ``/workspace/<name>`` inside the
    sandbox. Review needs to read the repository, not change it, and a
    read-only bind stops a shell tool from modifying or deleting files in the
    host working tree.
    """
    sources: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in target_paths:
        resolved = Path(raw).expanduser()
        if not resolved.is_dir():
            raise ValueError(f"--target-path is not a directory: {raw}")
        # De-duplicate: two repos whose final path component matches would
        # otherwise share one /workspace/<name> mount and shadow each other.
        base = derive_local_base_name(str(resolved))
        subdir = base
        suffix = 1
        while subdir in seen:
            suffix += 1
            subdir = f"{base}-{suffix}"
        seen.add(subdir)
        sources.append(
            {
                "source_path": str(resolved),
                "workspace_subdir": subdir,
                "read_only": True,
            }
        )
    return sources


class _SandboxTools:
    """Lazily brings up one Strix sandbox session and binds the shell tools to
    it. The session is created on the first call that needs it and reused for
    the life of the server; ``aclose`` tears it down."""

    def __init__(
        self, local_sources: list[dict[str, Any]] | None = None, scan_id: str | None = None
    ) -> None:
        self._scan_id = scan_id or uuid.uuid4().hex[:8]
        self._local_sources = local_sources or []
        self._bundle: dict[str, Any] | None = None
        self._tools: dict[str, FunctionTool] | None = None
        self._lock = asyncio.Lock()

    @property
    def workspace_paths(self) -> list[str]:
        """The ``/workspace/<name>`` paths of the mounted repos, if any."""
        return [f"/workspace/{s['workspace_subdir']}" for s in self._local_sources]

    async def ensure(self) -> dict[str, FunctionTool]:
        async with self._lock:
            if self._tools is not None:
                return self._tools
            self._tools = await self._bring_up()
            return self._tools

    async def _bring_up(self) -> dict[str, FunctionTool]:
        settings = load_settings()
        logger.info("Starting Strix sandbox session %s", self._scan_id)
        self._bundle = await session_manager.create_or_reuse(
            self._scan_id,
            image=settings.runtime.image,
            local_sources=self._local_sources,
            status_sink=lambda phase: logger.info("sandbox: %s", phase),
        )
        session = self._bundle["session"]

        tools: list[FunctionTool] = [ExecCommandTool(session=session)]
        if session.supports_pty():
            tools.append(WriteStdinTool(session=session))
        logger.info("Sandbox ready; bound %d sandbox tool(s)", len(tools))
        return {t.name: t for t in tools}

    def caido_client(self) -> Any:
        return self._bundle["caido_client"] if self._bundle else None

    async def aclose(self) -> None:
        if self._bundle is None:
            return
        with contextlib.suppress(Exception):
            await session_manager.cleanup(self._scan_id)
        logger.info("Sandbox session %s cleaned up", self._scan_id)


def _run_context(sandbox: _SandboxTools) -> dict[str, Any]:
    """The minimal ``ctx.context`` dict Strix tools read from.

    Only the keys the exposed tools actually consult are populated; the rest of
    Strix's run context (coordinator, agent graph) is absent and the tools fall
    back to their no-coordinator paths.
    """
    return {
        "caido_client": sandbox.caido_client(),
        "agent_id": SERVER_NAME,
        "parent_id": None,
        "interactive": False,
        "scan_targets": sandbox.workspace_paths,
    }


def _spill_large_output(tool_name: str, text: str) -> str | None:
    """Persist an oversized tool result under the run directory and return the
    id (file name) the client passes to ``read_tool_output`` to read it back."""
    report_state = get_global_report_state()
    if report_state is None:
        return None
    safe_tool = "".join(c if c.isalnum() or c in "-_" else "_" for c in tool_name)
    output_id = f"{safe_tool}-{uuid.uuid4().hex[:8]}.txt"
    try:
        out_dir = report_state.get_run_dir() / _SPILL_SUBDIR
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / output_id).write_text(text, encoding="utf-8")
    except OSError:
        return None
    return output_id


def _read_spilled_output(output_id: str, offset: int, length: int) -> str:
    """Read a previously spilled tool result back in bounded chunks.

    Exposed as the ``read_tool_output`` MCP tool so a client limited to this
    server's tools can still retrieve output that ``_invoke`` truncated. The id
    must be a bare file name within the run's spill directory — no path parts.
    """
    if "/" in output_id or "\\" in output_id or ".." in output_id or not output_id.endswith(".txt"):
        return f"Invalid output id: {output_id!r}"
    report_state = get_global_report_state()
    if report_state is None:
        return "No run state is active, so there is no saved output to read."
    path = report_state.get_run_dir() / _SPILL_SUBDIR / output_id
    if not path.is_file():
        return f"No saved output named {output_id!r}."
    offset = max(offset, 0)
    length = length if length > 0 else _MAX_RESULT_CHARS
    data = path.read_text(encoding="utf-8", errors="replace")
    chunk = data[offset : offset + length]
    end = offset + len(chunk)
    return f"{chunk}\n\n[chars {offset}-{end} of {len(data)}; more available: {end < len(data)}]"


async def _invoke(tool: FunctionTool, arguments: dict[str, Any], sandbox: _SandboxTools) -> str:
    """Call a Strix FunctionTool and return its result as text.

    A result larger than ``_MAX_RESULT_CHARS`` is trimmed to a bounded preview
    so it cannot flood the client's context; the full text is written to the run
    directory and the preview points the client at it.
    """
    ctx: ToolContext[Any] = ToolContext(
        context=_run_context(sandbox),
        tool_name=tool.name,
        tool_call_id=f"{_CALL_ID_PREFIX}_{uuid.uuid4().hex[:12]}",
        tool_arguments=json.dumps(arguments),
    )
    result = await tool.on_invoke_tool(ctx, json.dumps(arguments))
    text = result if isinstance(result, str) else json.dumps(result, default=str)
    if len(text) <= _MAX_RESULT_CHARS:
        return text
    output_id = _spill_large_output(tool.name, text)
    how = (
        f"; call {_READ_OUTPUT_TOOL} with output_id={output_id!r} to read the rest"
        if output_id
        else ""
    )
    preview = text[:_MAX_RESULT_CHARS]
    return f"{preview}\n\n[truncated to {_MAX_RESULT_CHARS} of {len(text)} chars{how}]"


def _server_instructions(sandbox: _SandboxTools) -> str:
    if not sandbox.workspace_paths:
        return _INSTRUCTIONS
    mounted = ", ".join(sandbox.workspace_paths)
    return (
        f"{_INSTRUCTIONS} The target repository is mounted in the sandbox at: "
        f"{mounted}. Run the shell tools there for white-box review."
    )


def _build_server(sandbox: _SandboxTools) -> Any:
    server: Any = Server(
        SERVER_NAME, version=get_version(), instructions=_server_instructions(sandbox)
    )

    host_tools = {t.name: t for t in _host_tools()}

    def _as_mcp_tool(tool: FunctionTool) -> MCPTool:
        return MCPTool(
            name=tool.name,
            description=(tool.description or "").strip() or tool.name,
            inputSchema=tool.params_json_schema or {"type": "object", "properties": {}},
        )

    read_output_tool = MCPTool(
        name=_READ_OUTPUT_TOOL,
        description=(
            "Read back a tool result that was truncated, using the output_id "
            "from the truncation notice. Returns a bounded chunk; page with "
            "offset and length."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "output_id": {"type": "string", "description": "Id from the truncation notice."},
                "offset": {"type": "integer", "minimum": 0, "default": 0},
                "length": {"type": "integer", "minimum": 1, "default": _MAX_RESULT_CHARS},
            },
            "required": ["output_id"],
        },
    )

    @server.list_tools()  # type: ignore[untyped-decorator]  # mcp SDK decorators are untyped
    async def list_tools() -> list[MCPTool]:
        # Sandbox tools are advertised from their static schemas, so listing
        # never starts the container; the session is created on first call.
        host = [_as_mcp_tool(t) for t in host_tools.values()]
        return [*host, read_output_tool, *(_as_mcp_tool(t) for t in _sandbox_tool_specs())]

    @server.call_tool()  # type: ignore[untyped-decorator]  # mcp SDK decorators are untyped
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        tool: FunctionTool | None
        if name == _READ_OUTPUT_TOOL:
            args = arguments or {}
            text = _read_spilled_output(
                str(args.get("output_id", "")),
                int(args.get("offset", 0) or 0),
                int(args.get("length", _MAX_RESULT_CHARS) or _MAX_RESULT_CHARS),
            )
            return [TextContent(type="text", text=text)]
        if name in host_tools:
            tool = host_tools[name]
            # Proxy tools need the live session's Caido client; start it first.
            if name in PROXY_TOOL_NAMES:
                await sandbox.ensure()
        elif name in SANDBOX_TOOL_NAMES:
            tool = (await sandbox.ensure()).get(name)
            if tool is None:
                # Advertised, but this session doesn't provide it (e.g. no PTY).
                raise ValueError(f"tool not available in this sandbox session: {name}")
        else:
            raise ValueError(f"unknown tool: {name}")
        text = await _invoke(tool, arguments or {}, sandbox)
        return [TextContent(type="text", text=text)]

    return server


async def _serve(local_sources: list[dict[str, Any]], run_name: str) -> None:
    # Run state is keyed by the stable run_name so restarts resume it; the
    # sandbox container is ephemeral and keeps its own random id.
    _init_run_state(run_name)
    sandbox = _SandboxTools(local_sources=local_sources)
    server = _build_server(sandbox)
    init_options = server.create_initialization_options()
    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, init_options)
    finally:
        await sandbox.aclose()


def _configure_logging(*, verbose: bool) -> None:
    """Raise Strix's log level for this command and send logs to stderr.

    ``main`` already called ``setup_console_logging``, which attaches a quiet
    stderr handler (ERROR, with an INFO/DEBUG filter for the TUI) to the
    ``strix`` logger and sets ``propagate=False`` — so ``logging.basicConfig`` on
    the root would never change what this command prints. There is no TUI in
    server mode, so replace that handler with one that actually emits at the
    requested level. stdout carries the MCP protocol, so logs must use stderr.
    """
    level = logging.DEBUG if verbose else logging.INFO
    strix_logger = logging.getLogger("strix")
    strix_logger.setLevel(level)
    for handler in list(strix_logger.handlers):
        if isinstance(handler, logging.StreamHandler) and not isinstance(
            handler, logging.FileHandler
        ):
            strix_logger.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    strix_logger.addHandler(handler)
    strix_logger.propagate = False


def run_mcp_server(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="strix mcp-server",
        description="Serve Strix's tools to an MCP client over stdio.",
    )
    parser.add_argument(
        "-t",
        "--target-path",
        dest="target_paths",
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "Mount a local repository into the sandbox at /workspace/<name> so "
            "the shell tools can review its code. Repeatable."
        ),
    )
    parser.add_argument(
        "--run-name",
        dest="run_name",
        default=None,
        metavar="NAME",
        help=(
            "Run name for persisted reports, coverage, and threat models under "
            "strix_runs/<name>. Pass the same name to resume that run; reusing "
            "it also shares that run's files, so give concurrent servers "
            "distinct names. Defaults to a unique name per launch."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Log at DEBUG level to stderr.",
    )
    args = parser.parse_args(argv)

    _configure_logging(verbose=args.verbose)

    try:
        local_sources = _build_local_sources(args.target_paths)
    except ValueError as exc:
        parser.error(str(exc))

    # A unique default keeps two servers launched from the same directory from
    # sharing one run and overwriting each other's reports; pass --run-name to
    # deliberately resume or share a run.
    run_name = args.run_name or f"mcp-{uuid.uuid4().hex[:8]}"

    try:
        asyncio.run(_serve(local_sources, run_name))
    except KeyboardInterrupt:
        return 0
    return 0
