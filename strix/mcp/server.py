"""stdio MCP server for agent-native Strix scans."""

from __future__ import annotations

import os
import logging
from contextlib import asynccontextmanager
from typing import Any

import anyio
import mcp.types as mcp_types
from mcp.server.fastmcp import FastMCP
from mcp.shared.message import SessionMessage

from strix.mcp.service import StrixMCPService
from strix.tools.proxy.tools import (
    list_requests as _list_requests,
    list_sitemap as _list_sitemap,
    repeat_request as _repeat_request,
    scope_rules as _scope_rules,
    view_request as _view_request,
    view_sitemap_entry as _view_sitemap_entry,
)


logging.basicConfig(level=logging.WARNING)
service = StrixMCPService()
mcp = FastMCP(
    "Strix Security",
    instructions=(
        "Authorized application-security testing tools. The connected coding agent performs all "
        "reasoning; this server never invokes a language model. Call start_scan first and "
        "finish_scan last."
    ),
)


@mcp.tool()
async def start_scan(
    targets: list[str],
    scan_mode: str = "deep",
    instruction: str = "",
    run_name: str | None = None,
    mounts: list[str] | None = None,
    resume: bool = False,
    scope_mode: str = "auto",
    diff_base: str | None = None,
    non_interactive: bool = False,
) -> dict[str, Any]:
    """Start or resume an authorized Strix scan and isolated sandbox."""
    return await service.start_scan(
        targets,
        scan_mode=scan_mode,
        instruction=instruction,
        run_name=run_name,
        mounts=mounts,
        resume=resume,
        scope_mode=scope_mode,
        diff_base=diff_base,
        non_interactive=non_interactive,
    )


@mcp.tool()
async def sandbox_exec(argv: list[str], timeout: int = 120) -> dict[str, Any]:
    """Run an argv-form command in the isolated pentesting sandbox.

    The sandbox includes common reconnaissance tools, Python, curl, and the
    agent-browser CLI. Traffic is captured by the integrated Caido proxy.
    """
    return await service.sandbox_exec(argv, timeout)


@mcp.tool()
def list_knowledge() -> dict[str, Any]:
    """List Strix security knowledge modules available to load on demand."""
    return service.list_knowledge()


@mcp.tool()
def load_knowledge(name: str) -> dict[str, Any]:
    """Load one Strix knowledge module, such as vulnerabilities/xss."""
    return service.load_knowledge(name)


@mcp.tool()
async def list_proxy_requests(
    httpql_filter: str | None = None,
    first: int = 50,
    after: str | None = None,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
    scope_id: str | None = None,
) -> dict[str, Any]:
    """List HTTP requests captured from sandbox traffic by Caido."""
    return await service.proxy_call(
        _list_requests,
        {
            "httpql_filter": httpql_filter,
            "first": first,
            "after": after,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "scope_id": scope_id,
        },
    )


@mcp.tool()
async def view_proxy_request(
    request_id: str,
    part: str = "request",
    search_pattern: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    """Read a captured HTTP request or response with optional regex search."""
    return await service.proxy_call(
        _view_request,
        {
            "request_id": request_id,
            "part": part,
            "search_pattern": search_pattern,
            "page": page,
            "page_size": page_size,
        },
    )


@mcp.tool()
async def repeat_proxy_request(
    request_id: str,
    modifications: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replay a captured request with URL, parameter, header, cookie, or body changes."""
    return await service.proxy_call(
        _repeat_request,
        {"request_id": request_id, "modifications": modifications},
    )


@mcp.tool()
async def list_sitemap(
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: str = "DIRECT",
    page: int = 1,
) -> dict[str, Any]:
    """Browse the hierarchical sitemap built from captured proxy traffic."""
    return await service.proxy_call(
        _list_sitemap,
        {"scope_id": scope_id, "parent_id": parent_id, "depth": depth, "page": page},
    )


@mcp.tool()
async def view_sitemap_entry(entry_id: str) -> dict[str, Any]:
    """View one proxy sitemap entry and its recent requests."""
    return await service.proxy_call(_view_sitemap_entry, {"entry_id": entry_id})


@mcp.tool()
async def manage_scope(
    action: str,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> dict[str, Any]:
    """Create, list, update, get, or delete Caido proxy scope rules."""
    return await service.proxy_call(
        _scope_rules,
        {
            "action": action,
            "allowlist": allowlist,
            "denylist": denylist,
            "scope_id": scope_id,
            "scope_name": scope_name,
        },
    )


@mcp.tool()
async def create_vulnerability_report(
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    cvss_breakdown: dict[str, str],
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Persist one distinct, verified vulnerability and its working proof of concept."""
    return await service.create_finding(
        title=title,
        description=description,
        impact=impact,
        target=target,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
        cvss_breakdown=cvss_breakdown,
        endpoint=endpoint,
        method=method,
        cve=cve,
        cwe=cwe,
        code_locations=code_locations,
    )


@mcp.tool()
def list_findings() -> dict[str, Any]:
    """List findings already persisted for the active scan."""
    return service.list_findings()


@mcp.tool()
def scan_status() -> dict[str, Any]:
    """Return active scan metadata, output path, and finding count."""
    return service.status()


@mcp.tool()
async def finish_scan(
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
) -> dict[str, Any]:
    """Finalize the customer-facing report and tear down the sandbox."""
    return await service.finish_scan(
        executive_summary=executive_summary,
        methodology=methodology,
        technical_analysis=technical_analysis,
        recommendations=recommendations,
    )


@mcp.tool()
async def stop_scan(status: str = "stopped") -> dict[str, Any]:
    """Persist an incomplete scan and tear down its sandbox."""
    return await service.stop_scan(status)


def main() -> None:
    """Run the local stdio MCP server."""
    anyio.run(_run_stdio)


@asynccontextmanager
async def _event_loop_stdio() -> Any:
    """Provide stdio streams without AnyIO's worker-thread file wrapper.

    Some managed shells block AnyIO worker-thread jobs indefinitely. Reading
    and writing the pipe file descriptors through the event loop keeps the MCP
    transport portable while preserving newline-delimited JSON-RPC semantics.
    """
    read_writer, read_stream = anyio.create_memory_object_stream(0)
    write_stream, write_reader = anyio.create_memory_object_stream(0)

    async def read_stdin() -> None:
        buffered = b""
        async with read_writer:
            while True:
                await anyio.wait_readable(0)
                chunk = os.read(0, 65536)
                if not chunk:
                    break
                buffered += chunk
                while b"\n" in buffered:
                    line, buffered = buffered.split(b"\n", 1)
                    if not line:
                        continue
                    try:
                        message = mcp_types.JSONRPCMessage.model_validate_json(line)
                    except Exception as exc:  # noqa: BLE001 - protocol parse errors are messages.
                        await read_writer.send(exc)
                    else:
                        await read_writer.send(SessionMessage(message))

    async def write_stdout() -> None:
        async with write_reader:
            async for session_message in write_reader:
                payload = (
                    session_message.message.model_dump_json(by_alias=True, exclude_none=True)
                    + "\n"
                ).encode()
                while payload:
                    await anyio.wait_writable(1)
                    payload = payload[os.write(1, payload) :]

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(read_stdin)
        tasks.start_soon(write_stdout)
        yield read_stream, write_stream


async def _run_stdio() -> None:
    async with _event_loop_stdio() as (read_stream, write_stream):
        await mcp._mcp_server.run(  # noqa: SLF001 - mirrors FastMCP.run_stdio_async.
            read_stream,
            write_stream,
            mcp._mcp_server.create_initialization_options(),  # noqa: SLF001
        )


if __name__ == "__main__":
    main()
