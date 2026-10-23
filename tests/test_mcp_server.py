"""Tests for ``strix mcp-server`` — the MCP stdio bridge.

These cover the parts that need no Docker sandbox: the host-tool registry, the
MCP tool advertisement, and the invoke path that calls a Strix ``FunctionTool``
through a minimal run context. Sandbox bring-up is exercised separately and is
not required here.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest
from agents.tool import FunctionTool
from mcp.shared.memory import create_connected_server_and_client_session

from strix.interface import mcp_server
from strix.report.state import get_global_report_state, set_global_report_state
from strix.tools.load_skill.tool import load_skill


if TYPE_CHECKING:
    from pathlib import Path

    from agents.tool_context import ToolContext


def test_host_tools_are_function_tools_with_schemas() -> None:
    tools = mcp_server._host_tools()
    assert tools, "expected at least one host tool"
    for tool in tools:
        assert isinstance(tool, FunctionTool)
        assert tool.name
        assert isinstance(tool.params_json_schema, dict)


def test_host_tools_have_unique_names() -> None:
    names = [t.name for t in mcp_server._host_tools()]
    assert len(names) == len(set(names))


def test_orchestration_tools_are_not_exposed() -> None:
    names = {t.name for t in mcp_server._host_tools()}
    # The MCP client owns planning, control flow, and memory; Strix's
    # equivalents must not be advertised or they fight the client.
    for banned in ("create_agent", "finish_scan", "wait_for_user", "think", "create_todo"):
        assert banned not in names


def test_run_context_has_no_coordinator() -> None:
    # The exposed tools must degrade gracefully with no agent graph present.
    ctx = mcp_server._run_context(mcp_server._SandboxTools())
    assert ctx["agent_id"] == mcp_server.SERVER_NAME
    assert "coordinator" not in ctx
    assert ctx["interactive"] is False


@pytest.mark.asyncio
async def test_invoke_returns_text_for_bad_input() -> None:
    # load_skill with an invalid argument should come back as a graceful string,
    # never raise — the invoke path must always yield text for MCP.
    sandbox = mcp_server._SandboxTools()
    result = await mcp_server._invoke(load_skill, {"skills": 12345}, sandbox)
    assert isinstance(result, str)
    assert result


@pytest.mark.asyncio
async def test_invoke_serializes_non_string_results() -> None:
    # A tool returning a non-string must be JSON-encoded, not stringified ad hoc.
    async def _fake_invoke(_ctx: ToolContext[object], _raw: str) -> dict[str, int]:
        return {"ok": 1}

    fake = FunctionTool(
        name="fake",
        description="fake",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=_fake_invoke,
    )
    sandbox = mcp_server._SandboxTools()
    result = await mcp_server._invoke(fake, {}, sandbox)
    assert json.loads(result) == {"ok": 1}


def test_sandbox_specs_readable_without_a_session() -> None:
    # Advertising sandbox tools must not require a live container.
    specs = mcp_server._sandbox_tool_specs()
    names = {t.name for t in specs}
    assert names == set(mcp_server.SANDBOX_TOOL_NAMES)
    assert names == {"exec_command", "write_stdin"}
    for tool in specs:
        assert isinstance(tool.params_json_schema, dict)


@pytest.mark.asyncio
async def test_list_tools_handshake_does_not_start_sandbox() -> None:
    # A client lists tools on connect; that must complete over a real MCP
    # session without ever bringing up the Docker sandbox.
    class _NoBootSandbox(mcp_server._SandboxTools):
        async def ensure(self) -> dict[str, FunctionTool]:
            raise AssertionError("list_tools must not bring up the sandbox")

    server = mcp_server._build_server(_NoBootSandbox())
    async with create_connected_server_and_client_session(server) as client:
        listed = await client.list_tools()

    advertised = {t.name for t in listed.tools}
    assert "exec_command" in advertised  # sandbox tool, advertised statically
    assert "write_stdin" in advertised
    assert "load_skill" in advertised  # host tool
    # Orchestration tools stay hidden end-to-end.
    assert "finish_scan" not in advertised


@pytest.mark.asyncio
async def test_call_host_tool_over_session_returns_text() -> None:
    # A full client->server call of a host tool (no sandbox) returns text
    # content and does not raise, even on invalid input.
    server = mcp_server._build_server(mcp_server._SandboxTools())
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool("load_skill", {"skills": 123})
    assert result.content
    assert result.content[0].type == "text"
    assert result.content[0].text


@pytest.mark.asyncio
async def test_call_unknown_tool_errors() -> None:
    server = mcp_server._build_server(mcp_server._SandboxTools())
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool("no_such_tool", {})
    assert result.isError


def test_build_server_advertises_host_tools() -> None:
    server = mcp_server._build_server(mcp_server._SandboxTools())
    assert server.name == mcp_server.SERVER_NAME


def test_run_mcp_server_rejects_unknown_flag() -> None:
    with pytest.raises(SystemExit):
        mcp_server.run_mcp_server(["--definitely-not-a-flag"])


def test_build_local_sources_maps_dirs_to_mounts(tmp_path: Path) -> None:
    repo = tmp_path / "my-repo"
    repo.mkdir()
    sources = mcp_server._build_local_sources([str(repo)])
    assert len(sources) == 1
    assert sources[0]["source_path"] == str(repo)
    assert sources[0]["workspace_subdir"] == "my-repo"
    # Review mounts are read-only so shell tools cannot alter the host repo.
    assert sources[0]["read_only"] is True


def test_build_local_sources_rejects_missing_dir(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    with pytest.raises(ValueError, match="not a directory"):
        mcp_server._build_local_sources([str(missing)])


def test_mounted_repo_appears_in_context_and_instructions(tmp_path: Path) -> None:
    repo = tmp_path / "target-app"
    repo.mkdir()
    sources = mcp_server._build_local_sources([str(repo)])
    sandbox = mcp_server._SandboxTools(local_sources=sources)
    assert sandbox.workspace_paths == ["/workspace/target-app"]
    # Tools scope to the mounted path, and the client is told where it is.
    assert mcp_server._run_context(sandbox)["scan_targets"] == ["/workspace/target-app"]
    assert "/workspace/target-app" in mcp_server._server_instructions(sandbox)


def test_no_mount_leaves_instructions_unchanged() -> None:
    sandbox = mcp_server._SandboxTools()
    assert sandbox.workspace_paths == []
    assert mcp_server._server_instructions(sandbox) == mcp_server._INSTRUCTIONS


def test_build_local_sources_dedupes_colliding_names(tmp_path: Path) -> None:
    # Two repos with the same final path component must get distinct mounts,
    # or one would shadow the other at /workspace/<name>.
    a = tmp_path / "one" / "api"
    b = tmp_path / "two" / "api"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    sources = mcp_server._build_local_sources([str(a), str(b)])
    subdirs = [s["workspace_subdir"] for s in sources]
    assert subdirs == ["api", "api-2"]
    assert len(set(subdirs)) == 2


def test_init_run_state_wires_global_report_state(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Without this, reporting/threat-model/coverage tools report success but
    # persist nothing. _init_run_state must install a global report state and
    # create the run directory the tools write to.
    monkeypatch.chdir(tmp_path)
    try:
        assert get_global_report_state() is None
        returned = mcp_server._init_run_state("mcp-test")
        state = get_global_report_state()
        assert state is not None
        # run_name is used verbatim (stable across restarts), not a random id.
        run_dir = tmp_path / "strix_runs" / "mcp-test"
        assert returned == run_dir
        assert run_dir.is_dir()
        assert (run_dir / ".state").is_dir()
    finally:
        set_global_report_state(None)


@pytest.mark.asyncio
async def test_proxy_tool_brings_up_sandbox() -> None:
    # Proxy tools read the Caido client from the live session, so invoking one
    # must trigger sandbox bring-up even though it is a host tool.
    class _RecordingSandbox(mcp_server._SandboxTools):
        def __init__(self) -> None:
            super().__init__()
            self.ensure_calls = 0

        async def ensure(self) -> dict[str, FunctionTool]:
            self.ensure_calls += 1
            return {}

    sandbox = _RecordingSandbox()
    server = mcp_server._build_server(sandbox)
    async with create_connected_server_and_client_session(server) as client:
        # repeat_request takes a single required arg, so it clears schema
        # validation and reaches the dispatch that must start the sandbox.
        result = await client.call_tool("repeat_request", {"request_id": "missing"})
    assert sandbox.ensure_calls == 1
    assert result.content and result.content[0].type == "text"


def test_proxy_tool_names_are_host_tools() -> None:
    host_names = {t.name for t in mcp_server._host_tools()}
    assert mcp_server.PROXY_TOOL_NAMES
    assert host_names >= mcp_server.PROXY_TOOL_NAMES


@pytest.mark.asyncio
async def test_invoke_truncates_large_output(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # A huge tool result is trimmed to a bounded preview, and the full text is
    # written to the run directory so nothing is silently lost.
    monkeypatch.chdir(tmp_path)
    mcp_server._init_run_state("mcp-big")
    try:
        big = "x" * (mcp_server._MAX_RESULT_CHARS + 500)

        class _BigTool:
            name = "big"

            async def on_invoke_tool(self, _ctx, _args):  # type: ignore[no-untyped-def]
                return big

        out = await mcp_server._invoke(_BigTool(), {}, mcp_server._SandboxTools())  # type: ignore[arg-type]
        assert len(out) < len(big)
        assert "truncated" in out
        # The notice points at the retrieval tool, and the spill is readable.
        assert mcp_server._READ_OUTPUT_TOOL in out
        spilled = list((tmp_path / "strix_runs" / "mcp-big" / "mcp_outputs").glob("big-*.txt"))
        assert spilled and spilled[0].read_text(encoding="utf-8") == big
        back = mcp_server._read_spilled_output(spilled[0].name, 0, mcp_server._MAX_RESULT_CHARS)
        assert back.startswith("x")
        assert "more available: True" in back
    finally:
        set_global_report_state(None)


def test_read_spilled_output_rejects_traversal() -> None:
    assert "Invalid output id" in mcp_server._read_spilled_output("../secret.txt", 0, 100)
    assert "Invalid output id" in mcp_server._read_spilled_output("a/b.txt", 0, 100)


@pytest.mark.asyncio
async def test_read_tool_output_is_advertised_and_callable(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.chdir(tmp_path)
    mcp_server._init_run_state("mcp-read")
    try:
        output_id = mcp_server._spill_large_output("demo", "full-body-content")
        assert output_id
        server = mcp_server._build_server(mcp_server._SandboxTools())
        async with create_connected_server_and_client_session(server) as client:
            listed = {t.name for t in (await client.list_tools()).tools}
            assert mcp_server._READ_OUTPUT_TOOL in listed
            result = await client.call_tool(mcp_server._READ_OUTPUT_TOOL, {"output_id": output_id})
        assert result.content and "full-body-content" in result.content[0].text
    finally:
        set_global_report_state(None)


def test_configure_logging_enables_debug_on_stderr() -> None:
    strix_logger = logging.getLogger("strix")
    saved = (strix_logger.level, list(strix_logger.handlers), strix_logger.propagate)
    try:
        mcp_server._configure_logging(verbose=True)
        assert strix_logger.level == logging.DEBUG
        streams = [
            h
            for h in strix_logger.handlers
            if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
        ]
        assert streams
        assert all(h.level == logging.DEBUG for h in streams)
    finally:
        strix_logger.setLevel(saved[0])
        strix_logger.handlers = saved[1]
        strix_logger.propagate = saved[2]


def _docker_available() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    try:
        completed = subprocess.run(  # noqa: S603  # fixed `docker info`, resolved path
            [docker, "info"], capture_output=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


@pytest.mark.asyncio
@pytest.mark.skipif(not _docker_available(), reason="needs a running Docker daemon")
async def test_sandbox_runs_shell_on_readonly_mount(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Real Docker-backed flow: bring the sandbox up with a mounted repo, run a
    # shell command through the exposed tool, and confirm the mount is read-only.
    repo = tmp_path / "proj"
    repo.mkdir()
    (repo / "hello.txt").write_text("mounted-content", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    mcp_server._init_run_state("mcp-it")
    sources = mcp_server._build_local_sources([str(repo)])
    sandbox = mcp_server._SandboxTools(local_sources=sources)
    server = mcp_server._build_server(sandbox)
    try:
        async with create_connected_server_and_client_session(server) as client:
            read = await client.call_tool("exec_command", {"cmd": "cat /workspace/proj/hello.txt"})
            assert read.content and "mounted-content" in read.content[0].text
            wrote = await client.call_tool(
                "exec_command", {"cmd": "echo tampered > /workspace/proj/hello.txt"}
            )
            text = wrote.content[0].text.lower() if wrote.content else ""
            assert "read-only" in text or "permission denied" in text
        # Host file is untouched.
        assert (repo / "hello.txt").read_text(encoding="utf-8") == "mounted-content"
    finally:
        await sandbox.aclose()
        set_global_report_state(None)
