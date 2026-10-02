"""Process cleanup that cannot accidentally target another agent's services."""

from typing import Any

from agents import RunContextWrapper, function_tool

from strix.runtime.agent_session import AgentSandboxSession


@function_tool
async def stop_process(ctx: RunContextWrapper[dict[str, Any]], pid: int) -> str:
    """Stop a background PID started by this agent. For tool sessions use write_stdin Ctrl-C.

    Args:
        pid: OS process ID printed when this agent started the background process.
    """
    session = ctx.context.get("sandbox_session")
    if not isinstance(session, AgentSandboxSession):
        return "Process ownership is unavailable; use Ctrl-C on your own write_stdin session."
    result = await session.stop_process(pid)
    return str(result.stdout or result.stderr or f"Process stop returned {result.exit_code}")
