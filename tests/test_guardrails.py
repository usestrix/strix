"""Tests for destructive-command guardrails."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import pytest
from agents.tool import FunctionTool

from strix.agents import factory
from strix.agents.guardrails import check_destructive


# ── check_destructive 单元测试 ──

@pytest.mark.parametrize(
    "cmd",
    [
        "DROP TABLE users",
        "drop table if exists users;",
        "DROP DATABASE prod",
        "TRUNCATE TABLE logs",
        "DELETE FROM orders;",
        "ALTER TABLE users DROP COLUMN email",
        "rm -rf /",
        "rm -rf /tmp && echo done",
        "mkfs.ext4 /dev/sda1",
        "dd if=/dev/zero of=/dev/sda bs=1M",
        ":(){ :|:& };:",
        "shutdown -h now",
        "git push origin main --force",
    ],
)
def test_destructive_commands_are_blocked(cmd: str) -> None:
    assert check_destructive(cmd) is not None, f"should block: {cmd}"


@pytest.mark.parametrize(
    "cmd",
    [
        "SELECT * FROM users",
        "SELECT count(*) FROM users WHERE id > 10",
        "ls -la /tmp",
        "curl -s http://localhost:8080/admin",
        "nmap -sV target.local",
        "echo hello",
        "python3 -c 'print(1)'",
        "git status",
        "sqlmap -u http://target --batch",
    ],
)
def test_safe_commands_pass(cmd: str) -> None:
    assert check_destructive(cmd) is None, f"should allow: {cmd}"


# ── 集成测试：exec_command 包装阻止破坏性命令 ──

def _capturing_exec_tool(captured: dict[str, str]) -> FunctionTool:
    async def invoke(_ctx: Any, raw_input: str) -> str:
        captured["raw_input"] = raw_input
        return "ok"

    return FunctionTool(
        name="exec_command",
        description="test tool",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
    )


@pytest.mark.asyncio
async def test_wrap_exec_command_blocks_destructive() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    result = await wrapped.on_invoke_tool(
        cast("Any", None), json.dumps({"cmd": "DROP TABLE users"})
    )

    assert "guardrail" in result
    assert "destructive" in result
    # 工具不应真正执行
    assert "raw_input" not in captured


@pytest.mark.asyncio
async def test_wrap_exec_command_allows_safe() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._wrap_exec_command(_capturing_exec_tool(captured))

    result = await wrapped.on_invoke_tool(
        cast("Any", None), json.dumps({"cmd": "SELECT * FROM users"})
    )

    assert result == "ok"
    assert "cmd" in captured["raw_input"]
