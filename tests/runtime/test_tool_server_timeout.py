"""Unit + functional tests for request-timeout resolution in the sandbox tool server.

Regression coverage for #436 — ``terminal_execute`` timing out at the sandbox
hard cap even when the caller passed a longer explicit ``timeout`` kwarg.
"""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from strix.tools import registry


if TYPE_CHECKING:
    from types import ModuleType


TOOL_SERVER_PATH = Path(__file__).resolve().parents[2] / "strix" / "runtime" / "tool_server.py"


@pytest.fixture
def tool_server(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load ``strix.runtime.tool_server`` under its import-time guards.

    The module requires ``STRIX_SANDBOX_MODE=true`` and reads ``sys.argv`` at
    import time. We load it under a unique module name via ``importlib.util``
    and register it with ``monkeypatch.setitem`` so the entry is torn down
    between tests — keeping sibling tests clean.
    """

    monkeypatch.setenv("STRIX_SANDBOX_MODE", "true")
    monkeypatch.setattr(
        sys,
        "argv",
        ["tool_server", "--token", "test-token", "--port", "0"],
    )

    spec = importlib.util.spec_from_file_location(
        "strix.runtime._tool_server_under_test", TOOL_SERVER_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


class TestResolveRequestTimeout:
    def test_no_timeout_kwarg_uses_default(self, tool_server: ModuleType) -> None:
        assert tool_server._resolve_request_timeout(120, {}) == 120
        assert tool_server._resolve_request_timeout(120, {"command": "ls"}) == 120

    def test_small_tool_timeout_keeps_default_hard_cap(self, tool_server: ModuleType) -> None:
        # Inner tool asks for 10s; sandbox default (120) still dominates.
        assert tool_server._resolve_request_timeout(120, {"timeout": 10}) == 120

    def test_large_tool_timeout_grows_envelope_by_buffer(self, tool_server: ModuleType) -> None:
        # The actual #436 case: agent passes a 600s timeout, sandbox should grow
        # the wait_for envelope to 600s + buffer instead of killing at 120.
        buffer = tool_server._TOOL_TIMEOUT_BUFFER_SECONDS
        assert tool_server._resolve_request_timeout(120, {"timeout": 600}) == 600 + buffer

    def test_float_timeout_is_accepted(self, tool_server: ModuleType) -> None:
        buffer = tool_server._TOOL_TIMEOUT_BUFFER_SECONDS
        assert tool_server._resolve_request_timeout(120, {"timeout": 300.0}) == 300 + buffer

    def test_zero_or_negative_timeout_falls_back_to_default(self, tool_server: ModuleType) -> None:
        assert tool_server._resolve_request_timeout(120, {"timeout": 0}) == 120
        assert tool_server._resolve_request_timeout(120, {"timeout": -1}) == 120

    def test_bool_is_not_treated_as_timeout(self, tool_server: ModuleType) -> None:
        # ``bool`` is a subclass of ``int``; guard against ``True`` being read
        # as ``1 second`` (or ``False`` disabling the envelope).
        assert tool_server._resolve_request_timeout(120, {"timeout": True}) == 120
        assert tool_server._resolve_request_timeout(120, {"timeout": False}) == 120

    def test_non_numeric_timeout_is_ignored(self, tool_server: ModuleType) -> None:
        assert tool_server._resolve_request_timeout(120, {"timeout": None}) == 120
        assert tool_server._resolve_request_timeout(120, {"timeout": "forever"}) == 120
        assert tool_server._resolve_request_timeout(120, {"timeout": ["a"]}) == 120


async def test_timeout_error_message_is_actionable(
    tool_server: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a tool exceeds the effective envelope, the response error mentions
    ``STRIX_SANDBOX_EXECUTION_TIMEOUT`` so issue-reporters like #436 can
    self-discover the configuration knob."""

    # Shrink the envelope to keep the test fast.
    monkeypatch.setattr(tool_server, "REQUEST_TIMEOUT", 1)

    def _slow_tool(**_kwargs: Any) -> dict[str, Any]:
        time.sleep(3)
        return {"ok": True}

    _slow_tool.__name__ = "__slow_test_tool__"
    monkeypatch.setitem(registry._tools_by_name, "__slow_test_tool__", _slow_tool)

    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="test-token")
    request = tool_server.ToolExecutionRequest(
        agent_id="agent-x",
        tool_name="__slow_test_tool__",
        kwargs={},
    )

    response = await tool_server.execute_tool(request, creds)

    assert response.result is None
    assert response.error is not None
    assert "timed out after 1s" in response.error
    assert "STRIX_SANDBOX_EXECUTION_TIMEOUT" in response.error
