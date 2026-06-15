"""F-10: inventory tools must be reachable through the built agent, not just importable."""

from __future__ import annotations

import sys
from types import ModuleType
from typing import Any, ClassVar
from unittest import TestCase


# Minimal mock of the agents SDK so build_strix_agent can be imported and tested
# hermetically without the real SDK/sandbox dependencies.
_agents: Any = ModuleType("agents")
_agents_usage: Any = ModuleType("agents.usage")


class _Usage:
    pass


_agents_usage.Usage = _Usage
_agents_usage.serialize_usage = lambda _: {}
_agents_usage.deserialize_usage = lambda _: _Usage()


class _RunContextWrapper:
    def __init__(self, context: dict[str, Any] | None = None) -> None:
        self.context = context or {}


def _function_tool(*, timeout: int = 60, strict_mode: bool = False) -> Any:
    _ = timeout, strict_mode

    def decorator(func: Any) -> Any:
        func.name = func.__name__
        return func

    return decorator


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name


class _FunctionTool(_Tool):
    pass


class _CustomTool(_Tool):
    pass


class _SandboxAgent:
    def __init__(self, tools: list[Any] | None = None, **_: Any) -> None:
        self.tools = tools or []


class _ToolsToFinalOutputResult:
    def __init__(self, is_final_output: bool, final_output: Any) -> None:
        self.is_final_output = is_final_output
        self.final_output = final_output


class _Filesystem:
    def __init__(self, configure_tools: Any = None) -> None:
        self.configure_tools = configure_tools


class _Shell:
    def __init__(self, configure_tools: Any = None) -> None:
        self.configure_tools = configure_tools


class _InvalidManifestPathError(Exception):
    pass


_agents.RunContextWrapper = _RunContextWrapper
_agents.function_tool = _function_tool
_agents.agent = ModuleType("agents.agent")
_agents.agent.ToolsToFinalOutputResult = _ToolsToFinalOutputResult
_agents.sandbox = ModuleType("agents.sandbox")
_agents.sandbox.SandboxAgent = _SandboxAgent
_agents.sandbox.capabilities = ModuleType("agents.sandbox.capabilities")
_agents.sandbox.capabilities.Filesystem = _Filesystem
_agents.sandbox.capabilities.Shell = _Shell
_agents.sandbox.errors = ModuleType("agents.sandbox.errors")
_agents.sandbox.errors.InvalidManifestPathError = _InvalidManifestPathError
_agents.tool = ModuleType("agents.tool")
_agents.tool.CustomTool = _CustomTool
_agents.tool.FunctionTool = _FunctionTool
_agents.tool.Tool = _Tool

sys.modules["agents"] = _agents
sys.modules["agents.usage"] = _agents_usage
sys.modules["agents.agent"] = _agents.agent
sys.modules["agents.sandbox"] = _agents.sandbox
sys.modules["agents.sandbox.capabilities"] = _agents.sandbox.capabilities
sys.modules["agents.sandbox.errors"] = _agents.sandbox.errors
sys.modules["agents.tool"] = _agents.tool

# Clear any stale namespace-module mocks left by other tests so the real
# strix.tools.proxy package is loaded for the factory import.
for _stale in ("strix.tools.proxy", "strix.tools.proxy.caido_api"):
    sys.modules.pop(_stale, None)

# Mock caido_sdk_client so proxy tools can import without the real client.
_caido_sdk_client: Any = ModuleType("caido_sdk_client")
_caido_sdk_client.Client = object
_caido_sdk_client.TokenAuthOptions = object
_caido_sdk_client.types = ModuleType("caido_sdk_client.types")
_caido_sdk_client.types.ConnectionInfoInput = object
_caido_sdk_client.types.CreateScopeOptions = object
_caido_sdk_client.types.ReplaySendOptions = object
_caido_sdk_client.types.RequestGetOptions = object
_caido_sdk_client.types.UpdateScopeOptions = object
sys.modules["caido_sdk_client"] = _caido_sdk_client
sys.modules["caido_sdk_client.types"] = _caido_sdk_client.types

from strix.agents.factory import build_strix_agent  # noqa: E402


def _tool_names(agent: Any) -> set[str]:
    names: set[str] = set()
    for tool in agent.tools:
        if hasattr(tool, "name"):
            names.add(str(tool.name))
        elif callable(tool):
            names.add(str(tool.__name__))
    return names


class TestInventoryToolRegistration(TestCase):
    BLACKBOX_TOOLS: ClassVar[set[str]] = {
        "collect_inventory_from_proxy",
        "build_ranked_surface_map",
        "load_ranked_surface_map",
        "classify_inventory_params",
        "spray_inventory_params",
        "enrich_inventory_from_openapi",
        "enrich_inventory_from_js",
        "enrich_inventory_from_forms",
    }

    OOB_TOOLS: ClassVar[set[str]] = {
        "mint_oob_token",
        "poll_oob_callbacks",
        "confirm_oob_callback",
        "report_oob_confirmed_candidate",
    }

    def test_blackbox_agent_exposes_inventory_tools(self) -> None:
        agent = build_strix_agent(is_root=True, is_whitebox=False)
        self.assertTrue(self.BLACKBOX_TOOLS.issubset(_tool_names(agent)))

    def test_blackbox_agent_omits_code_collector(self) -> None:
        agent = build_strix_agent(is_root=True, is_whitebox=False)
        self.assertNotIn("collect_inventory_from_code", _tool_names(agent))

    def test_whitebox_agent_adds_code_collector(self) -> None:
        agent = build_strix_agent(is_root=True, is_whitebox=True)
        self.assertIn("collect_inventory_from_code", _tool_names(agent))

    def test_blackbox_agent_exposes_oob_tools(self) -> None:
        agent = build_strix_agent(is_root=True, is_whitebox=False)
        self.assertTrue(self.OOB_TOOLS.issubset(_tool_names(agent)))
