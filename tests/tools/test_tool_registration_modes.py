import importlib
import sys
from types import ModuleType
from typing import Any

from strix.config import Config
from strix.runtime.context import configure_runtime_context
from strix.tools.registry import clear_registry


def _config_without_web_search(_cls: type[Config]) -> dict[str, Any]:
    return {
        "features": {
            "disable_browser": True,
        }
    }


def _reload_tools_module() -> ModuleType:
    clear_registry()

    for name in list(sys.modules):
        if name == "strix.tools" or name.startswith("strix.tools."):
            sys.modules.pop(name, None)

    return importlib.import_module("strix.tools")


def test_non_sandbox_registers_agents_graph_but_not_browser_or_web_search_when_disabled(
    monkeypatch: Any,
) -> None:
    configure_runtime_context(sandbox_mode=False, caido_api_token=None)
    monkeypatch.setattr(Config, "load", classmethod(_config_without_web_search))

    tools = _reload_tools_module()
    names = set(tools.get_tool_names())

    assert "create_agent" in names
    assert "browser_action" not in names
    assert "web_search" not in names


def test_sandbox_registers_sandbox_tools_but_not_non_sandbox_tools(
    monkeypatch: Any,
) -> None:
    configure_runtime_context(sandbox_mode=True, caido_api_token=None)
    monkeypatch.setattr(Config, "load", classmethod(_config_without_web_search))

    tools = _reload_tools_module()
    names = set(tools.get_tool_names())

    assert "terminal_execute" in names
    assert "python_action" in names
    assert "list_requests" in names
    assert "create_agent" not in names
    assert "finish_scan" not in names
    assert "load_skill" not in names
    assert "browser_action" not in names
    assert "web_search" not in names


def test_load_skill_import_does_not_register_create_agent_in_sandbox(
    monkeypatch: Any,
) -> None:
    configure_runtime_context(sandbox_mode=True, caido_api_token=None)
    monkeypatch.setattr(Config, "load", classmethod(_config_without_web_search))

    clear_registry()
    for name in list(sys.modules):
        if name == "strix.tools" or name.startswith("strix.tools."):
            sys.modules.pop(name, None)

    load_skill_module = importlib.import_module("strix.tools.load_skill.load_skill_actions")
    registry = importlib.import_module("strix.tools.registry")

    names_before = set(registry.get_tool_names())
    assert "load_skill" not in names_before
    assert "create_agent" not in names_before

    state_type = type(
        "DummyState",
        (),
        {
            "agent_id": "agent_test",
            "context": {},
            "update_context": lambda self, key, value: self.context.__setitem__(key, value),
        },
    )
    result = load_skill_module.load_skill(state_type(), "nmap")

    names_after = set(registry.get_tool_names())
    assert "create_agent" not in names_after
    assert result["success"] is False
