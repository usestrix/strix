from typing import Any

import strix.runtime_agent_registry as runtime_registry
from strix.tools.runtime_skills import runtime_skills_actions


class _DummyLLM:
    def __init__(self) -> None:
        self.loaded: set[str] = set()

    def add_runtime_skills(self, skill_names: list[str]) -> list[str]:
        newly_loaded = [skill for skill in skill_names if skill not in self.loaded]
        self.loaded.update(newly_loaded)
        return newly_loaded


class _DummyAgent:
    def __init__(self) -> None:
        self.llm = _DummyLLM()


class _DummyAgentState:
    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self.context: dict[str, Any] = {}

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value


def test_load_skill_success_and_context_update() -> None:
    instances = runtime_registry.__dict__["_agent_instances"]
    original_instances = dict(instances)
    try:
        state = _DummyAgentState("agent_test_load_skill_success")
        instances.clear()
        instances[state.agent_id] = _DummyAgent()

        result = runtime_skills_actions.load_skill(state, "tooling/ffuf,xss")

        assert result["success"] is True
        assert result["loaded_skills"] == ["tooling/ffuf", "xss"]
        assert result["newly_loaded_skills"] == ["tooling/ffuf", "xss"]
        assert state.context["runtime_skills_loaded"] == ["tooling/ffuf", "xss"]
    finally:
        instances.clear()
        instances.update(original_instances)


def test_load_skill_short_tool_name_is_canonicalized_in_context() -> None:
    instances = runtime_registry.__dict__["_agent_instances"]
    original_instances = dict(instances)
    try:
        state = _DummyAgentState("agent_test_load_skill_short_name")
        instances.clear()
        instances[state.agent_id] = _DummyAgent()

        result = runtime_skills_actions.load_skill(state, "nmap")

        assert result["success"] is True
        assert result["loaded_skills"] == ["tooling/nmap"]
        assert result["newly_loaded_skills"] == ["tooling/nmap"]
        assert state.context["runtime_skills_loaded"] == ["tooling/nmap"]
    finally:
        instances.clear()
        instances.update(original_instances)


def test_load_skill_invalid_skill_returns_error() -> None:
    instances = runtime_registry.__dict__["_agent_instances"]
    original_instances = dict(instances)
    try:
        state = _DummyAgentState("agent_test_load_skill_invalid")
        instances.clear()
        instances[state.agent_id] = _DummyAgent()

        result = runtime_skills_actions.load_skill(state, "definitely_not_a_real_skill")

        assert result["success"] is False
        assert "Invalid skills" in result["error"]
    finally:
        instances.clear()
        instances.update(original_instances)


def test_load_skill_missing_agent_instance_returns_error() -> None:
    instances = runtime_registry.__dict__["_agent_instances"]
    original_instances = dict(instances)
    try:
        state = _DummyAgentState("agent_test_load_skill_missing_instance")
        instances.clear()

        result = runtime_skills_actions.load_skill(state, "tooling/httpx")

        assert result["success"] is False
        assert "running agent instance" in result["error"]
    finally:
        instances.clear()
        instances.update(original_instances)
