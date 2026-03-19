from typing import Any

from strix.tools.agents_graph import agents_graph_actions
from strix.tools.load_skill import load_skill_actions


class _DummyLLM:
    def __init__(self, initial_skills: list[str] | None = None) -> None:
        self.loaded: set[str] = set(initial_skills or [])

    def add_skills(self, skill_names: list[str]) -> list[str]:
        newly_loaded = [skill for skill in skill_names if skill not in self.loaded]
        self.loaded.update(newly_loaded)
        return newly_loaded


class _DummyAgent:
    def __init__(self, initial_skills: list[str] | None = None) -> None:
        self.llm = _DummyLLM(initial_skills)


class _DummyAgentState:
    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self.context: dict[str, Any] = {}

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value


def test_load_skill_success_and_context_update() -> None:
    instances = agents_graph_actions.__dict__["_agent_instances"]
    original_instances = dict(instances)
    try:
        state = _DummyAgentState("agent_test_load_skill_success")
        instances.clear()
        instances[state.agent_id] = _DummyAgent()

        result = load_skill_actions.load_skill(state, "ffuf,xss")

        assert result["success"] is True
        assert result["loaded_skills"] == ["ffuf", "xss"]
        assert result["newly_loaded_skills"] == ["ffuf", "xss"]
        assert state.context["loaded_skills"] == ["ffuf", "xss"]
    finally:
        instances.clear()
        instances.update(original_instances)


def test_load_skill_uses_same_plain_skill_format_as_create_agent() -> None:
    instances = agents_graph_actions.__dict__["_agent_instances"]
    original_instances = dict(instances)
    try:
        state = _DummyAgentState("agent_test_load_skill_short_name")
        instances.clear()
        instances[state.agent_id] = _DummyAgent()

        result = load_skill_actions.load_skill(state, "nmap")

        assert result["success"] is True
        assert result["loaded_skills"] == ["nmap"]
        assert result["newly_loaded_skills"] == ["nmap"]
        assert state.context["loaded_skills"] == ["nmap"]
    finally:
        instances.clear()
        instances.update(original_instances)


def test_load_skill_invalid_skill_returns_error() -> None:
    instances = agents_graph_actions.__dict__["_agent_instances"]
    original_instances = dict(instances)
    try:
        state = _DummyAgentState("agent_test_load_skill_invalid")
        instances.clear()
        instances[state.agent_id] = _DummyAgent()

        result = load_skill_actions.load_skill(state, "definitely_not_a_real_skill")

        assert result["success"] is False
        assert "Invalid skills" in result["error"]
        assert "Available skills" in result["error"]
    finally:
        instances.clear()
        instances.update(original_instances)


def test_load_skill_rejects_more_than_five_skills() -> None:
    instances = agents_graph_actions.__dict__["_agent_instances"]
    original_instances = dict(instances)
    try:
        state = _DummyAgentState("agent_test_load_skill_too_many")
        instances.clear()
        instances[state.agent_id] = _DummyAgent()

        result = load_skill_actions.load_skill(state, "a,b,c,d,e,f")

        assert result["success"] is False
        assert result["error"] == (
            "Cannot specify more than 5 skills for an agent (use comma-separated format)"
        )
    finally:
        instances.clear()
        instances.update(original_instances)


def test_load_skill_missing_agent_instance_returns_error() -> None:
    instances = agents_graph_actions.__dict__["_agent_instances"]
    original_instances = dict(instances)
    try:
        state = _DummyAgentState("agent_test_load_skill_missing_instance")
        instances.clear()

        result = load_skill_actions.load_skill(state, "httpx")

        assert result["success"] is False
        assert "running agent instance" in result["error"]
    finally:
        instances.clear()
        instances.update(original_instances)


def test_load_skill_does_not_reload_skill_already_present_from_agent_creation() -> None:
    instances = agents_graph_actions.__dict__["_agent_instances"]
    original_instances = dict(instances)
    try:
        state = _DummyAgentState("agent_test_load_skill_existing_config_skill")
        instances.clear()
        instances[state.agent_id] = _DummyAgent(["xss"])

        result = load_skill_actions.load_skill(state, "xss,sql_injection")

        assert result["success"] is True
        assert result["loaded_skills"] == ["xss", "sql_injection"]
        assert result["newly_loaded_skills"] == ["sql_injection"]
        assert result["already_loaded_skills"] == ["xss"]
        assert state.context["loaded_skills"] == ["sql_injection", "xss"]
    finally:
        instances.clear()
        instances.update(original_instances)
