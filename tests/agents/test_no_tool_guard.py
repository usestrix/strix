import asyncio

from strix.agents import AgentState, StrixAgent
from strix.llm.config import LLMConfig
from strix.tools.agents_graph import agents_graph_actions


def _reset_agent_graph_state() -> None:
    agents_graph_actions._agent_graph["nodes"].clear()
    agents_graph_actions._agent_graph["edges"].clear()
    agents_graph_actions._agent_messages.clear()
    agents_graph_actions._running_agents.clear()
    agents_graph_actions._agent_instances.clear()
    agents_graph_actions._completed_agent_llm_totals.clear()
    agents_graph_actions._completed_agent_llm_totals.update(
        agents_graph_actions._empty_llm_stats_totals()
    )
    agents_graph_actions._agent_states.clear()


def test_non_interactive_agent_stops_after_repeated_text_only_responses(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "true")
    monkeypatch.setenv("STRIX_AGENT_NO_TOOL_MAX_RETRIES", "2")
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-5")
    _reset_agent_graph_state()

    state = AgentState(
        agent_name="Local Model Child",
        parent_id="parent-agent",
        max_iterations=10,
    )
    agent = StrixAgent({"llm_config": LLMConfig(interactive=False), "state": state})

    async def text_only_iteration(_tracer):
        agent.state.add_message("assistant", "I will do the task without using a tool.")
        return None

    monkeypatch.setattr(agent, "_process_iteration", text_only_iteration)

    result = asyncio.run(agent.agent_loop("Investigate auth"))

    assert result["success"] is False
    assert "no executable tool calls" in result["error"]
    assert state.completed is True
    assert agents_graph_actions._agent_messages["parent-agent"]
    assert "FAILED" in agents_graph_actions._agent_messages["parent-agent"][0]["content"]
