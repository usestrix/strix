from strix.agents.state import AgentState
from strix.tools.agents_graph import agents_graph_actions


def test_wait_for_message_allows_last_running_agent_to_wait(monkeypatch) -> None:
    agent_state = AgentState(agent_id="agent_root", agent_name="Root Agent")
    graph = {
        "nodes": {
            "agent_root": {"name": "Root Agent", "status": "running"},
            "agent_child": {"name": "Child Agent", "status": "waiting"},
        },
        "edges": [],
    }
    monkeypatch.setattr(agents_graph_actions, "_agent_graph", graph)

    result = agents_graph_actions.wait_for_message(agent_state, "Waiting for user input")

    assert result["success"] is True
    assert result["status"] == "waiting"
    assert graph["nodes"]["agent_root"]["status"] == "waiting"
    assert agent_state.waiting_for_input is True
