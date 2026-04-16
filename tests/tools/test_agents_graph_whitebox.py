from types import SimpleNamespace

import strix.agents as agents_module
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


def test_create_agent_inherits_parent_whitebox_flag(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-5")

    _reset_agent_graph_state()

    parent_id = "parent-agent"
    parent_llm = LLMConfig(timeout=123, scan_mode="standard", is_whitebox=True)
    agents_graph_actions._agent_instances[parent_id] = SimpleNamespace(
        llm_config=parent_llm,
        non_interactive=True,
    )

    captured_config: dict[str, object] = {}

    class FakeStrixAgent:
        def __init__(self, config: dict[str, object]):
            captured_config["agent_config"] = config

    class FakeThread:
        def __init__(self, target, args, daemon, name):
            self.target = target
            self.args = args
            self.daemon = daemon
            self.name = name

        def start(self) -> None:
            return None

    monkeypatch.setattr(agents_module, "StrixAgent", FakeStrixAgent)
    monkeypatch.setattr(agents_graph_actions.threading, "Thread", FakeThread)

    agent_state = SimpleNamespace(
        agent_id=parent_id,
        get_conversation_history=list,
    )
    result = agents_graph_actions.create_agent(
        agent_state=agent_state,
        task="source-aware child task",
        name="SourceAwareChild",
        inherit_context=False,
    )

    assert result["success"] is True
    llm_config = captured_config["agent_config"]["llm_config"]
    assert isinstance(llm_config, LLMConfig)
    assert llm_config.timeout == 123
    assert llm_config.scan_mode == "standard"
    assert llm_config.is_whitebox is True
    child_task = captured_config["agent_config"]["state"].task
    assert "White-box execution guidance (recommended when source is available):" in child_task
    assert "mandatory" not in child_task.lower()


def test_delegation_prompt_includes_wiki_memory_instruction_in_whitebox(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-5")

    _reset_agent_graph_state()

    parent_id = "parent-1"
    child_id = "child-1"
    agents_graph_actions._agent_graph["nodes"][parent_id] = {"name": "Parent", "status": "running"}
    agents_graph_actions._agent_graph["nodes"][child_id] = {"name": "Child", "status": "running"}

    class FakeState:
        def __init__(self) -> None:
            self.agent_id = child_id
            self.agent_name = "Child"
            self.parent_id = parent_id
            self.task = "analyze source risks"
            self.stop_requested = False
            self.messages: list[tuple[str, str]] = []

        def add_message(self, role: str, content: str) -> None:
            self.messages.append((role, content))

        def model_dump(self) -> dict[str, str]:
            return {"agent_id": self.agent_id}

    class FakeAgent:
        def __init__(self) -> None:
            self.llm_config = LLMConfig(is_whitebox=True)

        async def agent_loop(self, _task: str) -> dict[str, bool]:
            return {"ok": True}

    state = FakeState()
    agent = FakeAgent()
    agents_graph_actions._agent_instances[child_id] = agent
    result = agents_graph_actions._run_agent_in_thread(agent, state, inherited_messages=[])

    assert result["result"] == {"ok": True}
    task_messages = [msg for role, msg in state.messages if role == "user"]
    assert task_messages
    assert 'list_notes(category="wiki")' in task_messages[-1]
    assert "get_note(note_id=...)" in task_messages[-1]
    assert "Before agent_finish" in task_messages[-1]


def test_agent_finish_appends_wiki_update_for_whitebox(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-5")

    _reset_agent_graph_state()

    parent_id = "parent-2"
    child_id = "child-2"
    agents_graph_actions._agent_graph["nodes"][parent_id] = {
        "name": "Parent",
        "task": "parent task",
        "status": "running",
        "parent_id": None,
    }
    agents_graph_actions._agent_graph["nodes"][child_id] = {
        "name": "Child",
        "task": "child task",
        "status": "running",
        "parent_id": parent_id,
    }
    agents_graph_actions._agent_instances[child_id] = SimpleNamespace(
        llm_config=LLMConfig(is_whitebox=True)
    )

    captured: dict[str, str] = {}

    def fake_list_notes(category=None):
        assert category == "wiki"
        return {
            "success": True,
            "notes": [{"note_id": "wiki-note-1", "content": "Existing wiki content"}],
            "total_count": 1,
        }

    captured_get: dict[str, str] = {}

    def fake_get_note(note_id: str):
        captured_get["note_id"] = note_id
        return {
            "success": True,
            "note": {
                "note_id": note_id,
                "title": "Repo Wiki",
                "content": "Existing wiki content",
            },
        }

    def fake_append_note_content(note_id: str, delta: str):
        captured["note_id"] = note_id
        captured["delta"] = delta
        return {"success": True, "note_id": note_id}

    monkeypatch.setattr("strix.tools.notes.notes_actions.list_notes", fake_list_notes)
    monkeypatch.setattr("strix.tools.notes.notes_actions.get_note", fake_get_note)
    monkeypatch.setattr("strix.tools.notes.notes_actions.append_note_content", fake_append_note_content)

    state = SimpleNamespace(agent_id=child_id, parent_id=parent_id)
    result = agents_graph_actions.agent_finish(
        agent_state=state,
        result_summary="AST pass completed",
        findings=["Found route sink candidate"],
        success=True,
        final_recommendations=["Validate sink with dynamic PoC"],
    )

    assert result["agent_completed"] is True
    assert captured_get["note_id"] == "wiki-note-1"
    assert captured["note_id"] == "wiki-note-1"
    assert "Agent Update: Child" in captured["delta"]
    assert "AST pass completed" in captured["delta"]


def test_run_agent_in_thread_injects_shared_wiki_context_in_whitebox(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-5")

    _reset_agent_graph_state()

    parent_id = "parent-3"
    child_id = "child-3"
    agents_graph_actions._agent_graph["nodes"][parent_id] = {"name": "Parent", "status": "running"}
    agents_graph_actions._agent_graph["nodes"][child_id] = {"name": "Child", "status": "running"}

    class FakeState:
        def __init__(self) -> None:
            self.agent_id = child_id
            self.agent_name = "Child"
            self.parent_id = parent_id
            self.task = "map source"
            self.stop_requested = False
            self.messages: list[tuple[str, str]] = []

        def add_message(self, role: str, content: str) -> None:
            self.messages.append((role, content))

        def model_dump(self) -> dict[str, str]:
            return {"agent_id": self.agent_id}

    class FakeAgent:
        def __init__(self) -> None:
            self.llm_config = LLMConfig(is_whitebox=True)

        async def agent_loop(self, _task: str) -> dict[str, bool]:
            return {"ok": True}

    captured_get: dict[str, str] = {}

    def fake_list_notes(category=None):
        assert category == "wiki"
        return {
            "success": True,
            "notes": [{"note_id": "wiki-ctx-1"}],
            "total_count": 1,
        }

    def fake_get_note(note_id: str):
        captured_get["note_id"] = note_id
        return {
            "success": True,
            "note": {
                "note_id": note_id,
                "title": "Shared Repo Wiki",
                "content": "Architecture: server/client split",
            },
        }

    monkeypatch.setattr("strix.tools.notes.notes_actions.list_notes", fake_list_notes)
    monkeypatch.setattr("strix.tools.notes.notes_actions.get_note", fake_get_note)

    state = FakeState()
    agent = FakeAgent()
    agents_graph_actions._agent_instances[child_id] = agent
    result = agents_graph_actions._run_agent_in_thread(agent, state, inherited_messages=[])

    assert result["result"] == {"ok": True}
    assert captured_get["note_id"] == "wiki-ctx-1"
    user_messages = [content for role, content in state.messages if role == "user"]
    assert user_messages
    assert "<shared_repo_wiki" in user_messages[0]
    assert "Architecture: server/client split" in user_messages[0]


def test_load_primary_wiki_note_prefers_repo_tag_match(monkeypatch) -> None:
    selected_note_ids: list[str] = []

    def fake_list_notes(category=None):
        assert category == "wiki"
        return {
            "success": True,
            "notes": [
                {"note_id": "wiki-other", "tags": ["repo:other"]},
                {"note_id": "wiki-target", "tags": ["repo:appsmith"]},
            ],
            "total_count": 2,
        }

    def fake_get_note(note_id: str):
        selected_note_ids.append(note_id)
        return {
            "success": True,
            "note": {"note_id": note_id, "title": "Repo Wiki", "content": "content"},
        }

    monkeypatch.setattr("strix.tools.notes.notes_actions.list_notes", fake_list_notes)
    monkeypatch.setattr("strix.tools.notes.notes_actions.get_note", fake_get_note)

    agent_state = SimpleNamespace(
        task="analyze /workspace/appsmith",
        context={"whitebox_repo_tags": ["repo:appsmith"]},
    )
    note = agents_graph_actions._load_primary_wiki_note(agent_state)

    assert note is not None
    assert note["note_id"] == "wiki-target"
    assert selected_note_ids == ["wiki-target"]
