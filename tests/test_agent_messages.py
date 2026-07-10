"""Tests for agent-to-session message conversion."""

from __future__ import annotations

from strix.core.agents import AgentCoordinator


CHATGPT_TRANSCRIPT_CONTENT = (
    "<analysis>checked target</analysis>\n<channel>final</channel>\n<final>done</final>"
)


def test_message_to_session_item_strips_chatgpt_transcript_tags() -> None:
    coordinator = AgentCoordinator()
    coordinator.names["child"] = "Researcher"

    item = coordinator._message_to_session_item(
        {
            "from": "child",
            "type": "information",
            "priority": "normal",
            "content": CHATGPT_TRANSCRIPT_CONTENT,
        }
    )

    content = str(item["content"])

    assert "<analysis>" not in content
    assert "</analysis>" not in content
    assert "<channel>" not in content
    assert "</channel>" not in content
    assert "<final>" not in content
    assert "</final>" not in content
    assert "checked target" in content
    assert "done" in content
