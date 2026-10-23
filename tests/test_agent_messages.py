"""Tests for agent-to-session message conversion."""

from __future__ import annotations

from strix.core.agents import AgentCoordinator


CHATGPT_TRANSCRIPT_CONTENT = (
    "<analysis>checked target</analysis>\n<channel>final</channel>\n<final>done</final>"
)
CHATGPT_TRANSCRIPT_CONTENT_WITH_ATTRIBUTES = (
    '<analysis trace="true">checked target</analysis>\n'
    '<channel name="final">final</channel>\n'
    '<final reason="done">done</final>\n'
    "<assistant/>"
)
USER_LITERAL_TAG_CONTENT = (
    "Please preserve this XML-like snippet: "
    '<analysis>literal user content</analysis> and <final reason="example">done</final>'
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


def test_message_to_session_item_preserves_user_literal_tags() -> None:
    coordinator = AgentCoordinator()

    item = coordinator._message_to_session_item(
        {
            "from": "user",
            "content": USER_LITERAL_TAG_CONTENT,
        }
    )

    assert item["content"] == USER_LITERAL_TAG_CONTENT


def test_message_to_session_item_strips_attributed_chatgpt_transcript_tags() -> None:
    coordinator = AgentCoordinator()
    coordinator.names["child"] = "Researcher"

    item = coordinator._message_to_session_item(
        {
            "from": "child",
            "type": "information",
            "priority": "normal",
            "content": CHATGPT_TRANSCRIPT_CONTENT_WITH_ATTRIBUTES,
        }
    )

    content = str(item["content"])

    assert '<analysis trace="true">' not in content
    assert '<channel name="final">' not in content
    assert '<final reason="done">' not in content
    assert "<assistant/>" not in content
    assert "checked target" in content
    assert "done" in content
