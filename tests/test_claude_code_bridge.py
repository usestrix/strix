"""Bridge translation, exercised against recorded ``claude -p`` transcripts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, cast

import pytest
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from strix.config import claude_bridge


if TYPE_CHECKING:
    from agents.items import ModelResponse, TResponseInputItem
    from agents.tool import Tool


FIXTURES = Path(__file__).parent / "fixtures" / "claude_code"


def _tool_output(blocks: list[dict[str, Any]]) -> TResponseInputItem:
    """A ``function_call_output`` whose output is a list of raw content blocks.

    The SDK's ``FunctionCallOutput`` TypedDict declares ``output`` as a plain
    string, so a block list has to be cast in; the runtime item really does carry
    one when a tool returns mixed text and images.
    """
    return cast(
        "TResponseInputItem",
        {"type": "function_call_output", "call_id": "c1", "output": blocks},
    )


def _fixture(name: str) -> dict[str, Any]:
    lines = (FIXTURES / name).read_text(encoding="utf-8").split("\n")
    return claude_bridge.parse_transcript(lines)


def _decode(name: str) -> ModelResponse:
    return claude_bridge.decode_result(_fixture(name))


def _assistant_text(response: ModelResponse) -> str:
    """The assistant prose from a decoded turn, narrowed out of the output union."""
    message = response.output[0]
    assert isinstance(message, ResponseOutputMessage)
    block = message.content[0]
    assert isinstance(block, ResponseOutputText)
    return block.text


def _tool_calls(response: ModelResponse) -> list[ResponseFunctionToolCall]:
    """Just the function calls, narrowed out of the output union."""
    return [item for item in response.output if isinstance(item, ResponseFunctionToolCall)]


def test_decode_simple_text() -> None:
    response = _decode("simple_text.jsonl")
    assert len(response.output) == 1
    assert _assistant_text(response).startswith("Reconnaissance complete")
    # input_tokens folds both cache counters in, matching what LiteLLM's Anthropic
    # transformation reports for the same model on the metered route: 1200 raw
    # + 29225 cache reads + 24303 cache writes.
    assert response.usage.input_tokens == 54_728
    assert response.usage.output_tokens == 45
    assert response.usage.total_tokens == 54_773
    assert response.usage.input_tokens_details.cached_tokens == 29225
    assert response.usage.input_tokens_details.cache_write_tokens == 24303


def test_usage_folds_cache_tokens_like_litellm() -> None:
    # Regression guard for a ~50x undercount, with the numbers taken from a real
    # `claude -p` turn: Anthropic excludes both cache counters from input_tokens,
    # and litellm's Anthropic transformation folds them back in. A turn on
    # claude-code/ must report what the same turn on anthropic/ would.
    raw = {
        "is_error": False,
        "structured_output": {"text": "ok", "tool_calls": []},
        "usage": {
            "input_tokens": 3,
            "cache_creation_input_tokens": 7253,
            "cache_read_input_tokens": 0,
            "output_tokens": 140,
            "output_tokens_details": {"thinking_tokens": 36},
        },
    }
    usage = claude_bridge.decode_result(raw).usage
    assert usage.input_tokens == 7256
    assert usage.total_tokens == 7396
    assert usage.output_tokens_details.reasoning_tokens == 36


def test_usage_ignores_a_cache_excluding_total_tokens() -> None:
    # A `total_tokens` supplied by the CLI would carry Anthropic's cache-excluding
    # meaning; honouring it reopens exactly the undercount the fold closes.
    raw = {
        "is_error": False,
        "structured_output": {"text": "", "tool_calls": []},
        "usage": {
            "input_tokens": 10,
            "cache_read_input_tokens": 990,
            "output_tokens": 5,
            "total_tokens": 15,
        },
    }
    assert claude_bridge.decode_result(raw).usage.total_tokens == 1005


def test_usage_survives_a_malformed_payload() -> None:
    # The usage block is CLI stdout, so it is untrusted input. An unreadable field
    # must degrade to zero rather than fail a turn that already produced a valid
    # result -- `int("not a number")` would raise straight through the run loop.
    raw = {
        "is_error": False,
        "structured_output": {"text": "ok", "tool_calls": []},
        "usage": {
            "input_tokens": "not a number",
            "cache_read_input_tokens": {"nested": 1},
            "cache_creation_input_tokens": float("nan"),
            "output_tokens": -5,
        },
    }
    usage = claude_bridge.decode_result(raw).usage
    assert usage.input_tokens == 0
    assert usage.output_tokens == 0
    assert usage.total_tokens == 0


def test_result_cost_rejects_non_finite_values() -> None:
    # json.loads accepts the non-standard `Infinity` and `NaN` literals, and an
    # infinite cost handed to the ledger would trip the budget guard permanently.
    assert claude_bridge.result_cost({"total_cost_usd": float("inf")}) is None
    assert claude_bridge.result_cost({"total_cost_usd": float("nan")}) is None


def test_result_cost_reads_the_cli_total() -> None:
    assert claude_bridge.result_cost({"total_cost_usd": 0.046686}) == pytest.approx(0.046686)
    # Absent, zero, or non-numeric means "nothing to record", not "free".
    assert claude_bridge.result_cost({}) is None
    assert claude_bridge.result_cost({"total_cost_usd": 0}) is None
    assert claude_bridge.result_cost({"total_cost_usd": "0.15"}) is None
    # bool is an int subclass; True must not read as a $1 charge.
    assert claude_bridge.result_cost({"total_cost_usd": True}) is None


def test_decode_tool_request() -> None:
    response = _decode("tool_request.jsonl")
    calls = _tool_calls(response)
    assert [c.name for c in calls] == ["shell", "browser"]
    assert json.loads(calls[0].arguments) == {"command": "nmap -sV 10.0.0.1"}
    # Every emitted call gets a stable id shared between id and call_id.
    assert calls[0].call_id == calls[0].id
    assert calls[0].call_id != calls[1].call_id


def test_decode_skips_non_json_lines() -> None:
    response = _decode("noisy.jsonl")
    assert _assistant_text(response) == "done"


def test_decode_rate_limit_raises_retryable() -> None:
    with pytest.raises(claude_bridge.ClaudeStreamError) as excinfo:
        _decode("error_ratelimit.jsonl")
    assert excinfo.value.status_code == 429


def test_missing_result_line_raises() -> None:
    with pytest.raises(claude_bridge.ClaudeStreamError):
        claude_bridge.parse_transcript(['{"type": "system", "subtype": "init"}'])


def test_entitlement_error_is_not_retryable() -> None:
    # Observed verbatim on a Max account whose org had Claude Code subscription
    # access turned off. It arrives with no api_error_status, so an untagged error
    # would hit the statusless retry fallback: five attempts with 2s..90s backoff,
    # per turn, per agent, for something a second attempt cannot clear.
    result = {
        "is_error": True,
        "subtype": "success",
        "result": (
            "Your organization has disabled Claude subscription access for Claude Code "
            "- Use an Anthropic API key instead, or ask your admin to enable access"
        ),
    }
    with pytest.raises(claude_bridge.ClaudeStreamError) as excinfo:
        claude_bridge.decode_result(result)
    assert excinfo.value.status_code == 403

    # A transient failure must stay untagged so the statusless fallback still runs.
    assert claude_bridge._error_status({"result": "some transient provider hiccup"}) is None


def test_error_status_inferred_from_message() -> None:
    result = {"is_error": True, "result": "API Error: Overloaded, please retry"}
    with pytest.raises(claude_bridge.ClaudeStreamError) as excinfo:
        claude_bridge.decode_result(result)
    assert excinfo.value.status_code == 529


def test_structured_output_falls_back_to_result_string() -> None:
    result = {
        "type": "result",
        "is_error": False,
        "result": '{"text": "hi", "tool_calls": []}',
        "usage": {"input_tokens": 5, "output_tokens": 1},
    }
    response = claude_bridge.decode_result(result)
    assert _assistant_text(response) == "hi"


def test_mcp_prefixed_tool_names_are_stripped() -> None:
    result = {
        "is_error": False,
        "structured_output": {
            "text": "",
            "tool_calls": [{"name": "mcp__strix__shell", "arguments": {"command": "ls"}}],
        },
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }
    response = claude_bridge.decode_result(result)
    calls = _tool_calls(response)
    assert calls[0].name == "shell"


class _FakeTool:
    name = "shell"
    description = "Run a shell command in the sandbox"
    params_json_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {"command": {"type": "string"}},
    }


def _fake_tools() -> list[Tool]:
    """``_FakeTool`` as the SDK's Tool union; build_content only duck-types it."""
    return [cast("Tool", _FakeTool())]


def _prompt_text(
    system: str | None,
    items: Any,
    tools: list[Tool],
    *,
    parallel_tool_calls: bool = True,
) -> str:
    """Only the prose of a built turn, for assertions about wording."""
    return "".join(
        block["text"]
        for block in claude_bridge.build_content(
            system,
            cast("list[TResponseInputItem]", items),
            tools,
            parallel_tool_calls=parallel_tool_calls,
        )
        if block["type"] == "text"
    )


def _image_blocks(system: str | None, items: Any, tools: list[Tool]) -> list[dict[str, Any]]:
    """Only the image blocks of a built turn, in order."""
    return [
        block
        for block in claude_bridge.build_content(
            system, cast("list[TResponseInputItem]", items), tools
        )
        if block["type"] == "image"
    ]


def test_build_prompt_includes_history_tools_and_task() -> None:
    prompt = _prompt_text(
        "You are a pentester.",
        [
            {"role": "user", "content": "scan the target"},
            {"type": "function_call", "name": "shell", "arguments": '{"command": "nmap x"}'},
            {"type": "function_call_output", "call_id": "c1", "output": "22/tcp open"},
        ],
        _fake_tools(),
    )
    assert "You are a pentester." in prompt
    assert "shell" in prompt
    assert "scan the target" in prompt
    assert "nmap x" in prompt
    assert "22/tcp open" in prompt
    assert "tool_calls" in prompt  # the task instruction naming the reply shape


def test_toolless_prompt_asks_for_the_answer_not_an_agent_step() -> None:
    # Strix calls this backend two ways. A turn with tools is an agent step and
    # must reply in the {text, tool_calls} envelope; a turn with tools=[] is a
    # one-shot completion (dedupe, preflight) whose caller parses the reply. Give
    # the second kind the agent framing and the model narrates a step instead of
    # answering -- which is why dedupe never found the JSON object it asked for.
    agent_turn = _prompt_text("sys", "do the thing", _fake_tools())
    assert "tool_calls" in agent_turn

    completion = _prompt_text("Reply with JSON.", "compare these", [])
    assert "tool_calls" not in completion
    assert "Answer the request above directly" in completion


def test_toolless_reply_keeps_the_callers_own_json() -> None:
    # A one-shot completion answers with the caller's shape, often a JSON object.
    # Reading that as the {text, tool_calls} envelope finds no "text" key and
    # reports an empty response, discarding the answer.
    answer = '{"is_duplicate": false, "duplicate_id": "", "confidence": 0.9}'
    response = claude_bridge.decode_result({"is_error": False, "result": answer})
    assert _assistant_text(response) == answer

    # An actual envelope is still unwrapped.
    enveloped = claude_bridge.decode_result(
        {"is_error": False, "result": '{"text": "hello", "tool_calls": []}'}
    )
    assert _assistant_text(enveloped) == "hello"


def test_build_prompt_string_input() -> None:
    assert "just a string" in _prompt_text(None, "just a string", [])


def test_message_wraps_the_content_as_a_stream_json_user_turn() -> None:
    message = claude_bridge.build_message(None, "hello", [])
    assert message["type"] == "user"
    assert message["message"]["role"] == "user"
    assert message["message"]["content"][0]["type"] == "text"


def test_non_parallel_turn_asks_for_a_single_tool_call() -> None:
    # parallel_tool_calls=False is what every other Strix route sends its provider.
    assert "Request at most one tool" in _prompt_text(
        "sys", "go", _fake_tools(), parallel_tool_calls=False
    )
    assert "Request only tools you need" in _prompt_text("sys", "go", _fake_tools())


def test_image_tool_result_is_carried_as_an_image_block() -> None:
    # The transport sends stream-json, so a browser/visual tool result travels as
    # a real image block beside its text rather than as a placeholder.
    items = [
        _tool_output(
            [
                {"type": "output_text", "text": "page loaded"},
                {"type": "output_image", "image_url": "data:image/png;base64,AAAA"},
            ]
        ),
    ]
    assert "page loaded" in _prompt_text(None, items, [])
    assert _image_blocks(None, items, []) == [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}
    ]
    # The base64 payload rides in the image block, never dumped into the prose.
    assert "AAAA" not in _prompt_text(None, items, [])


def test_anthropic_shaped_image_block_is_carried_verbatim() -> None:
    items = [
        _tool_output(
            [
                {
                    "type": "image",
                    "source": {"type": "base64", "media_type": "image/webp", "data": "BBBB"},
                }
            ]
        )
    ]
    assert _image_blocks(None, items, []) == [
        {"type": "image", "source": {"type": "base64", "media_type": "image/webp", "data": "BBBB"}}
    ]


def test_images_keep_their_place_in_the_conversation() -> None:
    items = [
        {"role": "user", "content": "look"},
        _tool_output([{"type": "input_image", "image_url": "data:image/png;base64,AAAA"}]),
        {"role": "assistant", "content": "done"},
    ]
    kinds = [
        block["type"]
        for block in claude_bridge.build_content(None, cast("list[TResponseInputItem]", items), [])
    ]
    # text (history up to the image), image, then text (the rest and the task).
    assert kinds == ["text", "image", "text"]


@pytest.mark.parametrize(
    "block",
    [
        # A remote URL is refused on purpose: forwarding it would have Anthropic's
        # servers fetch it, which on a pentest run reaches into the target network.
        {"type": "input_image", "image_url": "https://target.internal/shot.png"},
        {"type": "input_image", "image_url": {"url": "https://target.internal/shot.png"}},
        {"type": "image", "source": {"type": "url", "url": "https://target.internal/shot.png"}},
        # Not an image format the API accepts inline.
        {"type": "input_image", "image_url": "data:image/tiff;base64,AAAA"},
        # Malformed data URL.
        {"type": "input_image", "image_url": "data:image/png,AAAA"},
        {"type": "input_image", "image_url": "not-a-url"},
        {"type": "input_image"},
    ],
)
def test_uncarriable_image_is_marked_not_dropped(block: dict[str, Any]) -> None:
    # Whatever cannot travel must still be announced, so the model does not
    # narrate having inspected a screenshot it never received.
    items = [_tool_output([block])]
    assert _image_blocks(None, items, []) == []
    assert "not readable by this backend" in _prompt_text(None, items, [])


def test_oversized_image_is_marked_not_carried() -> None:
    huge = "A" * (5 * 1024 * 1024 + 1)
    items = [_tool_output([{"type": "input_image", "image_url": f"data:image/png;base64,{huge}"}])]
    assert _image_blocks(None, items, []) == []
    assert "not readable by this backend" in _prompt_text(None, items, [])


def test_non_image_block_with_a_source_key_keeps_its_text() -> None:
    # The marker *replaces* the block it fires on, so a detector keyed on the mere
    # presence of `source` or `image_url` silently deletes real tool output. Match
    # the block type, the way compaction.py / sessions.py / live_view.py already do.
    prompt = _prompt_text(
        None,
        [_tool_output([{"type": "output_text", "text": "see app.py:5", "source": "app.py"}])],
        [],
    )
    assert "see app.py:5" in prompt
    assert "image returned by tool" not in prompt


def test_image_blocks_are_detected_by_type() -> None:
    for block_type in ("input_image", "output_image", "image", "image_url"):
        assert claude_bridge._is_image_block({"type": block_type}) is True
    assert claude_bridge._is_image_block({"type": "output_text", "source": "app.py"}) is False
    assert claude_bridge._is_image_block({"type": "input_text", "text": "hi"}) is False


def test_invalid_model_transcript_is_classified_and_surfaced() -> None:
    # Recorded from claude 2.1.251 with a bogus slug: the CLI prints a bracketed
    # diagnostic to stdout before the JSON stream, and reports the failure as a
    # 404 whose wording says neither "not found" nor "invalid".
    result = _fixture("error_invalid_model.jsonl")
    with pytest.raises(claude_bridge.ClaudeStreamError) as exc:
        claude_bridge.decode_result(result)
    assert exc.value.status_code == 404
    assert "issue with the selected model" in str(exc.value)
