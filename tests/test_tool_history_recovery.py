"""Crash recovery must preserve occurrences, not concatenate full SDK histories."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from agents import Agent, Runner, function_tool
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.run import RunConfig
from openai import APIConnectionError, AsyncOpenAI

from strix.config.models import _NonStreamingModel
from strix.core.execution import _salvage_stream_to_session
from strix.core.sessions import open_agent_session, replace_session_items


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


def _call(call_id: str = "call_a") -> dict[str, Any]:
    return {"type": "function_call", "call_id": call_id, "name": "noop", "arguments": "{}"}


def _output(call_id: str = "call_a") -> dict[str, Any]:
    return {"type": "function_call_output", "call_id": call_id, "output": "ok"}


async def test_full_replay_without_new_events_does_not_duplicate(tmp_path: Path) -> None:
    session = open_agent_session("a", tmp_path / "agents.db")
    original = [{"role": "user", "content": "task"}, _call(), _output()]
    try:
        await session.add_items(original)
        for _ in range(3):
            await _salvage_stream_to_session(
                session, original, SimpleNamespace(to_input_list=lambda: original), "a"
            )
        assert await session.get_items() == original
    finally:
        session.close()


@pytest.mark.parametrize("persisted_count", [0, 1, 2])
async def test_partial_sdk_persistence_and_late_message_are_preserved(
    tmp_path: Path, persisted_count: int
) -> None:
    session = open_agent_session("a", tmp_path / "agents.db")
    original = [{"role": "user", "content": "task"}]
    generated = [_call(), _output()]
    late = {"role": "user", "content": "new instructions"}
    replay = original + generated
    try:
        await session.add_items(original + generated[:persisted_count] + [late])
        stream = SimpleNamespace(to_input_list=lambda: replay)
        await _salvage_stream_to_session(session, original, stream, "a")
        await _salvage_stream_to_session(session, original, stream, "a")
        assert await session.get_items() == [*replay, late]
    finally:
        session.close()


async def test_recovery_preserves_repeated_legitimate_messages(tmp_path: Path) -> None:
    session = open_agent_session("a", tmp_path / "agents.db")
    message = {"role": "user", "content": "continue"}
    original = [message, message]
    replay = [*original, _call(), _output()]
    try:
        await session.add_items([*original, message, message])
        await _salvage_stream_to_session(
            session, original, SimpleNamespace(to_input_list=lambda: replay), "a"
        )
        assert await session.get_items() == [*replay, message, message]
    finally:
        session.close()


async def test_divergent_compacted_session_is_not_overwritten(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    session = open_agent_session("a", tmp_path / "agents.db")
    original = [{"role": "user", "content": "old"}]
    current = [{"role": "user", "content": "compacted"}]
    try:
        await session.add_items(current)
        await _salvage_stream_to_session(
            session, original, SimpleNamespace(to_input_list=lambda: [*original, _call()]), "a"
        )
        assert await session.get_items() == current
        assert "salvaging crashed run history failed" in caplog.text
    finally:
        session.close()


async def test_parallel_sdk_writes_are_not_lost(tmp_path: Path) -> None:
    db = tmp_path / "agents.db"
    session = open_agent_session("a", db)
    # A different SDK session instance bypasses Strix's per-instance asyncio lock.
    writer = open_agent_session("a", db)
    original = [{"role": "user", "content": "task"}]
    replay = [*original, _call(), _output()]
    late = [{"role": "user", "content": f"message {i}"} for i in range(20)]
    try:
        await session.add_items(original)
        await asyncio.gather(
            _salvage_stream_to_session(
                session, original, SimpleNamespace(to_input_list=lambda: replay), "a"
            ),
            *(writer.add_items([item]) for item in late),
        )
        stored = await session.get_items()
        assert stored[:3] == replay
        assert sorted(item["content"] for item in stored[3:]) == sorted(
            item["content"] for item in late
        )
    finally:
        session.close()
        writer.close()


async def test_real_sdk_failure_salvage_and_resume_never_repeat_a_tool(tmp_path: Path) -> None:
    """Exercise SDK session persistence and Chat conversion, with no network."""
    requests: list[dict[str, Any]] = []
    executed: list[int] = []

    @function_tool
    def noop(n: int) -> str:
        executed.append(n)
        return f"result-{n}"

    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append(body)
        turn = len(requests)
        if turn == 3:
            raise RuntimeError("synthetic stream failure")
        message: dict[str, Any] = {"role": "assistant", "content": "finished"}
        if turn < 3:
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": f"call_{turn}",
                        "type": "function",
                        "function": {"name": "noop", "arguments": json.dumps({"n": turn})},
                    }
                ],
            }
        return httpx.Response(
            200,
            json={
                "id": f"completion-{turn}",
                "object": "chat.completion",
                "created": 0,
                "model": "offline",
                "choices": [
                    {
                        "index": 0,
                        "message": message,
                        "finish_reason": "tool_calls" if turn < 3 else "stop",
                    }
                ],
            },
        )

    session = open_agent_session("a", tmp_path / "agents.db")
    client = AsyncOpenAI(
        api_key="offline",
        base_url="http://offline.invalid/v1",
        max_retries=0,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(respond)),
    )
    model = _NonStreamingModel(OpenAIChatCompletionsModel(model="offline", openai_client=client))
    agent = Agent(name="offline", tools=[noop], model=model)
    config = RunConfig(tracing_disabled=True)
    try:
        original = [{"role": "user", "content": "run two noops"}]
        await session.add_items(original)
        stream = Runner.run_streamed(agent, input=[], session=session, run_config=config)
        with pytest.raises(APIConnectionError):
            async for _ in stream.stream_events():
                pass
        assert executed == [1, 2]
        persisted = await session.get_items()
        for _ in range(3):
            await _salvage_stream_to_session(session, original, stream, "a")
        assert await session.get_items() == persisted
        result = await Runner.run(agent, input=[], session=session, run_config=config)
        assert result.final_output == "finished"
        assert executed == [1, 2]
        sent = requests[-1]["messages"]
        assert [m["tool_call_id"] for m in sent if m["role"] == "tool"] == ["call_1", "call_2"]
    finally:
        session.close()
        await client.close()


async def test_sqlite_rewrite_rolls_back_partial_insertion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = open_agent_session("a", tmp_path / "agents.db")
    original = [{"role": "user", "content": "keep me"}]
    insert = session._insert_items

    def fail_after_insert(connection: Any, items: Any) -> None:
        insert(connection, items)
        raise RuntimeError("write failed")

    try:
        await session.add_items(original)
        monkeypatch.setattr(session, "_insert_items", fail_after_insert)
        with pytest.raises(RuntimeError, match="write failed"):
            await replace_session_items(session, [_call()])
        assert await session.get_items() == original
    finally:
        session.close()


@pytest.mark.parametrize("later_turn", [False, True])
async def test_recovery_never_overwrites_divergent_or_later_generated_items(
    tmp_path: Path, later_turn: bool
) -> None:
    session = open_agent_session("a", tmp_path / "agents.db")
    before = [{"role": "user", "content": "task"}]
    replay = [*before, _call(), _output()]
    other = [_call("call_b"), _output("call_b")]
    current = (replay if later_turn else before) + other
    try:
        await session.add_items(current)
        await _salvage_stream_to_session(
            session, before, SimpleNamespace(to_input_list=lambda: replay), "a"
        )
        assert await session.get_items() == current
    finally:
        session.close()


async def test_recovery_transaction_blocks_writer_without_exposing_empty_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "agents.db"
    session, writer = [open_agent_session("a", db) for _ in range(2)]
    entered, attempted, release = threading.Event(), threading.Event(), threading.Event()
    original = [{"role": "user", "content": "task"}]
    replay = [*original, _call(), _output()]
    late = {"role": "user", "content": "late"}
    insert, locked = session._insert_items, writer._locked_connection

    def hold_transaction(connection: Any, items: Any) -> None:
        entered.set()
        if not release.wait(5):
            raise TimeoutError("test did not release transaction")
        insert(connection, items)

    @contextmanager
    def announce_writer() -> Iterator[sqlite3.Connection]:
        attempted.set()
        with locked() as connection:
            yield connection

    tasks: list[asyncio.Task[Any]] = []
    try:
        await session.add_items(original)
        monkeypatch.setattr(session, "_insert_items", hold_transaction)
        monkeypatch.setattr(writer, "_locked_connection", announce_writer)
        tasks.append(
            asyncio.create_task(
                _salvage_stream_to_session(
                    session, original, SimpleNamespace(to_input_list=lambda: replay), "a"
                )
            )
        )
        assert await asyncio.to_thread(entered.wait, 5)
        tasks.append(asyncio.create_task(writer.add_items([late])))
        assert await asyncio.to_thread(attempted.wait, 5)
        # DELETE is uncommitted: a separate reader still sees the original,
        # while the SDK writer waits for the recovery transaction to commit.
        with sqlite3.connect(db) as connection:
            rows = connection.execute(
                "SELECT message_data FROM agent_messages ORDER BY id"
            ).fetchall()
        assert [json.loads(row[0]) for row in rows] == original
        assert not tasks[1].done()
        release.set()
        await asyncio.gather(*tasks)
        assert await session.get_items() == [*replay, late]
    finally:
        release.set()
        await asyncio.gather(*tasks, return_exceptions=True)
        for item in (session, writer):
            item.close()
