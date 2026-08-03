from __future__ import annotations

import argparse
import asyncio
import json
import socket
import struct
from types import SimpleNamespace
from typing import Any, cast

import pytest
from agents.tool import ToolOutputImage

from strix.config.settings import DEFAULT_MAX_TURNS
from strix.interface.tui.backend.controller import TuiController
from strix.interface.tui.backend.projection import terminal_projection
from strix.interface.tui.backend.protocol import (
    MAX_COMMAND_BYTES,
    PROTOCOL_CAPABILITIES,
    PROTOCOL_VERSION,
    ProtocolHandshakeError,
    envelope,
)
from strix.interface.tui.backend.server import TuiBackendServer
from strix.interface.tui.live_view import TuiLiveView


def args() -> argparse.Namespace:
    return argparse.Namespace(
        needs_setup=True,
        targets_info=[],
        instruction=None,
        scan_mode="deep",
        max_budget_usd=None,
        max_turns=DEFAULT_MAX_TURNS,
        scope_mode="auto",
        diff_base=None,
        local_sources=[],
        diff_scope={"active": False},
        user_explicit_instruction=None,
        run_name=None,
    )


async def send_message(connection: socket.socket, message: dict[str, object]) -> None:
    raw = json.dumps(message).encode()
    await asyncio.get_running_loop().sock_sendall(connection, struct.pack(">I", len(raw)) + raw)


async def receive_exactly(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    while size:
        chunk = await asyncio.get_running_loop().sock_recv(connection, size)
        if not chunk:
            raise EOFError
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


async def receive_frame(connection: socket.socket) -> tuple[int, dict[str, Any]]:
    size = struct.unpack(">I", await receive_exactly(connection, 4))[0]
    value = json.loads(await receive_exactly(connection, size))
    assert isinstance(value, dict)
    return size, value


async def receive_message(connection: socket.socket) -> dict[str, Any]:
    return (await receive_frame(connection))[1]


async def start_server(
    server: TuiBackendServer, backend: socket.socket, child: socket.socket
) -> dict[str, Any]:
    start_task = asyncio.create_task(server.start(backend))
    hello = await receive_message(child)
    await send_message(
        child,
        {
            "version": PROTOCOL_VERSION,
            "type": "ready",
            "payload": {"capabilities": list(PROTOCOL_CAPABILITIES)},
        },
    )
    await asyncio.wait_for(start_task, timeout=1)
    return hello


async def receive_until(
    connection: socket.socket,
    message_type: str,
    *,
    request_id: str | None = None,
) -> dict[str, Any]:
    for _ in range(100):
        message = await asyncio.wait_for(receive_message(connection), timeout=2)
        if message.get("type") != message_type:
            continue
        if request_id is not None and message.get("request_id") != request_id:
            continue
        return message
    raise AssertionError(f"did not receive {message_type}")


async def receive_initial_state(connection: socket.socket) -> None:
    state_received = False
    complete: set[str] = set()
    while not state_received or complete != {"agents", "events", "vulnerabilities"}:
        message = await asyncio.wait_for(receive_message(connection), timeout=2)
        if message["type"] == "state":
            state_received = True
        elif message["type"] == "collection_bootstrap":
            payload = message["payload"]
            if payload["done"]:
                complete.add(payload["collection"])


@pytest.mark.asyncio
async def test_server_requires_ready_before_state_or_commands() -> None:
    backend, child = socket.socketpair()
    child.setblocking(False)  # noqa: FBT003
    server = TuiBackendServer(TuiController(args()))
    start_task = asyncio.create_task(server.start(backend))
    try:
        hello = await receive_message(child)
        assert hello == {
            "version": 3,
            "type": "hello",
            "payload": {"capabilities": list(PROTOCOL_CAPABILITIES)},
        }
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(receive_message(child), timeout=0.1)
        assert not start_task.done()

        await send_message(
            child,
            {
                "version": 3,
                "type": "ready",
                "payload": {"capabilities": list(PROTOCOL_CAPABILITIES)},
            },
        )
        await asyncio.wait_for(start_task, timeout=1)
        assert server.activated is True
        assert (await receive_until(child, "state"))["payload"]["revision"] == 1
    finally:
        child.close()
        start_task.cancel()
        await server.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("version", "capabilities"),
    [
        (2, list(PROTOCOL_CAPABILITIES)),
        (3, ["state-revisions"]),
    ],
)
async def test_server_rejects_handshake_mismatch(version: int, capabilities: list[str]) -> None:
    backend, child = socket.socketpair()
    child.setblocking(False)  # noqa: FBT003
    server = TuiBackendServer(TuiController(args()))
    start_task = asyncio.create_task(server.start(backend))
    try:
        await receive_message(child)
        await send_message(
            child,
            {"version": version, "type": "ready", "payload": {"capabilities": capabilities}},
        )
        with pytest.raises(ProtocolHandshakeError, match="mismatch"):
            await asyncio.wait_for(start_task, timeout=1)
        assert server.activated is False
    finally:
        child.close()
        await server.close()


@pytest.mark.asyncio
async def test_server_command_round_trip_over_inherited_socket() -> None:
    backend, child = socket.socketpair()
    child.setblocking(False)  # noqa: FBT003
    server = TuiBackendServer(TuiController(args()))
    await start_server(server, backend, child)
    try:
        await send_message(
            child,
            {
                "version": 3,
                "type": "setup.add_target",
                "request_id": "test-1",
                "payload": {"target": "example.com"},
            },
        )
        result = await receive_until(child, "command_result", request_id="test-1")
        assert result["payload"]["ok"] is True
        assert result["payload"]["command"] == "setup.add_target"
        state = await receive_until(child, "state")
        assert state["payload"]["revision"] >= 1
        assert state["payload"]["state"]["targets"] == ["example.com"]
    finally:
        child.close()
        await server.close()


def test_unicode_heavy_setup_state_stays_within_control_frame_limit() -> None:
    controller = TuiController(args())
    controller.instruction = "🔒" * 10_000
    controller.targets = [f"https://例え.{index}/" + "界" * 500 for index in range(20)]
    controller.error = "失" * 10_000
    controller.messages = [
        {"id": str(index), "text": "警" * 10_000, "level": "warning"} for index in range(10)
    ]
    controller.report_state = cast(
        "Any",
        SimpleNamespace(
            caido_url="https://例え.example/" + "道" * 10_000,
            get_total_llm_usage=lambda: {f"model-{index}": "費" * 10_000 for index in range(20)},
        ),
    )
    server = TuiBackendServer(controller)

    snapshot = controller.snapshot()
    encoded = server._encode(envelope("state", {"revision": 1, "state": snapshot}))

    assert len(encoded) <= MAX_COMMAND_BYTES
    assert "🔒".encode() in encoded
    assert snapshot["projection_truncated"] is True


@pytest.mark.asyncio
async def test_persistence_error_does_not_kill_command_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, child = socket.socketpair()
    child.setblocking(False)  # noqa: FBT003
    controller = TuiController(args())
    calls = 0

    async def handle(command: str, payload: dict[str, Any]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("disk is read-only")
        return {"command": command, "payload": payload}

    monkeypatch.setattr(controller, "handle", handle)
    server = TuiBackendServer(controller)
    await start_server(server, backend, child)
    try:
        for request_id in ("persist-1", "persist-2"):
            await send_message(
                child,
                {
                    "version": 3,
                    "type": "setup.select_model",
                    "request_id": request_id,
                    "payload": {"provider": "openai", "model": "openai/gpt-5"},
                },
            )
            result = await receive_until(child, "command_result", request_id=request_id)
            if request_id == "persist-1":
                assert result["payload"]["error"] == {
                    "code": "persistence_error",
                    "message": "disk is read-only",
                    "retryable": True,
                }
            else:
                assert result["payload"]["ok"] is True
        assert server._reader_task is not None and not server._reader_task.done()
    finally:
        child.close()
        await server.close()


@pytest.mark.asyncio
async def test_invalid_version_error_is_correlated_and_next_command_succeeds() -> None:
    backend, child = socket.socketpair()
    child.setblocking(False)  # noqa: FBT003
    server = TuiBackendServer(TuiController(args()))
    await start_server(server, backend, child)
    try:
        await send_message(
            child,
            {
                "version": 2,
                "type": "setup.add_target",
                "request_id": "bad-version",
                "payload": {"target": "ignored.example"},
            },
        )
        rejected = await receive_until(child, "command_result", request_id="bad-version")
        assert rejected["payload"]["error"]["code"] == "invalid_request"

        await send_message(
            child,
            {
                "version": 3,
                "type": "setup.add_target",
                "request_id": "after-error",
                "payload": {"target": "example.com"},
            },
        )
        accepted = await receive_until(child, "command_result", request_id="after-error")
        assert accepted["payload"]["ok"] is True
    finally:
        child.close()
        await server.close()


@pytest.mark.asyncio
async def test_collection_bootstrap_is_chunked_deltas_are_incremental_and_idle_is_silent() -> None:
    backend, child = socket.socketpair()
    child.setblocking(False)  # noqa: FBT003
    controller = TuiController(args())
    report_state = SimpleNamespace(
        vulnerability_reports=[],
        caido_url=None,
        get_total_llm_usage=dict,
    )
    controller.report_state = cast("Any", report_state)
    content = "x" * (64 * 1024)
    for index in range(80):
        controller.live_view.record_user_message(f"agent-{index}", content)
    server = TuiBackendServer(controller)
    await start_server(server, backend, child)
    try:
        event_frames = 0
        event_count = 0
        complete: set[str] = set()
        state_received = False
        while not (complete == {"agents", "events", "vulnerabilities"} and state_received):
            size, message = await asyncio.wait_for(receive_frame(child), timeout=5)
            if message["type"] == "state":
                state_received = True
            if message["type"] != "collection_bootstrap":
                continue
            payload = message["payload"]
            if payload["collection"] == "events":
                event_frames += 1
                event_count += len(payload["items"])
                assert size <= 4 * 1024 * 1024
            if payload["done"]:
                complete.add(payload["collection"])
        assert event_frames >= 2
        assert event_count == 80

        server.notify_changed()
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(receive_message(child), timeout=0.2)

        controller.live_view.record_user_message("agent-new", "delta")
        controller.notify_changed()
        delta = await receive_until(child, "collection_delta")
        assert delta["payload"]["collection"] == "events"
        assert delta["payload"]["base_revision"] == 1
        assert len(delta["payload"]["operations"]) == 1

        report_state.vulnerability_reports.append(
            {"id": "vuln-0001", "title": "Incremental finding", "severity": "high"}
        )
        controller.notify_changed()
        finding_delta = await receive_until(child, "collection_delta")
        assert finding_delta["payload"]["collection"] == "vulnerabilities"
        assert len(finding_delta["payload"]["operations"]) == 1
    finally:
        child.close()
        await server.close()


@pytest.mark.asyncio
async def test_agents_collection_has_no_state_cap_and_sends_delete_and_resync() -> None:
    backend, child = socket.socketpair()
    child.setblocking(False)  # noqa: FBT003
    controller = TuiController(args())
    for index in range(40):
        controller.live_view.upsert_agent(
            f"agent-{index}",
            name=f"Agent {index}",
            status="running",
        )
    server = TuiBackendServer(controller)
    await start_server(server, backend, child)
    try:
        agents: list[dict[str, Any]] = []
        complete: set[str] = set()
        state: dict[str, Any] | None = None
        while state is None or complete != {"agents", "events", "vulnerabilities"}:
            message = await asyncio.wait_for(receive_message(child), timeout=2)
            if message["type"] == "state":
                state = message["payload"]["state"]
            elif message["type"] == "collection_bootstrap":
                payload = message["payload"]
                if payload["collection"] == "agents":
                    agents.extend(payload["items"])
                if payload["done"]:
                    complete.add(payload["collection"])

        assert "agents" not in state
        assert len(agents) == 40

        controller.live_view.agents.pop("agent-7")
        controller.notify_changed()
        delta = await receive_until(child, "collection_delta")
        assert delta["payload"]["collection"] == "agents"
        assert delta["payload"]["operations"] == [{"op": "delete", "id": "agent-7"}]

        await send_message(
            child,
            {
                "version": 3,
                "type": "collection.resync",
                "request_id": "resync-agents",
                "payload": {"collection": "agents"},
            },
        )
        result = await receive_until(child, "command_result", request_id="resync-agents")
        assert result["payload"]["ok"] is True
        bootstrap = await receive_until(child, "collection_bootstrap")
        assert bootstrap["payload"]["collection"] == "agents"
        assert bootstrap["payload"]["revision"] == 3
        assert len(bootstrap["payload"]["items"]) == 39
    finally:
        child.close()
        await server.close()


@pytest.mark.asyncio
async def test_bootstrap_larger_than_64_mib_has_no_total_message_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = TuiBackendServer(TuiController(args()))
    shared_projection = "x" * (1024 * 1024)
    items = [{"id": f"event-{index}", "content": shared_projection} for index in range(65)]
    frames: list[dict[str, Any]] = []
    encoded_sizes: list[int] = []

    async def capture(message: dict[str, Any]) -> None:
        encoded_sizes.append(len(server._encode(message)))
        frames.append(message)

    monkeypatch.setattr(server, "_send", capture)

    await server._send_collection_frames(
        "collection_bootstrap",
        {"collection": "events", "revision": 1},
        "items",
        items,
    )

    assert sum(len(item["content"]) for item in items) > 64 * 1024 * 1024
    assert len(frames) > 16
    assert max(encoded_sizes) <= 4 * 1024 * 1024
    assert frames[0]["payload"]["cursor"] == 0
    assert frames[-1]["payload"]["next_cursor"] == len(items)
    assert frames[-1]["payload"]["done"] is True


@pytest.mark.asyncio
async def test_oversized_terminal_projection_is_truncated_without_mutating_history() -> None:
    controller = TuiController(args())
    durable = "x" * (2 * 1024 * 1024)
    controller.live_view.record_user_message("agent", durable)

    projected = controller.collection("events")

    assert len(projected[0]["data"]["content"]) < len(durable)
    assert controller.live_view.events[0]["data"]["content"] == durable


def test_terminal_projection_strips_ansi_osc_and_c1_controls() -> None:
    controller = TuiController(args())
    hostile = "safe\x1b[31mred\x1b[0m\x1b]52;c;Y2xpcGJvYXJk\x07\x85tail"
    controller.live_view.record_user_message("agent", hostile)

    projected = controller.collection_snapshot("events")[1][0]["data"]["content"]

    assert projected == "saferedtail"
    assert "\x1b" not in projected

    hostile_mapping = {"header\x1b]52;c;Y2xpcA==\x07": "value"}
    assert list(terminal_projection(hostile_mapping)) == ["header"]
    assert list(TuiBackendServer._sanitize_wire_value(hostile_mapping)) == ["header"]


def test_terminal_event_history_is_bounded_without_changing_durable_sessions() -> None:
    controller = TuiController(args())
    for index in range(10_050):
        controller.live_view.record_user_message("agent", f"message-{index}")

    _cursor, projected = controller.collection_snapshot("events")

    assert len(controller.live_view.events) == 10_000
    assert len(projected) == 5_000
    assert projected[0]["data"]["content"] == "message-5050"
    assert projected[-1]["data"]["content"] == "message-10049"


@pytest.mark.asyncio
async def test_oversized_command_frame_is_rejected_before_payload_read() -> None:
    backend, child = socket.socketpair()
    child.setblocking(False)  # noqa: FBT003
    server = TuiBackendServer(TuiController(args()))
    await start_server(server, backend, child)
    try:
        await asyncio.get_running_loop().sock_sendall(
            child, struct.pack(">I", MAX_COMMAND_BYTES + 1)
        )
        assert server._reader_task is not None
        await asyncio.wait_for(server._reader_task, timeout=1)
        assert server._socket is None
    finally:
        child.close()
        await server.close()


@pytest.mark.asyncio
async def test_server_stops_when_peer_closes() -> None:
    backend, child = socket.socketpair()
    child.setblocking(False)  # noqa: FBT003
    server = TuiBackendServer(TuiController(args()))
    await start_server(server, backend, child)
    child.close()
    try:
        assert server._reader_task is not None
        await asyncio.wait_for(server._reader_task, timeout=1)
    finally:
        await server.close()


def test_image_data_uri_survives_terminal_projection() -> None:
    uri = "data:image/png;base64," + "A" * 100_000
    assert terminal_projection(uri) == uri
    assert terminal_projection({"type": "image", "image_url": uri})["image_url"] == uri

    oversized = "data:image/png;base64," + "A" * (3 * 1024 * 1024)
    assert terminal_projection(oversized) == "[image omitted from terminal projection]"


def test_view_image_tool_output_is_normalized_to_image_dict() -> None:
    uri = "data:image/png;base64," + "B" * 4000
    view = TuiLiveView()
    view._record_tool_output_data(
        "agent",
        {
            "call_id": "c1",
            "tool_name": "view_image",
            "output": ToolOutputImage(type="image", image_url=uri),
        },
    )
    view._record_tool_output_data(
        "agent",
        {
            "call_id": "c2",
            "tool_name": "view_image",
            "output": [{"type": "input_image", "image_url": uri}],
        },
    )
    for event in view.events:
        assert event["data"]["result"] == {"type": "image", "image_url": uri}
