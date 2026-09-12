"""Private framed IPC connection used by the Go TUI."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import struct
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from strix.interface.tui.backend.projection import sanitize_terminal_text
from strix.interface.tui.backend.protocol import (
    MAX_COLLECTION_FRAME_BYTES,
    MAX_COMMAND_BYTES,
    PROTOCOL_CAPABILITIES,
    PROTOCOL_VERSION,
    ProtocolHandshakeError,
    envelope,
)


if TYPE_CHECKING:
    import socket

    from strix.interface.tui.backend.controller import TuiController

logger = logging.getLogger(__name__)

_HEADER = struct.Struct(">I")
_HANDSHAKE_TIMEOUT = 10.0
_COLLECTIONS = ("agents", "events", "vulnerabilities")
_COLLECTION_ITEM_LIMITS = {"events": 5_000, "vulnerabilities": 1_000}
# Leave enough room for the collection envelope and cursor metadata.
_COLLECTION_PAYLOAD_TARGET = MAX_COLLECTION_FRAME_BYTES - 16 * 1024


class _MessageTooLargeError(ValueError):
    pass


@dataclass
class _CollectionState:
    revision: int = 0
    bootstrapped: bool = False
    order: list[str] = field(default_factory=list)
    items: dict[str, dict[str, Any]] = field(default_factory=dict)
    fingerprints: dict[str, str] = field(default_factory=dict)
    source_cursor: int | None = None


class TuiBackendServer:
    """Serve one TUI child over an authenticated, connected socket."""

    def __init__(self, controller: TuiController) -> None:
        self.controller = controller
        self._socket: socket.socket | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._broadcast_event = asyncio.Event()
        self._broadcast_task: asyncio.Task[None] | None = None
        self._write_lock = asyncio.Lock()
        self._sync_lock = asyncio.Lock()
        self._state_revision = 0
        self._state_fingerprint = ""
        self._collections = {name: _CollectionState() for name in _COLLECTIONS}
        self._seen_request_ids: set[str] = set()
        self._request_id_order: deque[str] = deque()
        self.activated = False
        controller.set_change_callback(self.notify_changed)

    async def start(self, connection: socket.socket) -> None:
        """Negotiate protocol v3 before activating command or state traffic."""
        if self._socket is not None:
            raise RuntimeError("TUI backend is already started")
        connection.setblocking(False)  # noqa: FBT003
        self._socket = connection
        try:
            await self._send(envelope("hello", {"capabilities": list(PROTOCOL_CAPABILITIES)}))
            await asyncio.wait_for(self._receive_ready(), timeout=_HANDSHAKE_TIMEOUT)
        except TimeoutError as exc:
            raise ProtocolHandshakeError("Timed out waiting for TUI protocol ready") from exc
        except (EOFError, ConnectionError, OSError) as exc:
            raise ProtocolHandshakeError(f"TUI closed during protocol handshake: {exc}") from exc
        except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ProtocolHandshakeError(str(exc)) from exc

        self.activated = True
        self._reader_task = asyncio.create_task(self._read_loop())
        self._broadcast_task = asyncio.create_task(self._broadcast_loop())
        self.notify_changed()

    async def close(self) -> None:
        tasks = [task for task in (self._reader_task, self._broadcast_task) if task is not None]
        for task in tasks:
            task.cancel()
        for task in tasks:
            if task is asyncio.current_task():
                continue
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._reader_task = None
        self._broadcast_task = None
        self._close_socket()

    def _close_socket(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def notify_changed(self) -> None:
        if self.activated:
            self._broadcast_event.set()

    async def _read_exactly(self, size: int) -> bytes:
        connection = self._socket
        if connection is None:
            raise ConnectionError("TUI IPC connection is closed")
        loop = asyncio.get_running_loop()
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = await loop.sock_recv(connection, remaining)
            if not chunk:
                raise EOFError("TUI IPC peer closed")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    async def _read_frame(self, maximum: int) -> bytes:
        (size,) = _HEADER.unpack(await self._read_exactly(_HEADER.size))
        if size == 0 or size > maximum:
            # Reject the length before allocating or reading its payload.
            raise ConnectionError(f"invalid TUI IPC frame size: {size}")
        return await self._read_exactly(size)

    async def _receive_ready(self) -> None:
        raw = await self._read_frame(MAX_COMMAND_BYTES)
        message = json.loads(raw.decode("utf-8"))
        if not isinstance(message, dict):
            raise TypeError("TUI ready message must be an object")
        if message.get("version") != PROTOCOL_VERSION:
            raise ValueError(
                f"TUI protocol mismatch: expected v{PROTOCOL_VERSION}, "
                f"received v{message.get('version')}"
            )
        if message.get("type") != "ready":
            raise ValueError("TUI protocol handshake expected ready")
        payload = message.get("payload")
        if not isinstance(payload, dict):
            raise TypeError("TUI ready payload must be an object")
        capabilities = payload.get("capabilities")
        if capabilities != list(PROTOCOL_CAPABILITIES):
            raise ValueError("TUI protocol capability mismatch")

    async def _read_loop(self) -> None:
        try:
            while True:
                raw = await self._read_frame(MAX_COMMAND_BYTES)
                response, resync = await self._handle_message(raw)
                if response is not None:
                    await self._send_command_response(response)
                if resync is not None:
                    await self._resync_collection(resync)
        except asyncio.CancelledError:
            raise
        except (EOFError, ConnectionError, OSError):
            self._close_socket()

    @staticmethod
    def _decode_message(raw: bytes) -> tuple[str, str, dict[str, object]]:
        message = json.loads(raw.decode("utf-8"))
        if not isinstance(message, dict):
            raise TypeError("message must be an object")
        request_id = message.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("command request_id must be a non-empty string")
        if message.get("version") != PROTOCOL_VERSION:
            raise ValueError(f"unsupported protocol version; expected {PROTOCOL_VERSION}")
        command = message.get("type")
        payload = message.get("payload", {})
        if not isinstance(command, str) or not isinstance(payload, dict):
            raise TypeError("invalid command envelope")
        if len(command) > 128:
            raise ValueError("command name exceeds 128 characters")
        return request_id, command, payload

    @staticmethod
    def _structured_error(exc: Exception) -> dict[str, object]:
        if isinstance(exc, OSError):
            return {"code": "persistence_error", "message": str(exc), "retryable": True}
        if isinstance(exc, TypeError | ValueError | json.JSONDecodeError | UnicodeDecodeError):
            return {"code": "invalid_request", "message": str(exc), "retryable": False}
        if isinstance(exc, RuntimeError):
            return {"code": "command_failed", "message": str(exc), "retryable": False}
        logger.exception("Unhandled TUI command error", exc_info=exc)
        return {
            "code": "internal_error",
            "message": "The command failed unexpectedly",
            "retryable": True,
        }

    async def _handle_message(self, raw: bytes) -> tuple[dict[str, Any] | None, str | None]:
        request_id: str | None = None
        command = ""
        resync: str | None = None
        try:
            preliminary = json.loads(raw.decode("utf-8"))
            if isinstance(preliminary, dict):
                raw_request_id = preliminary.get("request_id")
                if isinstance(raw_request_id, str) and raw_request_id:
                    request_id = raw_request_id
                raw_command = preliminary.get("type")
                if isinstance(raw_command, str):
                    command = raw_command[:128]
            request_id, command, payload = self._decode_message(raw)
            if request_id in self._seen_request_ids:
                raise ValueError(f"duplicate request_id: {request_id}")  # noqa: TRY301
            self._seen_request_ids.add(request_id)
            self._request_id_order.append(request_id)
            if len(self._request_id_order) > 10_000:
                self._seen_request_ids.discard(self._request_id_order.popleft())
            if command == "collection.resync":
                collection = payload.get("collection")
                if not isinstance(collection, str) or collection not in _COLLECTIONS:
                    choices = ", ".join(_COLLECTIONS)
                    raise ValueError(f"collection must be one of: {choices}")  # noqa: TRY301
                result: dict[str, Any] = {"collection": collection, "resyncing": True}
                resync = collection
            else:
                result = await self.controller.handle(command, payload)
            response = envelope(
                "command_result",
                {"ok": True, "command": command, "result": result},
                request_id=request_id,
            )
        except Exception as exc:  # noqa: BLE001 - command failures are protocol results
            if request_id is None:
                # A malformed envelope without an ID cannot be correlated. Keep
                # the reader alive and wait for the next valid command.
                logger.warning("Ignoring uncorrelatable TUI command: %s", exc)
                return None, None
            response = envelope(
                "command_result",
                {
                    "ok": False,
                    "command": command,
                    "error": self._structured_error(exc),
                },
                request_id=request_id,
            )
        return response, resync

    def _encode(self, message: dict[str, Any]) -> bytes:
        raw = json.dumps(
            self._sanitize_wire_value(message),
            default=str,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        maximum = (
            MAX_COLLECTION_FRAME_BYTES
            if message.get("type") in {"collection_bootstrap", "collection_delta"}
            else MAX_COMMAND_BYTES
        )
        if len(raw) > maximum:
            raise _MessageTooLargeError(f"TUI IPC message exceeds {maximum} bytes")
        return raw

    @classmethod
    def _sanitize_wire_value(cls, value: Any) -> Any:
        if isinstance(value, str):
            return sanitize_terminal_text(value)
        if isinstance(value, dict):
            return {
                sanitize_terminal_text(str(key)): cls._sanitize_wire_value(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._sanitize_wire_value(item) for item in value]
        if isinstance(value, tuple):
            return [cls._sanitize_wire_value(item) for item in value]
        return value

    async def _send(self, message: dict[str, Any]) -> None:
        connection = self._socket
        if connection is None:
            raise ConnectionError("TUI IPC connection is closed")
        raw = self._encode(message)
        framed = _HEADER.pack(len(raw)) + raw
        async with self._write_lock:
            await asyncio.get_running_loop().sock_sendall(connection, framed)

    async def _send_command_response(self, response: dict[str, Any]) -> None:
        try:
            await self._send(response)
        except _MessageTooLargeError:
            request_id = response.get("request_id")
            payload = response.get("payload")
            command = payload.get("command", "") if isinstance(payload, dict) else ""
            await self._send(
                envelope(
                    "command_result",
                    {
                        "ok": False,
                        "command": command,
                        "error": {
                            "code": "result_too_large",
                            "message": "Command result exceeds the terminal frame limit",
                            "retryable": False,
                        },
                    },
                    request_id=request_id if isinstance(request_id, str) else None,
                )
            )

    @staticmethod
    def _fingerprint(value: Any) -> str:
        return json.dumps(value, default=str, sort_keys=True, separators=(",", ":"))

    async def _send_state_if_changed(self) -> None:
        state = self.controller.snapshot()
        fingerprint = self._fingerprint(state)
        if fingerprint == self._state_fingerprint:
            return
        revision = self._state_revision + 1
        await self._send(envelope("state", {"revision": revision, "state": state}))
        self._state_revision = revision
        self._state_fingerprint = fingerprint

    @staticmethod
    def _collection_values(
        items: list[dict[str, Any]],
    ) -> tuple[list[str], dict[str, dict[str, Any]], dict[str, str]]:
        order: list[str] = []
        by_id: dict[str, dict[str, Any]] = {}
        fingerprints: dict[str, str] = {}
        for item in items:
            item_id = item.get("id")
            if not isinstance(item_id, str) or not item_id:
                continue
            order.append(item_id)
            by_id[item_id] = item
            fingerprints[item_id] = TuiBackendServer._fingerprint(item)
        return order, by_id, fingerprints

    async def _send_collection_frames(
        self,
        message_type: str,
        fixed: dict[str, Any],
        field_name: str,
        values: list[dict[str, Any]],
    ) -> None:
        cursor = 0
        if not values:
            payload = {**fixed, "cursor": 0, "next_cursor": 0, "done": True, field_name: []}
            await self._send(envelope(message_type, payload))
            return

        while cursor < len(values):
            chunk: list[dict[str, Any]] = []
            next_cursor = cursor
            empty_payload = {
                **fixed,
                "cursor": cursor,
                "next_cursor": cursor,
                "done": False,
                field_name: [],
            }
            estimated_size = len(
                json.dumps(
                    envelope(message_type, empty_payload),
                    default=str,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            while next_cursor < len(values):
                item = values[next_cursor]
                item_size = len(
                    json.dumps(item, default=str, separators=(",", ":")).encode("utf-8")
                )
                if estimated_size + item_size + 1 > _COLLECTION_PAYLOAD_TARGET and chunk:
                    break
                chunk.append(item)
                estimated_size += item_size + 1
                next_cursor += 1
            payload = {
                **fixed,
                "cursor": cursor,
                "next_cursor": next_cursor,
                "done": next_cursor == len(values),
                field_name: chunk,
            }
            await self._send(envelope(message_type, payload))
            cursor = next_cursor

    async def _send_collection_bootstrap(
        self,
        name: str,
        items: list[dict[str, Any]] | None = None,
    ) -> None:
        state = self._collections[name]
        source_cursor: int | None = None
        if items is None:
            source_cursor, projected = self.controller.collection_snapshot(name)
        else:
            projected = items
        order, by_id, fingerprints = self._collection_values(projected)
        revision = state.revision + 1
        await self._send_collection_frames(
            "collection_bootstrap",
            {"collection": name, "revision": revision},
            "items",
            [by_id[item_id] for item_id in order],
        )
        state.revision = revision
        state.bootstrapped = True
        state.order = order
        state.items = by_id
        state.fingerprints = fingerprints
        state.source_cursor = source_cursor

    async def _send_collection_if_changed(self, name: str) -> None:
        state = self._collections[name]
        if name == "events" and state.bootstrapped and state.source_cursor is not None:
            next_cursor, changed = self.controller.collection_changes(
                name,
                state.source_cursor,
            )
            if next_cursor == state.source_cursor:
                return
            operations: list[dict[str, Any]] = []
            for item in changed:
                item_id = item.get("id")
                if not isinstance(item_id, str) or not item_id:
                    continue
                operations.append({"op": "upsert", "item": item})
                if item_id not in state.items:
                    state.order.append(item_id)
                state.items[item_id] = item
                state.fingerprints[item_id] = self._fingerprint(item)
            limit = _COLLECTION_ITEM_LIMITS[name]
            while len(state.order) > limit:
                removed_id = state.order.pop(0)
                state.items.pop(removed_id, None)
                state.fingerprints.pop(removed_id, None)
                operations.append({"op": "delete", "id": removed_id})
            if operations:
                revision = state.revision + 1
                await self._send_collection_frames(
                    "collection_delta",
                    {
                        "collection": name,
                        "base_revision": state.revision,
                        "revision": revision,
                    },
                    "operations",
                    operations,
                )
                state.revision = revision
            state.source_cursor = next_cursor
            return
        projected = self.controller.collection(name)
        order, by_id, fingerprints = self._collection_values(projected)
        if not state.bootstrapped:
            await self._send_collection_bootstrap(
                name,
                None if name == "events" else projected,
            )
            return
        if order == state.order and fingerprints == state.fingerprints:
            return

        retained = [item_id for item_id in state.order if item_id in by_id]
        expected_order = retained + [item_id for item_id in order if item_id not in state.items]
        if order != expected_order:
            await self._send_collection_bootstrap(name, projected)
            return

        operations = [
            {"op": "delete", "id": item_id} for item_id in state.order if item_id not in by_id
        ] + [
            {"op": "upsert", "item": by_id[item_id]}
            for item_id in order
            if fingerprints[item_id] != state.fingerprints.get(item_id)
        ]
        if not operations:
            await self._send_collection_bootstrap(name, projected)
            return

        revision = state.revision + 1
        await self._send_collection_frames(
            "collection_delta",
            {
                "collection": name,
                "base_revision": state.revision,
                "revision": revision,
            },
            "operations",
            operations,
        )
        state.revision = revision
        state.order = order
        state.items = by_id
        state.fingerprints = fingerprints

    async def _flush_updates(self) -> None:
        async with self._sync_lock:
            await self._send_state_if_changed()
            for name in _COLLECTIONS:
                await self._send_collection_if_changed(name)

    async def _resync_collection(self, name: str) -> None:
        async with self._sync_lock:
            await self._send_collection_bootstrap(name)

    async def _broadcast_loop(self) -> None:
        try:
            while True:
                await self._broadcast_event.wait()
                self._broadcast_event.clear()
                await asyncio.sleep(0.05)
                await self._flush_updates()
        except asyncio.CancelledError:
            raise
        except (_MessageTooLargeError, ValueError):
            logger.exception("TUI projection could not be framed")
            self._close_socket()
        except (ConnectionError, OSError):
            self._close_socket()
