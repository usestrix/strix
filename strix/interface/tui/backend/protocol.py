"""Versioned JSON protocol shared with the Go TUI."""

from __future__ import annotations

from typing import Any


PROTOCOL_VERSION = 5
PROTOCOL_CAPABILITIES = (
    "state-revisions",
    "collection-deltas",
    "structured-command-errors",
    "agents-collection",
    "safety-approvals",
)

# Commands and control messages are intentionally small. Event and finding
# history uses a separate bounded collection stream so a resumed run can be
# larger than any individual frame.
MAX_COMMAND_BYTES = 64 * 1024
MAX_COLLECTION_FRAME_BYTES = 4 * 1024 * 1024


class ProtocolHandshakeError(RuntimeError):
    """Raised before the Go TUI is activated when protocol negotiation fails."""


def envelope(
    message_type: str,
    payload: dict[str, Any],
    *,
    request_id: str | None = None,
) -> dict[str, Any]:
    message: dict[str, Any] = {
        "version": PROTOCOL_VERSION,
        "type": message_type,
        "payload": payload,
    }
    if request_id:
        message["request_id"] = request_id
    return message
