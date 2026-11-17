"""Per-run registry of objects the test owns — mirrored to {state_dir}/test_objects.json.

Agents register what they create on the target; the scan seeds the accounts it
was given. The action-approval guard reads it to tell the test's own objects
from pre-existing ones.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

_MIN_IDENTIFIER_CHARS = 3
_MAX_IDENTIFIER_CHARS = 200
_MAX_MATCHES = 20
_ISSUED_IDENTIFIER_RE = re.compile(r"[0-9@]")

# A bare 201 status in tool output, not one inside an address, version or id.
_CREATED_RE = re.compile(r"(?<![\w.,:/-])201(?![\w.,:/-])")
_REGISTRATION_REMINDER = (
    "Note: this output shows HTTP 201 Created. If this test just created objects on the "
    "target, your next call must be register_test_object with every identifier returned, "
    "all in one call. Register identifiers only, never secrets, tokens or passwords. "
    "Ignore this if nothing was created or they are already registered."
)

_objects: dict[str, dict[str, Any]] = {}
_lock = threading.RLock()
_path: Path | None = None


def hydrate_test_objects_from_disk(state_dir: Path) -> None:
    global _path  # noqa: PLW0603
    _path = state_dir / "test_objects.json"
    with _lock:
        _objects.clear()
        if not _path.exists():
            return
        try:
            data = json.loads(_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception("test_objects.json at %s is unreadable; starting empty", _path)
            return
        # The file can sit where the agent writes, so nothing in it is taken as provisioned;
        # the scan seeds its provisioned accounts again on every start.
        for identifier, entry in data.items() if isinstance(data, dict) else ():
            if isinstance(entry, dict) and _ISSUED_IDENTIFIER_RE.search(str(identifier)):
                _objects[str(identifier)] = {**entry, "source": "agent"}


def _persist() -> None:
    if _path is None:
        return
    try:
        _path.parent.mkdir(parents=True, exist_ok=True)
        tmp = _path.with_name(f".{_path.name}.tmp")
        tmp.write_text(json.dumps(_objects, ensure_ascii=False), encoding="utf-8")
        tmp.replace(_path)
    except OSError:
        logger.exception("test objects persist to %s failed", _path)


def register(identifier: str, kind: str, source: str, agent_id: str | None = None) -> bool:
    """Add one identifier; return False when it is unusable."""
    identifier = identifier.strip()
    if not _MIN_IDENTIFIER_CHARS <= len(identifier) <= _MAX_IDENTIFIER_CHARS:
        return False
    # An agent's entry must name one object the target issued (an id, an email, a numbered
    # name). A bare word such as "users" or "admin" names a whole table, route or role.
    if source == "agent" and not _ISSUED_IDENTIFIER_RE.search(identifier):
        return False
    with _lock:
        _objects.setdefault(
            identifier,
            {
                "kind": kind.strip() or "object",
                "source": source,
                "agent_id": agent_id,
                "created_at": datetime.now(UTC).isoformat(),
            },
        )
        _persist()
    return True


def seed_provisioned_accounts(instructions: str) -> int:
    """Register the accounts named in a structured credentials block.

    Credentials written as prose cannot be told from the rest of the instructions,
    so the agent registers those itself before it first uses them.
    """
    names = re.findall(r"<username>\s*([^<\s][^<]*?)\s*</username>", instructions or "")
    return sum(register(name, "account", "provisioned") for name in names)


def matching_test_objects(text: str) -> list[dict[str, str]]:
    """Registered identifiers that appear in ``text`` as whole tokens."""
    with _lock:
        entries = list(_objects.items())
    matches = []
    for identifier, entry in entries:
        if re.search(rf"(?<![\w@.-]){re.escape(identifier)}(?![\w@-])", text):
            matches.append(
                {"identifier": identifier, "kind": entry["kind"], "source": entry["source"]}
            )
        if len(matches) >= _MAX_MATCHES:
            break
    return matches


def with_registration_reminder(result: Any) -> Any:
    """Append a registration reminder to shell output that reports a 201 Created."""
    if isinstance(result, str) and _CREATED_RE.search(result):
        return f"{result}\n{_REGISTRATION_REMINDER}"
    return result


@function_tool(timeout=30)
async def register_test_object(ctx: RunContextWrapper, identifiers: list[str], kind: str) -> str:
    """Record objects you just created on the target as this test's own.

    Call this right after a create succeeds (an account you registered, a
    record, file, role, key or tenant you added), with the identifiers the
    target returned. Later actions on registered objects are recognized as
    work on test data. Register only what this test created; never an object
    that existed before the test or belongs to someone else.

    Args:
        identifiers: IDs, emails, usernames or names exactly as the target uses them.
            Identifiers only, never secrets, tokens or passwords. A bare word with no
            digit or "@" (a table, route or role name) is not accepted.
        kind: What they are, e.g. "account", "record", "file", "role".
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    agent_id = inner.get("agent_id") if isinstance(inner.get("agent_id"), str) else None

    def _run() -> list[str]:
        return [i for i in identifiers if register(i, kind, "agent", agent_id)]

    added = await asyncio.to_thread(_run)
    return json.dumps({"success": bool(added), "registered": added})
