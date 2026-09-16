"""SDK session helpers for Strix agents."""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, cast
from weakref import WeakKeyDictionary

from agents.items import ItemHelpers
from agents.memory import SQLiteSession


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from agents.items import TResponseInputItem
    from agents.memory import Session


logger = logging.getLogger(__name__)


class _PooledConnectionSession(SQLiteSession):
    @contextmanager
    def _locked_connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise RuntimeError("SQLiteSession is closed")
            if self._is_memory_db:
                yield self._shared_connection
                return
            connection = sqlite3.connect(str(self.db_path), check_same_thread=False)
            try:
                yield connection
            finally:
                connection.close()


def open_agent_session(agent_id: str, path: Path) -> SQLiteSession:
    path.parent.mkdir(parents=True, exist_ok=True)
    return _PooledConnectionSession(session_id=agent_id, db_path=path)


async def seed_initial_input(session: Session, initial_input: Any) -> bool:
    """Commit an agent's opening identity/task input before its first run cycle."""
    items = ItemHelpers.input_to_new_input_list(initial_input)
    if not items:
        return False
    async with session_write_lock(session):
        if await session.get_items():
            return False
        await session.add_items(items)
    return True


_IMAGE_REJECTED_TEXT = "[image rejected by the model]"
_IMAGE_ELIDED_TEXT = "[older screenshot elided to bound context memory]"
_INHERITED_IMAGE_TEXT = "[screenshot omitted from inherited context]"


def _output_has_image(item_dict: dict[str, Any]) -> bool:
    return (
        item_dict.get("type") == "function_call_output"
        and isinstance(item_dict.get("output"), list)
        and any(isinstance(b, dict) and b.get("type") == "input_image" for b in item_dict["output"])
    )


def _elided_output(item_dict: dict[str, Any], text: str) -> dict[str, Any]:
    # Replace only image blocks; sibling text blocks are preserved.
    output = item_dict.get("output")
    blocks = output if isinstance(output, list) else []
    return {
        "type": "function_call_output",
        "call_id": item_dict.get("call_id"),
        "output": [
            {"type": "input_text", "text": text}
            if isinstance(block, dict) and block.get("type") == "input_image"
            else block
            for block in blocks
        ],
    }


_session_write_locks: WeakKeyDictionary[Session, asyncio.Lock] = WeakKeyDictionary()


def session_write_lock(session: Session) -> asyncio.Lock:
    """Lock serialising all out-of-band writes to ``session``."""
    lock = _session_write_locks.get(session)
    if lock is None:
        lock = asyncio.Lock()
        _session_write_locks[session] = lock
    return lock


async def _rewrite_session(
    session: Session,
    transform: Callable[[list[Any]], tuple[list[Any], bool]],
) -> bool:
    """Rewrite atomically against SDK writes for SQLite; lock other backends."""
    async with session_write_lock(session):
        if isinstance(session, SQLiteSession):
            return await asyncio.to_thread(_rewrite_sqlite_session, session, transform)
        items = await session.get_items()
        rebuilt, changed = transform(list(items))
        if not changed:
            return False
        rebuilt_items = cast("list[TResponseInputItem]", rebuilt)
        original_items = cast("list[TResponseInputItem]", list(items))
        await session.clear_session()
        try:
            await session.add_items(rebuilt_items)
        except Exception:
            logger.exception("session rewrite failed; restoring original items")
            await session.clear_session()
            await session.add_items(original_items)
            raise
        return True


def _rewrite_sqlite_session(
    session: SQLiteSession,
    transform: Callable[[list[Any]], tuple[list[Any], bool]],
) -> bool:
    # The SDK writes without our asyncio lock. The SQLite write transaction
    # covers read/compare/replace, including writers on another session object.
    # Table names come from the SDK's configured schema, never tool/message input.
    with session._locked_connection() as connection:  # pyright: ignore[reportPrivateUsage]
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                f"SELECT message_data FROM {session.messages_table} "  # noqa: S608  # nosec B608
                "WHERE session_id = ? ORDER BY id ASC",
                (session.session_id,),
            ).fetchall()
            original = [json.loads(row[0]) for row in rows]
            rebuilt, changed = transform(original)
            if changed:
                connection.execute(
                    f"DELETE FROM {session.messages_table} WHERE session_id = ?",  # noqa: S608  # nosec B608
                    (session.session_id,),
                )
                session._insert_items(connection, cast("list[TResponseInputItem]", rebuilt))  # pyright: ignore[reportPrivateUsage]
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        else:
            return changed


async def replace_session_items(
    session: Session,
    new_items: list[Any],
    *,
    expected_len: int | None = None,
) -> bool:
    """Overwrite the session's items, restoring the originals on failure.

    When ``expected_len`` is given, the rewrite is skipped if the session no
    longer has that many items (a concurrent writer changed it), so a slow
    compaction summary can't clobber newer turns.
    """

    def _transform(original: list[Any]) -> tuple[list[Any], bool]:
        if expected_len is not None and len(original) != expected_len:
            logger.warning(
                "skipping session rewrite: expected %d items, found %d",
                expected_len,
                len(original),
            )
            return original, False
        return new_items, new_items != original

    return await _rewrite_session(session, _transform)


async def recover_session_items(session: Session, before: list[Any], replay: list[Any]) -> bool:
    """Merge a full SDK replay once, retaining append-only incoming messages.

    Occurrences are compared by position, never globally deduplicated. If a
    concurrent compaction or divergent SDK write changed the prefix, refuse the
    rewrite rather than guess which events to delete or execute again.
    """

    def _transform(current: list[Any]) -> tuple[list[Any], bool]:
        if current[: len(before)] != before or replay[: len(before)] != before:
            raise ValueError("session history diverged from the pre-run snapshot")
        common = 0
        for left, right in zip(current, replay, strict=False):
            if left != right:
                break
            common += 1
        if common == len(replay):
            return current, False
        tail = current[common:]
        if any(
            not isinstance(item, dict) or cast("dict[str, Any]", item).get("role") != "user"
            for item in tail
        ):
            raise ValueError("session contains divergent generated items; recovery is ambiguous")
        if any(item in replay[common:] for item in tail):
            raise ValueError("incoming message ownership is ambiguous; history retained")
        return replay + tail, True

    return await _rewrite_session(session, _transform)


async def strip_all_images_from_session(session: Session) -> bool:
    """Replace every image tool output with a text placeholder (rejection recovery)."""

    def _transform(items: list[Any]) -> tuple[list[Any], bool]:
        rebuilt: list[Any] = []
        changed = False
        for item in items:
            item_dict = cast("dict[str, Any]", item) if isinstance(item, dict) else None
            if item_dict is not None and _output_has_image(item_dict):
                rebuilt.append(_elided_output(item_dict, _IMAGE_REJECTED_TEXT))
                changed = True
            else:
                rebuilt.append(item)
        return rebuilt, changed

    return await _rewrite_session(session, _transform)


async def enforce_image_budget(session: Session, max_images: int) -> bool:
    """Keep only the most recent ``max_images`` image outputs; elide older ones."""
    if max_images < 0:
        return False

    def _transform(items: list[Any]) -> tuple[list[Any], bool]:
        image_indices = [
            i
            for i, item in enumerate(items)
            if isinstance(item, dict) and _output_has_image(cast("dict[str, Any]", item))
        ]
        if len(image_indices) <= max_images:
            return items, False
        to_elide = set(image_indices[: len(image_indices) - max_images])
        rebuilt = [
            _elided_output(cast("dict[str, Any]", item), _IMAGE_ELIDED_TEXT)
            if i in to_elide
            else item
            for i, item in enumerate(items)
        ]
        return rebuilt, True

    return await _rewrite_session(session, _transform)


def scrub_images_from_items(items: list[Any]) -> list[Any]:
    """Return a copy of ``items`` with every image block replaced by text."""

    def _scrub(obj: Any) -> Any:
        if isinstance(obj, dict):
            if obj.get("type") == "input_image":
                return {"type": "input_text", "text": _INHERITED_IMAGE_TEXT}
            return {k: _scrub(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_scrub(v) for v in obj]
        return obj

    return [_scrub(item) for item in items]
