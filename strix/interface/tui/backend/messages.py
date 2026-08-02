"""Confirmed message delivery for non-Textual interactive clients."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)


def send_user_message_to_agent(
    *,
    coordinator: Any,
    loop: asyncio.AbstractEventLoop | None,
    live_view: Any,
    target_agent_id: str,
    message: str,
    notify_changed: Callable[[], None] | None = None,
    wait_for_delivery: bool = False,
) -> bool:
    if loop is None or loop.is_closed():
        return False

    async def deliver() -> bool:
        delivered = bool(
            await coordinator.send(
                target_agent_id,
                {"from": "user", "content": message, "type": "instruction"},
            )
        )
        if delivered:
            live_view.record_user_message(target_agent_id, message)
            if notify_changed is not None:
                notify_changed()
        return delivered

    future = asyncio.run_coroutine_threadsafe(deliver(), loop)
    if wait_for_delivery:
        try:
            return bool(future.result(timeout=10))
        except Exception:
            logger.exception("TUI user message delivery failed")
            return False
    future.add_done_callback(_log_delivery_failure)
    return True


def _log_delivery_failure(future: Any) -> None:
    try:
        delivered = bool(future.result())
    except Exception:
        logger.exception("TUI user message delivery failed")
        return
    if not delivered:
        logger.warning("TUI user message was not persisted to the SDK session")
