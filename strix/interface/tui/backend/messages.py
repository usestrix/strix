"""Confirmed message delivery for non-Textual interactive clients."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import TYPE_CHECKING, Any, Literal


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)

DeliveryOutcome = Literal["delivered", "not_delivered", "delivery_unknown"]


def deliver_user_message_to_agent(
    *,
    coordinator: Any,
    loop: asyncio.AbstractEventLoop | None,
    live_view: Any,
    target_agent_id: str,
    message: str,
    notify_changed: Callable[[], None] | None = None,
    wait_for_delivery: bool = False,
    timeout: float = 10.0,
) -> DeliveryOutcome:
    """Deliver a user steering message to an agent and report a truthful outcome.

    When ``wait_for_delivery`` is True and the deadline expires before the
    coroutine begins committing to ``coordinator.send``, the coroutine is
    cancelled under a lock so it can never enqueue late and ``"not_delivered"``
    is returned. If the deadline expires after ``coordinator.send`` has already
    started, ``"delivery_unknown"`` is returned so callers do not treat an
    in-flight or accepted message as a confirmed rejection.
    """
    if loop is None or loop.is_closed():
        return "not_delivered"

    state_lock = threading.Lock()
    state = "pending"

    def _mark_cancelled() -> None:
        nonlocal state
        state = "cancelled"

    async def deliver() -> bool:
        nonlocal state
        with state_lock:
            if state == "cancelled":
                return False
            state = "committing"

        delivered = bool(
            await coordinator.send(
                target_agent_id,
                {"from": "user", "content": message, "type": "instruction"},
            )
        )
        with state_lock:
            state = "delivered" if delivered else "rejected"
        if delivered:
            live_view.record_user_message(target_agent_id, message)
            if notify_changed is not None:
                notify_changed()
        return delivered

    coro = deliver()
    try:
        future = asyncio.run_coroutine_threadsafe(coro, loop)
    except RuntimeError:
        coro.close()
        logger.exception("TUI user message delivery failed")
        return "not_delivered"

    if not wait_for_delivery:
        future.add_done_callback(_log_delivery_failure)
        return "delivered"

    return _await_delivery_future(
        future,
        state_lock=state_lock,
        get_state=lambda: state,
        set_cancelled=_mark_cancelled,
        target_agent_id=target_agent_id,
        timeout=timeout,
    )


def _await_delivery_future(
    future: Any,
    *,
    state_lock: threading.Lock,
    get_state: Callable[[], str],
    set_cancelled: Callable[[], None],
    target_agent_id: str,
    timeout: float,
) -> DeliveryOutcome:
    try:
        return "delivered" if bool(future.result(timeout=timeout)) else "not_delivered"
    except TimeoutError:
        cancelled = False
        with state_lock:
            current = get_state()
            if current == "pending":
                set_cancelled()
                cancelled = True
            elif current == "delivered":
                return "delivered"
            elif current == "rejected":
                return "not_delivered"
        if cancelled:
            future.cancel()
            logger.warning(
                "TUI user message delivery timed out before dispatch; cancelled target=%s",
                target_agent_id,
            )
            return "not_delivered"
        logger.warning(
            "TUI user message delivery timed out while in flight; outcome unknown target=%s",
            target_agent_id,
        )
        future.add_done_callback(_log_delivery_failure)
        return "delivery_unknown"
    except Exception:
        logger.exception("TUI user message delivery failed")
        with state_lock:
            return "delivered" if get_state() == "delivered" else "not_delivered"


def send_user_message_to_agent(
    *,
    coordinator: Any,
    loop: asyncio.AbstractEventLoop | None,
    live_view: Any,
    target_agent_id: str,
    message: str,
    notify_changed: Callable[[], None] | None = None,
    wait_for_delivery: bool = False,
    timeout: float = 10.0,
) -> bool:
    return (
        deliver_user_message_to_agent(
            coordinator=coordinator,
            loop=loop,
            live_view=live_view,
            target_agent_id=target_agent_id,
            message=message,
            notify_changed=notify_changed,
            wait_for_delivery=wait_for_delivery,
            timeout=timeout,
        )
        == "delivered"
    )


def _log_delivery_failure(future: Any) -> None:
    if future.cancelled():
        return
    try:
        delivered = bool(future.result())
    except Exception:
        logger.exception("TUI user message delivery failed")
        return
    if not delivered:
        logger.warning("TUI user message was not persisted to the SDK session")
