"""SDK-native state for Strix's addressable agent graph."""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast


if TYPE_CHECKING:
    from agents.items import TResponseInputItem
    from agents.memory import Session


logger = logging.getLogger(__name__)

Status = Literal["running", "waiting", "completed", "stopped", "crashed", "failed"]


@dataclass(slots=True)
class AgentRuntime:
    session: Session | None = None
    task: asyncio.Task[Any] | None = None
    stream: Any | None = None
    interrupt_on_message: bool = False
    wake: asyncio.Event = field(default_factory=asyncio.Event)


class AgentCoordinator:
    """Single owner for graph state, SDK runtimes, messages, and resume snapshots."""

    def __init__(self) -> None:
        self.statuses: dict[str, Status] = {}
        self.parent_of: dict[str, str | None] = {}
        self.names: dict[str, str] = {}
        self.metadata: dict[str, dict[str, Any]] = {}
        self.pending_counts: dict[str, int] = {}
        self.runtimes: dict[str, AgentRuntime] = {}
        self._lock = asyncio.Lock()
        self._snapshot_path: Path | None = None
        self.is_shutting_down = False
        self._budget_stopped = False

    def set_snapshot_path(self, path: Path) -> None:
        self._snapshot_path = path

    def mark_shutting_down(self) -> None:
        self.is_shutting_down = True

    @property
    def budget_stopped(self) -> bool:
        return self._budget_stopped

    async def trigger_budget_stop(self) -> None:
        """Signal a scan-wide budget stop and wake every parked agent so it exits."""
        async with self._lock:
            self._budget_stopped = True
            for runtime in self.runtimes.values():
                runtime.wake.set()

    async def register(
        self,
        agent_id: str,
        name: str,
        parent_id: str | None,
        *,
        task: str | None = None,
        skills: list[str] | None = None,
    ) -> None:
        async with self._lock:
            self.statuses[agent_id] = "running"
            self.parent_of[agent_id] = parent_id
            self.names[agent_id] = name
            self.pending_counts.setdefault(agent_id, 0)
            self.metadata[agent_id] = {
                "task": task or "",
                "skills": list(skills or []),
            }
            self.runtimes.setdefault(agent_id, AgentRuntime())
        logger.info("agent.register %s (%s) parent=%s", agent_id, name, parent_id or "-")
        await self._maybe_snapshot()

    async def attach_runtime(
        self,
        agent_id: str,
        *,
        session: Session | None = None,
        task: asyncio.Task[Any] | None = None,
        interrupt_on_message: bool | None = None,
    ) -> None:
        async with self._lock:
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            if session is not None:
                runtime.session = session
            if task is not None:
                runtime.task = task
            if interrupt_on_message is not None:
                runtime.interrupt_on_message = interrupt_on_message

    async def mark_running(self, agent_id: str) -> None:
        async with self._lock:
            if agent_id in self.statuses:
                self.statuses[agent_id] = "running"
        await self._maybe_snapshot()

    async def park_waiting(self, agent_id: str) -> None:
        await self.set_status(agent_id, "waiting")

    async def set_status(self, agent_id: str, status: Status | str) -> None:
        async with self._lock:
            if agent_id not in self.statuses:
                return
            self.statuses[agent_id] = status  # type: ignore[assignment]
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            runtime.wake.set()
        logger.info("agent.status %s=%s", agent_id, status)
        await self._maybe_snapshot()

    async def send(self, target_agent_id: str, message: dict[str, Any]) -> bool:
        """Deliver a user/peer message by appending it to the target SDK session."""
        async with self._lock:
            if target_agent_id not in self.statuses:
                logger.debug("agent.send dropped unknown target=%s", target_agent_id)
                return False
            runtime = self.runtimes.setdefault(target_agent_id, AgentRuntime())
            session = runtime.session
            stream = runtime.stream
            interrupt = runtime.interrupt_on_message
        if session is None:
            logger.warning(
                "agent.send dropped target=%s because its SDK session is not attached",
                target_agent_id,
            )
            return False
        try:
            await session.add_items([self._message_to_session_item(message)])
        except Exception:
            logger.exception(
                "agent.send failed to append to SDK session target=%s",
                target_agent_id,
            )
            return False
        async with self._lock:
            self.pending_counts[target_agent_id] = self.pending_counts.get(target_agent_id, 0) + 1
            self.runtimes.setdefault(target_agent_id, AgentRuntime()).wake.set()
        if stream is not None and interrupt:
            stream.cancel(mode="immediate")
        await self._maybe_snapshot()
        return True

    async def wait_for_message(self, agent_id: str) -> None:
        while True:
            async with self._lock:
                if self._budget_stopped or self.pending_counts.get(agent_id, 0) > 0:
                    return
                wake = self.runtimes.setdefault(agent_id, AgentRuntime()).wake
                wake.clear()
            await wake.wait()

    async def consume_pending(
        self,
        agent_id: str,
        *,
        include_items: bool = False,
    ) -> tuple[int, list[Any]]:
        async with self._lock:
            count = self.pending_counts.get(agent_id, 0)
            self.pending_counts[agent_id] = 0
            session = self.runtimes.get(agent_id, AgentRuntime()).session
        if count <= 0:
            return 0, []
        await self._maybe_snapshot()
        if not include_items or session is None:
            return count, []
        items = await session.get_items()
        return count, list(items[-count:])

    async def request_stop(self, agent_id: str) -> None:
        async with self._lock:
            if agent_id not in self.statuses:
                return
            self.statuses[agent_id] = "stopped"
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            runtime.wake.set()
            stream = runtime.stream
        if stream is not None:
            stream.cancel(mode="after_turn")
        await self._maybe_snapshot()

    async def cancel_descendants(self, agent_id: str) -> None:
        tasks = []
        async with self._lock:
            for aid in reversed(self._subtree_order_locked(agent_id)):
                task = self.runtimes.get(aid, AgentRuntime()).task
                if task is not None and not task.done():
                    tasks.append(task)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def cancel_descendants_graceful(self, agent_id: str) -> None:
        async with self._lock:
            order = self._subtree_order_locked(agent_id)
        for aid in reversed(order):
            await self.request_stop(aid)
        await self._maybe_snapshot()

    async def attach_stream(
        self,
        agent_id: str,
        stream: Any,
    ) -> None:
        async with self._lock:
            self.runtimes.setdefault(agent_id, AgentRuntime()).stream = stream

    async def detach_stream(
        self,
        agent_id: str,
        stream: Any,
    ) -> None:
        async with self._lock:
            runtime = self.runtimes.setdefault(agent_id, AgentRuntime())
            if runtime.stream is stream:
                runtime.stream = None

    async def active_agents_except(self, agent_id: str) -> list[dict[str, Any]]:
        async with self._lock:
            return [
                {
                    "agent_id": aid,
                    "name": self.names.get(aid, aid),
                    "status": status,
                    "parent_id": self.parent_of.get(aid),
                }
                for aid, status in self.statuses.items()
                if aid != agent_id and status in {"running", "waiting"}
            ]

    async def graph_snapshot(
        self,
    ) -> tuple[dict[str, str | None], dict[str, Status], dict[str, str]]:
        async with self._lock:
            return dict(self.parent_of), dict(self.statuses), dict(self.names)

    def _message_to_session_item(self, message: dict[str, Any]) -> TResponseInputItem:
        sender = str(message.get("from", "unknown"))
        content = str(message.get("content", ""))
        if sender == "user":
            return cast("TResponseInputItem", {"role": "user", "content": content})
        sender_name = self.names.get(sender, sender)
        msg_type = message.get("type", "information")
        priority = message.get("priority", "normal")
        return cast(
            "TResponseInputItem",
            {
                "role": "user",
                "content": (
                    f"[Message from {sender_name} ({sender}) | type={msg_type} "
                    f"| priority={priority}]\n{content}"
                ),
            },
        )

    def _subtree_order_locked(self, agent_id: str) -> list[str]:
        queue = [agent_id]
        order: list[str] = []
        while queue:
            aid = queue.pop()
            order.append(aid)
            queue.extend(child for child, parent in self.parent_of.items() if parent == aid)
        return order

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return {
                "statuses": dict(self.statuses),
                "parent_of": dict(self.parent_of),
                "names": dict(self.names),
                "metadata": {aid: dict(md) for aid, md in self.metadata.items()},
                "pending_counts": dict(self.pending_counts),
            }

    async def restore(self, snap: dict[str, Any]) -> None:
        async with self._lock:
            self.statuses = dict(snap.get("statuses", {}))
            self.parent_of = dict(snap.get("parent_of", {}))
            self.names = dict(snap.get("names", {}))
            self.metadata = {aid: dict(md) for aid, md in snap.get("metadata", {}).items()}
            self.pending_counts = dict(snap.get("pending_counts", {}))
            for aid in self.statuses:
                self.runtimes.setdefault(aid, AgentRuntime())

    async def _maybe_snapshot(self) -> None:
        path = self._snapshot_path
        if path is None:
            return
        try:
            data = await self.snapshot()
            payload = json.dumps(data, ensure_ascii=False, default=str)
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(path.parent),
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp:
                tmp.write(payload)
                tmp_path = Path(tmp.name)
            tmp_path.replace(path)
        except Exception:
            logger.exception("coordinator snapshot to %s failed", path)


def coordinator_from_context(ctx: dict[str, Any]) -> AgentCoordinator | None:
    coordinator = ctx.get("coordinator")
    return coordinator if isinstance(coordinator, AgentCoordinator) else None
