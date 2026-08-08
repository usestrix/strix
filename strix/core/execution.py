"""Execution loop for addressable SDK-backed Strix agents."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

import litellm
from agents import RunConfig, Runner
from agents.exceptions import AgentsException, MaxTurnsExceeded, UserError
from agents.sandbox.errors import ExecTransportError
from docker import errors as docker_errors  # type: ignore[import-untyped, unused-ignore]
from openai import (
    APIConnectionError,
    APIError,
    APITimeoutError,
)

from strix.config import codex
from strix.core.hooks import (
    BudgetExceededError,
    BudgetPausedError,
    SubagentBudgetReservedError,
)
from strix.core.inputs import child_initial_input
from strix.core.sessions import (
    enforce_image_budget,
    open_agent_session,
    replace_session_items,
    seed_initial_input,
    strip_all_images_from_session,
)
from strix.llm.compaction import is_context_overflow, maybe_compact


if TYPE_CHECKING:
    from pathlib import Path

    from agents.items import TResponseInputItem
    from agents.lifecycle import RunHooks
    from agents.memory import Session, SQLiteSession
    from agents.result import RunResultBase

    from strix.core.agents import AgentCoordinator, Status


logger = logging.getLogger(__name__)

StreamEventSink = Callable[[str, Any], None]

_INPUT_REJECTION_CODES = frozenset({400, 404, 422})
_MAX_COMPACTIONS_PER_CYCLE = 2


class ProviderRefusalError(AgentsException):
    """Raised when a provider returns a structured refusal instead of an exception."""


def _structured_provider_refusal(result: Any) -> str | None:
    for item in getattr(result, "new_items", ()) or ():
        raw_item = getattr(item, "raw_item", None)
        for content in getattr(raw_item, "content", ()) or ():
            if getattr(content, "type", None) != "refusal":
                continue
            refusal = getattr(content, "refusal", None)
            if isinstance(refusal, str) and refusal.strip():
                return refusal.strip()
            return "The model provider refused this request."
    return None


def _run_config_model(run_config: RunConfig) -> str | None:
    return run_config.model if isinstance(run_config.model, str) else None


def _agent_instructions(agent: Any) -> str:
    instructions = getattr(agent, "instructions", None)
    return instructions if isinstance(instructions, str) else ""


def _agent_tools_text(agent: Any) -> str:
    parts: list[str] = []
    for tool in getattr(agent, "tools", []) or []:
        name = getattr(tool, "name", "")
        description = getattr(tool, "description", "") or ""
        schema = getattr(tool, "params_json_schema", "") or ""
        parts.append(f"{name} {description} {schema}")
    return "\n".join(parts)


async def _compact_session(
    agent: Any, session: Session, run_config: RunConfig, *, force: bool
) -> bool:
    model = _run_config_model(run_config)
    if session is None or model is None:
        return False
    return await maybe_compact(
        session,
        model=model,
        instructions=_agent_instructions(agent),
        tools_text=_agent_tools_text(agent),
        force=force,
    )


_MAX_TRANSIENT_MODEL_RETRIES = 5
_TRANSIENT_MODEL_RETRY_BASE_DELAY_S = 2.0
_TRANSIENT_MODEL_RETRY_MAX_DELAY_S = 90.0


def _model_error_status_code(exc: BaseException) -> int | None:
    code = getattr(exc, "status_code", None)
    return code if isinstance(code, int) else None


def _is_transient_model_error(exc: BaseException) -> bool:
    if codex.is_content_guardrail_error(exc):
        return False
    if isinstance(
        exc, APITimeoutError | APIConnectionError | TimeoutError | ConnectionError | OSError
    ):
        return True
    code = _model_error_status_code(exc)
    if code is not None:
        return bool(litellm._should_retry(code))
    return isinstance(exc, APIError)


def _transient_model_retry_delay(attempt: int) -> float:
    delay = _TRANSIENT_MODEL_RETRY_BASE_DELAY_S * float(2 ** (attempt - 1))
    return min(delay, _TRANSIENT_MODEL_RETRY_MAX_DELAY_S)


async def _salvage_stream_to_session(
    session: Session,
    pre_run_items: list[Any],
    stream: Any,
    agent_id: str,
) -> None:
    """Persist a crashed run's full history so a revived agent loses no context."""
    if stream is None:
        return
    try:
        replay = list(stream.to_input_list())
    except Exception:
        logger.exception("could not build salvage history for %s", agent_id)
        return
    desired = list(pre_run_items) + replay
    if len(desired) <= len(pre_run_items):
        return
    try:
        await replace_session_items(session, desired)
    except Exception:
        logger.exception("salvaging crashed run history failed for %s", agent_id)


async def _seed_and_prepare_first_input(
    session: Session | None, initial_input: Any, *, start_parked: bool
) -> Any:
    """Persist the opening input up front so it survives a first-turn crash."""
    if initial_input and session is not None and not start_parked:
        with contextlib.suppress(Exception):
            if await seed_initial_input(session, initial_input):
                return []
    return initial_input


async def run_agent_loop(
    *,
    agent: Any,
    initial_input: Any,
    run_config: RunConfig,
    context: dict[str, Any],
    max_turns: int,
    coordinator: AgentCoordinator,
    agent_id: str,
    interactive: bool,
    session: Session | None = None,
    start_parked: bool = False,
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> RunResultBase | None:
    await coordinator.attach_runtime(
        agent_id,
        session=session,
        interrupt_on_message=interactive,
    )
    result: RunResultBase | None = None

    first_cycle_input = await _seed_and_prepare_first_input(
        session, initial_input, start_parked=start_parked
    )

    budget_stopped = coordinator.budget_stopped
    reserve_stopped = coordinator.reserve_stopped
    if budget_stopped:
        await coordinator.set_status(agent_id, "stopped")
        raise BudgetExceededError("scan budget reached")
    if reserve_stopped and context.get("parent_id") is not None:
        await coordinator.set_status(agent_id, "stopped")
        raise SubagentBudgetReservedError("scan reached the sub-agent budget reserve")

    if reserve_stopped and start_parked and interactive and context.get("parent_id") is None:
        await coordinator.send(agent_id, _reserve_notice())

    if not (start_parked and interactive):
        with contextlib.suppress(BudgetPausedError):
            result = await _run_until_lifecycle(
                agent,
                coordinator,
                agent_id,
                initial_input=first_cycle_input,
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                session=session,
                interactive=interactive,
                event_sink=event_sink,
                hooks=hooks,
            )

    if not interactive:
        return result

    while True:
        timeout = await _plain_waiting_timeout(coordinator, agent_id)
        try:
            woke = await coordinator.wait_for_message(agent_id, timeout=timeout)
        except asyncio.CancelledError:
            return result

        if coordinator.budget_stopped:
            await coordinator.set_status(agent_id, "stopped")
            raise BudgetExceededError("scan budget reached")

        if coordinator.reserve_stopped and context.get("parent_id") is not None:
            await coordinator.set_status(agent_id, "stopped")
            raise SubagentBudgetReservedError("scan reached the sub-agent budget reserve")

        if woke:
            # Real input is real progress, so the nudge budget starts over. A bare
            # auto-resume is not: it must not hand a wedged agent a fresh budget.
            await coordinator.reset_recovery(agent_id)
            await coordinator.reset_idle_resumes(agent_id)
        else:
            idle_resumes = await coordinator.record_idle_resume(agent_id)
            if idle_resumes >= _MAX_IDLE_AUTO_RESUMES:
                logger.warning(
                    "agent %s auto-resumed %d times without hearing from anyone; "
                    "leaving it parked until a real message arrives",
                    agent_id,
                    idle_resumes,
                )
                await coordinator.park_waiting(agent_id, wait_kind="stalled")
                await _notify_parent_on_stall(coordinator, agent_id)
                continue
            logger.info("agent %s reached its waiting timeout; auto-resuming", agent_id)
            await coordinator.send(
                agent_id,
                {
                    "from": "system",
                    "type": "auto_resume",
                    "content": "Waiting timeout reached. Resuming execution.",
                },
                interrupt=False,
            )

        await coordinator.consume_pending(agent_id)
        with contextlib.suppress(BudgetPausedError):
            result = await _run_until_lifecycle(
                agent,
                coordinator,
                agent_id,
                initial_input=[],
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                session=session,
                interactive=True,
                event_sink=event_sink,
                hooks=hooks,
            )


async def spawn_child_agent(
    *,
    coordinator: AgentCoordinator,
    factory: Any,
    agents_db_path: Path,
    sessions_to_close: list[SQLiteSession],
    run_config: RunConfig,
    max_turns: int,
    interactive: bool,
    parent_ctx: dict[str, Any],
    name: str,
    task: str,
    skills: list[str],
    parent_history: list[Any],
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    parent_id = parent_ctx.get("agent_id")
    if not isinstance(parent_id, str):
        raise TypeError("Parent agent_id missing from context")

    child_id = uuid.uuid4().hex[:8]
    child_agent = factory(name=name, skills=skills)
    await coordinator.register(
        child_id,
        name,
        parent_id,
        task=task,
        skills=skills,
    )

    await _start_child_runner(
        parent_ctx=parent_ctx,
        coordinator=coordinator,
        agents_db_path=agents_db_path,
        sessions_to_close=sessions_to_close,
        run_config=run_config,
        max_turns=max_turns,
        interactive=interactive,
        child_agent=child_agent,
        child_id=child_id,
        name=name,
        parent_id=parent_id,
        task=task,
        initial_input=child_initial_input(
            name=name,
            child_id=child_id,
            parent_id=parent_id,
            task=task,
            parent_history=parent_history,
        ),
        event_sink=event_sink,
        hooks=hooks,
    )

    return {
        "success": True,
        "agent_id": child_id,
        "name": name,
        "parent_id": parent_id,
        "message": f"Spawned '{name}' ({child_id}) running in parallel.",
    }


async def respawn_subagents(
    *,
    coordinator: AgentCoordinator,
    factory: Any,
    agents_db_path: Path,
    sessions_to_close: list[SQLiteSession],
    run_config: RunConfig,
    max_turns: int,
    interactive: bool,
    parent_ctx: dict[str, Any],
    root_id: str,
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> None:
    async with coordinator._lock:
        agents_snapshot = [
            (aid, status, dict(coordinator.metadata.get(aid, {})))
            for aid, status in coordinator.statuses.items()
        ]
        candidates: list[tuple[str, str, str | None, dict[str, Any]]] = []
        for aid, status, md in agents_snapshot:
            if not interactive and status not in {"running", "waiting"}:
                continue
            if coordinator.parent_of.get(aid) is None or aid == root_id:
                continue
            md["_restored_status"] = status
            candidates.append(
                (
                    aid,
                    coordinator.names.get(aid, aid),
                    coordinator.parent_of.get(aid),
                    md,
                )
            )

    for child_id, name, parent_id, md in candidates:
        try:
            restored_status = str(md.get("_restored_status") or "running")
            start_parked = interactive and restored_status != "running"

            if start_parked:
                logger.warning(
                    "respawn %s (%s): starting parked from status=%s",
                    child_id,
                    name,
                    restored_status,
                )

            child_skills = list(md.get("skills") or [])
            child_agent = factory(name=name, skills=child_skills)
            await _start_child_runner(
                parent_ctx=parent_ctx,
                coordinator=coordinator,
                agents_db_path=agents_db_path,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                child_agent=child_agent,
                child_id=child_id,
                name=name,
                parent_id=parent_id,
                task=str(md.get("task", "")),
                initial_input=[],
                start_parked=start_parked,
                event_sink=event_sink,
                hooks=hooks,
            )
            logger.info(
                "respawned %s (%s) parent=%s task_len=%d",
                child_id,
                name,
                parent_id or "-",
                len(md.get("task", "")),
            )
        except Exception:
            logger.exception("respawn %s failed; marking crashed", child_id)
            with contextlib.suppress(Exception):
                await coordinator.set_status(child_id, "crashed")


_INTERACTIVE_TOOL_RECOVERY_LIMIT = 3


async def _run_until_lifecycle(
    agent: Any,
    coordinator: AgentCoordinator,
    agent_id: str,
    *,
    initial_input: Any,
    run_config: RunConfig,
    context: dict[str, Any],
    max_turns: int,
    session: Session | None,
    interactive: bool,
    event_sink: StreamEventSink | None,
    hooks: RunHooks[dict[str, Any]] | None,
) -> RunResultBase | None:
    """Drive an agent until an explicit lifecycle tool settles its status.

    A turn that ends without ``finish_scan``, ``agent_finish``,
    ``respond_to_user``, or ``wait_for_agents`` leaves the agent ``running``:
    plain text never terminates a run and never yields to the user. Such a turn
    is nudged back into a tool call, bounded by a recovery limit.
    """
    result: RunResultBase | None = None
    input_data: Any = initial_input
    recovery_limit = _INTERACTIVE_TOOL_RECOVERY_LIMIT if interactive else max(1, max_turns)

    while True:
        if coordinator.budget_stopped:
            await coordinator.set_status(agent_id, "stopped")
            raise BudgetExceededError("scan budget reached")

        if coordinator.reserve_stopped and context.get("parent_id") is not None:
            await coordinator.set_status(agent_id, "stopped")
            raise SubagentBudgetReservedError("scan reached the sub-agent budget reserve")

        if interactive:
            result = await _run_cycle_parked(
                agent,
                coordinator,
                agent_id,
                input_data=input_data,
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                session=session,
                event_sink=event_sink,
                hooks=hooks,
            )
        else:
            result = await _run_cycle(
                agent,
                coordinator,
                agent_id,
                input_data=input_data,
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                session=session,
                interactive=False,
                event_sink=event_sink,
                hooks=hooks,
            )

        status = await _agent_status(coordinator, agent_id)
        if status != "running":
            await coordinator.reset_recovery(agent_id)
            return result

        recoveries = await coordinator.record_recovery(agent_id)
        logger.warning(
            "agent %s ended a turn without a lifecycle tool call (interactive=%s); "
            "forcing tool continuation (%d/%d): %s",
            agent_id,
            interactive,
            recoveries,
            recovery_limit,
            _final_output_preview(result),
        )

        if recoveries >= recovery_limit:
            return await _exhausted_recovery(coordinator, agent_id, result, interactive=interactive)

        input_data = await _append_tool_required_message(
            session=session,
            context=context,
            attempt=recoveries,
            limit=recovery_limit,
            interactive=interactive,
        )


async def _exhausted_recovery(
    coordinator: AgentCoordinator,
    agent_id: str,
    result: RunResultBase | None,
    *,
    interactive: bool,
) -> RunResultBase | None:
    """Settle an agent that never recovered into a tool call.

    Interactive runs park instead of dying: a human is attached and can message
    any agent, so the scan stays resumable. Autonomous runs have nobody to
    resume them, so they fail loudly.
    """
    if not interactive:
        await coordinator.set_status(agent_id, "crashed")
        await notify_parent_on_terminal(coordinator, agent_id, "crashed")
        raise MaxTurnsExceeded(
            "Agent exhausted recovery attempts without calling finish_scan or agent_finish."
        )

    logger.warning(
        "agent %s exhausted tool-call recovery attempts; parking until a message arrives",
        agent_id,
    )
    await coordinator.park_waiting(agent_id, wait_kind="stalled")
    # A parked child owes its parent a completion report it can no longer send. The
    # parent is an agent, not a watching human, so nothing else tells it to stop
    # waiting and it burns its full timeout on a message that is never coming.
    await _notify_parent_on_stall(coordinator, agent_id)
    return result


_WAITING_AUTO_RESUME_TIMEOUT_S = 300.0

# An agent that parks again after every auto-resume makes no progress, so stop
# spending a model turn per timeout and leave it parked for a real message.
_MAX_IDLE_AUTO_RESUMES = 3


async def _plain_waiting_timeout(
    coordinator: AgentCoordinator,
    agent_id: str,
) -> float | None:
    """Auto-resume timeout for a parked agent; None waits until a message arrives.

    Driven by what the agent is waiting on, not by where it sits in the graph:
    the user can message any agent, so an agent awaiting a human parks
    indefinitely whether or not it is the root. Only an agent awaiting other
    agents is re-checked on a timer, and only until it has spent its idle
    budget re-parking without hearing anything.
    """
    async with coordinator._lock:
        status = coordinator.statuses.get(agent_id)
        has_error = agent_id in coordinator.errors
        runtime = coordinator.runtimes.get(agent_id)
        gated = runtime.user_wake_required if runtime is not None else False
        wait_kind = coordinator.wait_kinds.get(agent_id)
        idle_resumes = coordinator.idle_resume_counts.get(agent_id, 0)
    if status != "waiting" or has_error or gated:
        return None
    if wait_kind != "agents" or idle_resumes >= _MAX_IDLE_AUTO_RESUMES:
        return None
    return _WAITING_AUTO_RESUME_TIMEOUT_S


async def _run_cycle_parked(
    agent: Any,
    coordinator: AgentCoordinator,
    agent_id: str,
    *,
    input_data: Any,
    run_config: RunConfig,
    context: dict[str, Any],
    max_turns: int,
    session: Session | None,
    event_sink: StreamEventSink | None,
    hooks: RunHooks[dict[str, Any]] | None,
) -> RunResultBase | None:
    """Interactive run cycle that parks on any error instead of killing the runner."""
    try:
        return await _run_cycle(
            agent,
            coordinator,
            agent_id,
            input_data=input_data,
            run_config=run_config,
            context=context,
            max_turns=max_turns,
            session=session,
            interactive=True,
            event_sink=event_sink,
            hooks=hooks,
        )
    except (BudgetExceededError, BudgetPausedError, SubagentBudgetReservedError):
        raise
    except Exception as exc:
        logger.exception("error escaped the run cycle for %s; parking as failed", agent_id)
        await coordinator.set_status(agent_id, "failed", error=str(exc) or type(exc).__name__)
        await notify_parent_on_terminal(coordinator, agent_id, "failed")
        return None


async def _run_cycle(  # noqa: PLR0912, PLR0915
    agent: Any,
    coordinator: AgentCoordinator,
    agent_id: str,
    *,
    input_data: Any,
    run_config: RunConfig,
    context: dict[str, Any],
    max_turns: int,
    session: Session | None,
    interactive: bool,
    event_sink: StreamEventSink | None,
    hooks: RunHooks[dict[str, Any]] | None,
) -> RunResultBase | None:
    image_strips = 0
    compactions = 0
    model_retries = 0
    while True:
        stream: Any = None
        pre_run_items: list[Any] = []
        try:
            await coordinator.mark_running(agent_id)
            if session is not None:
                max_images = context.get("max_context_images")
                if isinstance(max_images, int):
                    try:
                        await enforce_image_budget(session, max_images)
                    except Exception:
                        logger.exception("image-budget enforcement failed for %s", agent_id)
                try:
                    await _compact_session(agent, session, run_config, force=False)
                except Exception:
                    logger.exception("proactive compaction failed for %s", agent_id)
                with contextlib.suppress(Exception):
                    pre_run_items = list(await session.get_items())
            stream = Runner.run_streamed(
                agent,
                input=input_data,
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                session=session,
                hooks=hooks,
            )
            await coordinator.attach_stream(agent_id, stream)
            try:
                try:
                    async for event in stream.stream_events():
                        if event_sink is not None:
                            try:
                                event_sink(agent_id, event)
                            except Exception:
                                logger.exception("stream event sink failed for %s", agent_id)
                    if stream.run_loop_exception is not None:
                        raise stream.run_loop_exception
                    if refusal := _structured_provider_refusal(stream):
                        raise ProviderRefusalError(refusal)
                except (BudgetExceededError, BudgetPausedError, SubagentBudgetReservedError):
                    raise
                except RuntimeError as stream_exc:
                    if "after shutdown" not in str(stream_exc):
                        raise
                    logger.warning(
                        "Ignoring LiteLLM end-of-stream shutdown race for %s",
                        agent_id,
                    )
                except (ExecTransportError, docker_errors.NotFound):
                    if not coordinator.is_shutting_down:
                        raise
                    logger.warning(
                        "Ignoring sandbox container error during teardown for %s",
                        agent_id,
                        exc_info=True,
                    )
            finally:
                await coordinator.detach_stream(agent_id, stream)
        except BudgetPausedError as exc:
            logger.info("agent %s paused at the scan budget limit: %s", agent_id, exc)
            await coordinator.pause_for_budget(agent_id)
            raise
        except SubagentBudgetReservedError as exc:
            logger.info("sub-agent %s stopped at the budget reserve: %s", agent_id, exc)
            await coordinator.set_status(agent_id, "stopped")
            await _notify_root_on_budget_reserve(coordinator)
            raise
        except BudgetExceededError as exc:
            logger.info(
                "agent %s reached the scan budget limit; stopping the scan: %s", agent_id, exc
            )
            await coordinator.set_status(agent_id, "stopped")
            await coordinator.trigger_budget_stop()
            raise
        except Exception as exc:
            if (
                image_strips < 3
                and session is not None
                and getattr(exc, "status_code", None) in _INPUT_REJECTION_CODES
            ):
                try:
                    stripped = await strip_all_images_from_session(session)
                except Exception:
                    logger.exception("image-strip recovery failed for %s", agent_id)
                    stripped = False
                if stripped:
                    image_strips += 1
                    logger.info(
                        "Stripped images from %s session after rejection; retrying (%d)",
                        agent_id,
                        image_strips,
                    )
                    input_data = []
                    continue
            if (
                compactions < _MAX_COMPACTIONS_PER_CYCLE
                and session is not None
                and is_context_overflow(exc)
            ):
                try:
                    compacted = await _compact_session(agent, session, run_config, force=True)
                except Exception:
                    logger.exception("overflow compaction recovery failed for %s", agent_id)
                    compacted = False
                if compacted:
                    compactions += 1
                    logger.info(
                        "Compacted %s session after context overflow; retrying (%d)",
                        agent_id,
                        compactions,
                    )
                    input_data = []
                    continue
            if model_retries < _MAX_TRANSIENT_MODEL_RETRIES and _is_transient_model_error(exc):
                model_retries += 1
                delay = _transient_model_retry_delay(model_retries)
                logger.warning(
                    "transient model/provider error for %s; replaying turn "
                    "(attempt %d/%d, backoff %.1fs): %r",
                    agent_id,
                    model_retries,
                    _MAX_TRANSIENT_MODEL_RETRIES,
                    delay,
                    exc,
                )
                await asyncio.sleep(delay)
                if session is not None:
                    input_data = []
                continue
            if session is not None:
                await _salvage_stream_to_session(session, pre_run_items, stream, agent_id)
            if isinstance(exc, ProviderRefusalError):
                logger.warning("agent %s refused by the model provider: %s", agent_id, exc)
                await coordinator.set_status(agent_id, "failed", error=str(exc))
                await notify_parent_on_terminal(coordinator, agent_id, "failed")
                return None
            if isinstance(exc, MaxTurnsExceeded):
                status: Status = "stopped"
            elif isinstance(exc, UserError | AgentsException | APIError):
                status = "failed"
            else:
                status = "crashed"
            logger.exception("agent run failed for %s; marking %s", agent_id, status)
            # Settle the status and wake the parent before the exception unwinds a
            # non-interactive agent's task: a child that dies still owes its parent a
            # report, and the parent would otherwise wait out its timeout on a message
            # the dead child can no longer send.
            await coordinator.set_status(agent_id, status, error=str(exc) or type(exc).__name__)
            await notify_parent_on_terminal(coordinator, agent_id, status)
            if not interactive:
                raise
            return None
        else:
            return cast("RunResultBase | None", stream)


async def _agent_status(coordinator: AgentCoordinator, agent_id: str) -> Status | None:
    async with coordinator._lock:
        return coordinator.statuses.get(agent_id)


def _final_output_preview(result: RunResultBase | None) -> str:
    final_output = getattr(result, "final_output", None)
    if final_output is None:
        return "<none>"
    text = str(final_output).replace("\n", " ").strip()
    if not text:
        return "<empty>"
    return text[:300]


async def _append_tool_required_message(
    *,
    session: Session | None,
    context: dict[str, Any],
    attempt: int,
    limit: int,
    interactive: bool,
) -> list[dict[str, str]]:
    finish_tool = "finish_scan" if context.get("parent_id") is None else "agent_finish"
    if interactive:
        message = (
            "Your previous message ended a turn without a tool call. Plain text never ends "
            "execution and never hands control to the user: it is shown to the user, and the "
            "run continues. Continue immediately and call exactly one tool. "
            "If you have something to tell the user and nothing to do until they reply, "
            "call respond_to_user. "
            "If you are blocked waiting for another agent, call wait_for_agents. "
            f"If the whole engagement is complete, call {finish_tool}. "
            "Otherwise use the appropriate execution or planning tool. "
            f"This is recovery attempt {attempt}/{limit}."
        )
    else:
        message = (
            "Your previous response ended the autonomous run without a lifecycle tool "
            "call. That is invalid in non-interactive mode; plain text final answers are "
            "ignored. Continue immediately and call exactly one tool. "
            f"If your work is complete, call {finish_tool}. "
            "If you are blocked waiting for another agent, call wait_for_agents. "
            "Otherwise use the appropriate execution or planning tool. "
            f"This is recovery attempt {attempt}/{limit}."
        )
    item = {"role": "user", "content": message}
    if session is None:
        return [item]

    await session.add_items([cast("TResponseInputItem", item)])
    return []


_TERMINAL_NOTICE = {
    "completed": (
        "[Agent completed] {name} ({agent_id}) finished and is no longer running, but it "
        "sent no completion report. Stop waiting on this child; ask it directly if you "
        "need its results."
    ),
    "crashed": (
        "[Agent crash] {name} ({agent_id}) terminated unexpectedly. "
        "Stop waiting on this child unless you want to message it again."
    ),
    "failed": (
        "[Agent failed] {name} ({agent_id}) stopped with an error and will not "
        "send a completion report. Stop waiting on this child unless you want to "
        "message it again."
    ),
    "stopped": (
        "[Agent stopped] {name} ({agent_id}) was stopped before finishing (turn limit "
        "or an explicit stop). It will not send a completion report, so stop waiting "
        "on this child; account for its unfinished subtask and continue."
    ),
}


_STALL_NOTICE = (
    "[Agent stalled] {name} ({agent_id}) kept ending turns without a tool call and is "
    "parked until it receives a message. It will not send a completion report on its "
    "own: either message it with a concrete next step to unblock it, or stop waiting on "
    "it and account for its unfinished subtask."
)


async def _notify_parent_on_stall(
    coordinator: AgentCoordinator,
    agent_id: str,
) -> None:
    """Tell the parent that a child parked mid-task, so it stops waiting blindly."""
    async with coordinator._lock:
        parent = coordinator.parent_of.get(agent_id)
        name = coordinator.names.get(agent_id, agent_id)
    if parent is None:
        return
    await coordinator.send(
        parent,
        {
            "from": agent_id,
            "type": "stalled",
            "priority": "high",
            "content": _STALL_NOTICE.format(name=name, agent_id=agent_id),
        },
        interrupt=False,
    )


async def notify_parent_on_terminal(
    coordinator: AgentCoordinator,
    agent_id: str,
    status: str,
) -> None:
    template = _TERMINAL_NOTICE.get(status)
    if template is None:
        return
    async with coordinator._lock:
        parent = coordinator.parent_of.get(agent_id)
        name = coordinator.names.get(agent_id, agent_id)
    if parent is None:
        return
    if not await coordinator.claim_parent_notice(agent_id):
        return
    await coordinator.send(
        parent,
        {
            "from": agent_id,
            "type": status,
            "priority": "high",
            "content": template.format(name=name, agent_id=agent_id),
        },
        interrupt=False,
    )


def _reserve_notice() -> dict[str, Any]:
    return {
        "from": "system",
        "type": "budget_reserve_stop",
        "priority": "high",
        "content": (
            "[Budget reserve] The scan has reached the sub-agent budget reserve: every "
            "sub-agent is being force-stopped as soon as its in-flight turn completes, and "
            "none will send a completion report. Their confirmed vulnerabilities are "
            "already filed as they were found. Do not wait on any sub-agents and do not "
            "spawn new ones — wrap up now and call finish_scan."
        ),
    }


async def _notify_root_on_budget_reserve(coordinator: AgentCoordinator) -> None:
    root = await coordinator.claim_reserve_notification()
    if root is None:
        return
    await coordinator.send(root, _reserve_notice())


async def _notify_parent_on_exit(
    coordinator: AgentCoordinator,
    agent_id: str,
) -> None:
    """Backstop for a child whose loop ended without telling its parent.

    Every terminal state counts, including ``completed``: a child that skips its
    completion report leaves the parent waiting on a message nobody will send.
    """
    status = await _agent_status(coordinator, agent_id)
    if status is None:
        return
    await notify_parent_on_terminal(coordinator, agent_id, status)


async def _start_child_runner(
    *,
    parent_ctx: dict[str, Any],
    coordinator: AgentCoordinator,
    agents_db_path: Path,
    sessions_to_close: list[SQLiteSession],
    run_config: RunConfig,
    max_turns: int,
    interactive: bool,
    child_agent: Any,
    child_id: str,
    name: str,
    parent_id: str | None,
    task: str,
    initial_input: Any,
    start_parked: bool = False,
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> None:
    session = open_agent_session(child_id, agents_db_path)
    sessions_to_close.append(session)
    await coordinator.attach_runtime(child_id, session=session)

    child_ctx: dict[str, Any] = dict(parent_ctx)
    child_ctx["agent_id"] = child_id
    child_ctx["parent_id"] = parent_id
    child_ctx["task"] = task

    async def _child_loop() -> None:
        # A budget stop is a clean scan-wide shutdown, not a child failure: the
        # child's status and parent notification are already settled in
        # ``_run_cycle``. Swallow it here so the detached task does not surface a
        # spurious "Task exception was never retrieved" warning. The root agent
        # hits the same limit on its next call and tears the scan down.
        try:
            await run_agent_loop(
                agent=child_agent,
                initial_input=initial_input,
                run_config=run_config,
                context=child_ctx,
                max_turns=max_turns,
                coordinator=coordinator,
                agent_id=child_id,
                interactive=interactive,
                session=session,
                start_parked=start_parked,
                event_sink=event_sink,
                hooks=hooks,
            )
        except BudgetExceededError:
            logger.info("child %s stopped after reaching the scan budget limit", child_id)
        except SubagentBudgetReservedError:
            logger.info("child %s stopped at the sub-agent budget reserve", child_id)
        finally:
            if not coordinator.is_shutting_down:
                await _notify_parent_on_exit(coordinator, child_id)

    task_handle = asyncio.create_task(_child_loop(), name=f"agent-{name}-{child_id}")
    await coordinator.attach_runtime(child_id, task=task_handle)
