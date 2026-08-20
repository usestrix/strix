from __future__ import annotations

from typing import Any

import pytest
from agents import ModelSettings, RunConfig, Runner

from strix.config import codex
from strix.core import execution
from strix.core.agents import AgentCoordinator


class _FakeStream:
    def __init__(self, exc: BaseException | None = None) -> None:
        self._exc = exc
        self.run_loop_exception: BaseException | None = None

    async def stream_events(self) -> Any:
        if self._exc is not None:
            raise self._exc
        events: list[Any] = []
        for event in events:
            yield event


def _patch_fast_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_BASE_DELAY_S", 0.0)
    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_MAX_DELAY_S", 0.0)


def _guardrail_stream() -> _FakeStream:
    return _FakeStream(codex.CodexContentGuardrailError("gpt-5.6-sol"))


async def _run_once(
    monkeypatch: pytest.MonkeyPatch,
    streams: list[_FakeStream],
    *,
    fallback_model: str | None = None,
    denied_retries: int = 3,
    primary_model: str = "openai/gpt-5.6-sol",
    fallback_model_settings: ModelSettings | None = None,
) -> tuple[Any, list[tuple[str | None, ModelSettings]], AgentCoordinator]:
    _patch_fast_backoff(monkeypatch)
    calls: list[tuple[str | None, ModelSettings]] = []

    def _fake_run_streamed(*_args: Any, **kwargs: Any) -> _FakeStream:
        run_config = kwargs["run_config"]
        calls.append((run_config.model, run_config.model_settings))
        return streams[len(calls) - 1]

    monkeypatch.setattr(Runner, "run_streamed", _fake_run_streamed)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    if fallback_model is not None:
        coordinator.configure_denial_fallback(
            fallback_model, denied_retries, model_settings=fallback_model_settings
        )

    result = await execution._run_cycle(
        object(),
        coordinator,
        "root",
        input_data="task",
        run_config=RunConfig(model=primary_model, model_settings=ModelSettings()),
        context={},
        max_turns=5,
        session=None,
        interactive=False,
        event_sink=None,
        hooks=None,
    )
    return result, calls, coordinator


@pytest.mark.asyncio
async def test_a_denied_turn_is_retried_on_the_fallback_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams = [_guardrail_stream(), _FakeStream()]
    result, models, coordinator = await _run_once(
        monkeypatch,
        streams,
        fallback_model="openai/gpt-5.4",
    )

    assert result is streams[1]
    assert [model for model, _ in models] == ["openai/gpt-5.6-sol", "openai/gpt-5.4"]
    # One denial is below the threshold, so the agent is not pinned to the
    # fallback and its next turn starts on the main model again.
    assert await coordinator.is_on_denial_fallback("root") is False


@pytest.mark.asyncio
async def test_agent_is_pinned_to_the_fallback_after_repeated_denials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams = [_guardrail_stream() for _ in range(3)] + [_FakeStream()]
    result, models, coordinator = await _run_once(
        monkeypatch,
        streams,
        fallback_model="openai/gpt-5.4",
    )

    assert result is streams[3]
    assert [model for model, _ in models] == ["openai/gpt-5.6-sol"] + ["openai/gpt-5.4"] * 3
    assert await coordinator.is_on_denial_fallback("root") is True


@pytest.mark.asyncio
async def test_run_cycle_does_not_retry_guardrail_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guardrail = codex.CodexContentGuardrailError("gpt-5.6-sol")
    with pytest.raises(codex.CodexContentGuardrailError):
        await _run_once(monkeypatch, [_FakeStream(guardrail), _FakeStream()])


@pytest.mark.asyncio
async def test_run_cycle_pins_on_first_denial_at_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams = [_guardrail_stream(), _FakeStream()]
    result, models, coordinator = await _run_once(
        monkeypatch,
        streams,
        fallback_model="openai/gpt-5.4",
        denied_retries=1,
    )

    assert result is streams[1]
    assert [model for model, _ in models] == ["openai/gpt-5.6-sol", "openai/gpt-5.4"]
    assert await coordinator.is_on_denial_fallback("root") is True


@pytest.mark.asyncio
async def test_fallback_uses_its_own_model_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fallback_settings = ModelSettings(parallel_tool_calls=True)
    streams = [_guardrail_stream(), _FakeStream()]
    result, calls, _coordinator = await _run_once(
        monkeypatch,
        streams,
        fallback_model="openai/gpt-5.4",
        denied_retries=1,
        fallback_model_settings=fallback_settings,
    )

    assert result is streams[1]
    assert calls[0][1] is not fallback_settings
    assert calls[1][1] is fallback_settings


@pytest.mark.asyncio
async def test_denial_fallback_state_round_trips_through_snapshot() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    coordinator.configure_denial_fallback("openai/gpt-5.4", 3)
    await coordinator.record_denial("root")
    await coordinator.mark_denial_fallback("root")

    restored = AgentCoordinator()
    await restored.restore(await coordinator.snapshot())

    assert restored.denial_counts == {"root": 1}
    assert await restored.is_on_denial_fallback("root") is True
