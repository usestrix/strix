from __future__ import annotations

from types import SimpleNamespace

import pytest

from strix.llm.budget import BudgetExceededError
from strix.llm.memory_compressor import MAX_TOTAL_TOKENS, MIN_RECENT_MESSAGES, MemoryCompressor


class DummyBudgetManager:
    def __init__(self, *, should_block: bool = False) -> None:
        self.should_block = should_block
        self.ensure_calls = 0
        self.record_calls = 0
        self.record_args: list[tuple[int, int, float]] = []

    def configure(self, *_: object, **__: object) -> None:  # pragma: no cover - helper parity
        return None

    def ensure_within_budget(self) -> None:
        self.ensure_calls += 1
        if self.should_block:
            raise BudgetExceededError("budget exceeded", {"total_tokens": 0}, "blocked")

    def record_usage(self, tokens_in: int, tokens_out: int, cost: float) -> None:
        self.record_calls += 1
        self.record_args.append((tokens_in, tokens_out, cost))


@pytest.fixture
def compressor(monkeypatch: pytest.MonkeyPatch) -> MemoryCompressor:
    monkeypatch.setattr(
        "strix.llm.memory_compressor._get_message_tokens",
        lambda *_args, **_kwargs: MAX_TOTAL_TOKENS,
    )
    monkeypatch.setattr(
        "strix.llm.memory_compressor.litellm.token_counter",
        lambda **_kwargs: MAX_TOTAL_TOKENS,
    )
    return MemoryCompressor(model_name="test-model", timeout=5)


def _sample_messages(count: int) -> list[dict[str, str]]:
    return [{"role": "user", "content": f"message {idx}"} for idx in range(count)]


def test_memory_compressor_halts_when_budget_blocked(
    compressor: MemoryCompressor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = DummyBudgetManager(should_block=True)
    monkeypatch.setattr(
        "strix.llm.memory_compressor.get_budget_manager",
        lambda: manager,
    )

    def _fail_completion(**_kwargs: object) -> None:
        raise AssertionError("should not call LLM")

    monkeypatch.setattr(
        "strix.llm.memory_compressor.litellm.completion",
        _fail_completion,
    )

    with pytest.raises(BudgetExceededError):
        compressor.compress_history(_sample_messages(MIN_RECENT_MESSAGES + 2))

    assert manager.ensure_calls == 1
    assert manager.record_calls == 0


def test_memory_compressor_records_budget_usage(
    compressor: MemoryCompressor,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = DummyBudgetManager()
    monkeypatch.setattr(
        "strix.llm.memory_compressor.get_budget_manager",
        lambda: manager,
    )

    response = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content="summary text"),
            )
        ],
        usage=SimpleNamespace(prompt_tokens=120, completion_tokens=30),
    )

    monkeypatch.setattr(
        "strix.llm.memory_compressor.litellm.completion",
        lambda **_kwargs: response,
    )
    monkeypatch.setattr(
        "strix.llm.memory_compressor.completion_cost",
        lambda *_args, **_kwargs: 0.42,
    )

    result = compressor.compress_history(_sample_messages(MIN_RECENT_MESSAGES + 2))

    assert result[0]["role"] == "assistant"
    assert manager.ensure_calls == 1
    assert manager.record_calls == 1
    assert manager.record_args[0] == (120, 30, 0.42)
