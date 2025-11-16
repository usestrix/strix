from __future__ import annotations

import pytest

from strix.llm.budget import BudgetConfig, BudgetExceededError, BudgetManager


class DummyTracer:
    def __init__(self) -> None:
        self.config: dict[str, object] | None = None
        self.usage_snapshots: list[dict[str, object]] = []
        self.events: list[dict[str, object]] = []

    def set_budget_config(self, config: dict[str, object]) -> None:
        self.config = config

    def update_budget_usage(self, usage: dict[str, object]) -> None:
        self.usage_snapshots.append(usage)

    def add_budget_event(
        self,
        level: str,
        message: str,
        snapshot: dict[str, object],
        summary: str,
    ) -> None:
        self.events.append(
            {
                "level": level,
                "message": message,
                "snapshot": snapshot,
                "summary": summary,
            }
        )


@pytest.fixture
def tracer(monkeypatch: pytest.MonkeyPatch) -> DummyTracer:
    dummy = DummyTracer()
    monkeypatch.setattr("strix.llm.budget.get_global_tracer", lambda: dummy)
    return dummy


def test_budget_manager_warns_and_blocks_tokens(tracer: DummyTracer) -> None:
    manager = BudgetManager()
    config = BudgetConfig(
        max_tokens=100,
        max_cost=None,
        warn_threshold=50,
        fallback_cost_per_1k_tokens=0.08,
    )

    manager.configure(config)
    assert tracer.config == {
        "max_tokens": 100,
        "max_cost": None,
        "warn_threshold": 50,
        "fallback_cost_per_1k_tokens": 0.08,
    }

    manager.record_usage(30, 20, 0.0)
    assert tracer.usage_snapshots, "Usage update should be recorded"
    assert tracer.usage_snapshots[-1]["total_tokens"] == 50
    assert tracer.events, "Warning event should be emitted"
    assert tracer.events[0]["level"] == "warning"

    manager.record_usage(35, 25, 0.0)

    with pytest.raises(BudgetExceededError) as exc_info:
        manager.ensure_within_budget()

    assert "Token budget exceeded" in str(exc_info.value)
    assert "tokens" in exc_info.value.summary

    last_event = tracer.events[-1]
    assert last_event["level"] == "error"
    assert "budget" in last_event["message"].lower()


def test_budget_manager_enforces_cost_limit(tracer: DummyTracer) -> None:
    manager = BudgetManager()
    config = BudgetConfig(
        max_tokens=None,
        max_cost=1.0,
        warn_threshold=50,
        fallback_cost_per_1k_tokens=0.05,
    )

    manager.configure(config)

    manager.record_usage(10, 10, 0.6)
    assert tracer.events, "Cost warning should be recorded"
    assert tracer.events[-1]["level"] == "warning"

    manager.record_usage(5, 5, 0.5)

    exc = pytest.raises(BudgetExceededError, manager.ensure_within_budget)
    assert "Cost budget exceeded" in str(exc.value)
    assert "$" in exc.value.summary
