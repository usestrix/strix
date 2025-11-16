"""Budget management utilities for tracking token and cost usage per run."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

from strix.telemetry.tracer import get_global_tracer


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class BudgetConfig:
    """Resolved configuration for usage budgeting."""

    max_tokens: int | None
    max_cost: float | None
    warn_threshold: float
    fallback_cost_per_1k_tokens: float | None


class BudgetExceededError(Exception):
    """Raised when a run exceeds one of the configured usage budgets."""

    def __init__(self, message: str, usage_snapshot: dict[str, Any], summary: str):
        super().__init__(message)
        self.usage_snapshot = usage_snapshot
        self.summary = summary


class BudgetManager:
    """Tracks usage across all agents and enforces configured budgets."""

    def __init__(self) -> None:
        self._config = BudgetConfig(None, None, 80.0, None)
        self._lock = threading.Lock()
        self._reset_usage()

    def configure(self, config: BudgetConfig) -> None:
        """Reset usage counters and apply a new configuration."""

        with self._lock:
            self._config = config
            self._reset_usage()
            logger.debug(
                "Budget configured: max_tokens=%s, max_cost=%s, warn_threshold=%s, "
                "fallback_cost_per_1k_tokens=%s",
                config.max_tokens,
                config.max_cost,
                config.warn_threshold,
                config.fallback_cost_per_1k_tokens,
            )

            tracer = get_global_tracer()
            if tracer:
                tracer.set_budget_config(
                    {
                        "max_tokens": config.max_tokens,
                        "max_cost": config.max_cost,
                        "warn_threshold": config.warn_threshold,
                        "fallback_cost_per_1k_tokens": config.fallback_cost_per_1k_tokens,
                    }
                )

    def ensure_within_budget(self) -> None:
        """Raise an error if the budget has already been exceeded."""

        with self._lock:
            if not self._budget_exceeded:
                return

            logger.info("Blocking LLM request: usage budget exceeded")
            raise BudgetExceededError(
                self._exceeded_reason,
                self._usage_snapshot(),
                self._exceeded_summary or self.format_summary(),
            )

    def record_usage(self, input_tokens: int, output_tokens: int, cost: float) -> None:
        """Record usage from a single LLM request."""

        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("Token counts must be non-negative")

        with self._lock:
            incremental_tokens = max(input_tokens + output_tokens, 0)

            if cost < 0:
                cost = 0.0

            if cost == 0 and incremental_tokens > 0:
                fallback = self._config.fallback_cost_per_1k_tokens
                if fallback and fallback > 0:
                    estimated = (incremental_tokens / 1000.0) * fallback
                    cost = max(cost, estimated)

            self._input_tokens += input_tokens
            self._output_tokens += output_tokens
            self._total_cost += cost
            self._requests += 1

            self._update_tracer()
            self._maybe_emit_progress()
            self._maybe_emit_warning()
            self._check_limits()

    # ---------------------------------------------------------------------
    # Internal helpers (protected by _lock)
    # ---------------------------------------------------------------------

    def _reset_usage(self) -> None:
        self._input_tokens = 0
        self._output_tokens = 0
        self._total_cost = 0.0
        self._requests = 0
        self._budget_exceeded = False
        self._exceeded_reason = ""
        self._exceeded_summary = ""
        self._warned_token = False
        self._warned_cost = False
        self._last_progress_token_bucket = -1
        self._last_progress_cost_bucket = -1

    def _total_tokens(self) -> int:
        return self._input_tokens + self._output_tokens

    def _usage_snapshot(self) -> dict[str, Any]:
        max_tokens = self._config.max_tokens
        max_cost = self._config.max_cost
        total_tokens = self._total_tokens()

        token_percent = (
            (total_tokens / max_tokens) * 100 if max_tokens and max_tokens > 0 else None
        )
        cost_percent = (
            (self._total_cost / max_cost) * 100 if max_cost and max_cost > 0 else None
        )

        return {
            "input_tokens": self._input_tokens,
            "output_tokens": self._output_tokens,
            "total_tokens": total_tokens,
            "total_cost": round(self._total_cost, 4),
            "requests": self._requests,
            "token_percent": round(token_percent, 2) if token_percent is not None else None,
            "cost_percent": round(cost_percent, 2) if cost_percent is not None else None,
            "max_tokens": max_tokens,
            "max_cost": max_cost,
            "warn_threshold": self._config.warn_threshold,
        }

    def _update_tracer(self) -> None:
        tracer = get_global_tracer()
        if tracer:
            tracer.update_budget_usage(self._usage_snapshot())

    def _maybe_emit_progress(self) -> None:
        snapshot = self._usage_snapshot()
        progress_step = 10

        token_percent = snapshot["token_percent"]
        if token_percent is not None:
            bucket = int(token_percent // progress_step) * progress_step
            if bucket > self._last_progress_token_bucket:
                logger.info(
                    "Budget usage: %d/%d tokens (%.2f%%)",
                    snapshot["total_tokens"],
                    snapshot["max_tokens"],
                    token_percent,
                )
                self._last_progress_token_bucket = bucket

        cost_percent = snapshot["cost_percent"]
        if cost_percent is not None:
            bucket = int(cost_percent // progress_step) * progress_step
            if bucket > self._last_progress_cost_bucket:
                logger.info(
                    "Budget spend: $%.4f / $%.4f (%.2f%%)",
                    snapshot["total_cost"],
                    snapshot["max_cost"],
                    cost_percent,
                )
                self._last_progress_cost_bucket = bucket

    def _maybe_emit_warning(self) -> None:
        snapshot = self._usage_snapshot()
        warn_threshold = self._config.warn_threshold

        token_percent = snapshot["token_percent"]
        if (
            token_percent is not None
            and not self._warned_token
            and token_percent >= warn_threshold
        ):
            message = (
                "Token usage warning: "
                f"{token_percent:.2f}% of budget consumed "
                f"({snapshot['total_tokens']}/{snapshot['max_tokens']} tokens)"
            )
            self._emit_event("warning", message)
            self._warned_token = True

        cost_percent = snapshot["cost_percent"]
        if cost_percent is not None and not self._warned_cost and cost_percent >= warn_threshold:
            message = (
                "Cost usage warning: "
                f"{cost_percent:.2f}% of budget consumed "
                f"(${snapshot['total_cost']:.4f} / ${snapshot['max_cost']:.4f})"
            )
            self._emit_event("warning", message)
            self._warned_cost = True

    def _check_limits(self) -> None:
        if self._budget_exceeded:
            return

        snapshot = self._usage_snapshot()
        over_tokens = (
            snapshot["max_tokens"] is not None
            and snapshot["total_tokens"] >= snapshot["max_tokens"]
        )
        over_cost = (
            snapshot["max_cost"] is not None
            and snapshot["total_cost"] >= snapshot["max_cost"]
        )

        if over_tokens or over_cost:
            if over_tokens and over_cost:
                reason = (
                    "Token and cost budgets exceeded: "
                    f"{snapshot['total_tokens']}/{snapshot['max_tokens']} tokens, "
                    f"${snapshot['total_cost']:.4f}/${snapshot['max_cost']:.4f}"
                )
            elif over_tokens:
                reason = (
                    "Token budget exceeded: "
                    f"{snapshot['total_tokens']} used out of {snapshot['max_tokens']}"
                )
            else:
                reason = (
                    "Cost budget exceeded: "
                    f"${snapshot['total_cost']:.4f} used out of ${snapshot['max_cost']:.4f}"
                )

            self._budget_exceeded = True
            self._exceeded_reason = reason
            self._exceeded_summary = self.format_summary(snapshot)
            self._emit_event("error", reason, snapshot)

    def _emit_event(
        self,
        level: str,
        message: str,
        snapshot: dict[str, Any] | None = None,
    ) -> None:
        if level == "warning":
            logger.warning(message)
        else:
            logger.error(message)

        tracer = get_global_tracer()
        if tracer:
            current_snapshot = snapshot or self._usage_snapshot()
            tracer.add_budget_event(
                level,
                message,
                current_snapshot,
                self.format_summary(current_snapshot),
            )

    def format_summary(self, snapshot: dict[str, Any] | None = None) -> str:
        data = snapshot or self._usage_snapshot()
        parts = []

        max_tokens = data.get("max_tokens")
        token_percent = data.get("token_percent")
        token_section = f"{data['total_tokens']} tokens"
        if max_tokens:
            token_section = f"{data['total_tokens']} / {max_tokens} tokens"
        if token_percent is not None:
            token_section += f" ({token_percent:.2f}% of limit)"
        parts.append(token_section)

        max_cost = data.get("max_cost")
        cost_percent = data.get("cost_percent")
        cost_section = f"${data['total_cost']:.4f}"
        if max_cost:
            cost_section = f"${data['total_cost']:.4f} / ${max_cost:.4f}"
        if cost_percent is not None:
            cost_section += f" ({cost_percent:.2f}% of limit)"
        parts.append(cost_section)

        return "; ".join(parts)


_GLOBAL_BUDGET_MANAGER: BudgetManager | None = None


def get_budget_manager() -> BudgetManager:
    global _GLOBAL_BUDGET_MANAGER  # noqa: PLW0603
    if _GLOBAL_BUDGET_MANAGER is None:
        _GLOBAL_BUDGET_MANAGER = BudgetManager()
    return _GLOBAL_BUDGET_MANAGER
