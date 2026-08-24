"""Preflight and $0 usage accounting for a ``claude-code/...`` run."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from agents.usage import Usage
from rich.console import Console

from strix.config import claude_code, loader
from strix.config.loader import load_settings
from strix.interface import environment
from strix.report.usage import LLMUsageLedger


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("STRIX_LLM", raising=False)
    loader._cached = None
    loader._override = None
    yield
    # load_settings() memoizes into loader._cached by direct assignment, which
    # monkeypatch does not track; reset it so a claude-code model doesn't leak
    # into an unrelated test's ReportState (which would then report $0 cost).
    loader._cached = None
    loader._override = None


def _preflight(monkeypatch: pytest.MonkeyPatch, *, model: str, state: str, present: bool) -> None:
    monkeypatch.setenv("STRIX_LLM", model)
    loader._cached = None
    loader._override = None
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude" if present else None)
    monkeypatch.setattr(claude_code, "meets_min_version", lambda: True)
    monkeypatch.setattr(claude_code, "session_state", lambda: state)
    environment._validate_claude_code(Console(), load_settings().llm.model)


def test_preflight_missing_binary_exits(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    with pytest.raises(SystemExit) as exc:
        _preflight(
            monkeypatch, model="claude-code/claude-opus-4-8", state="subscription", present=False
        )
    assert exc.value.code == 1


def test_preflight_signed_out_exits(monkeypatch: pytest.MonkeyPatch, _reset_settings: None) -> None:
    with pytest.raises(SystemExit) as exc:
        _preflight(
            monkeypatch, model="claude-code/claude-opus-4-8", state="signed_out", present=True
        )
    assert exc.value.code == 1


def test_preflight_old_version_exits(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setenv("STRIX_LLM", "claude-code/claude-opus-4-8")
    loader._cached = None
    loader._override = None
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    monkeypatch.setattr(claude_code, "meets_min_version", lambda: False)
    monkeypatch.setattr(claude_code, "version", lambda: "1.0.0")
    with pytest.raises(SystemExit) as exc:
        environment._validate_claude_code(Console(), "claude-code/claude-opus-4-8")
    assert exc.value.code == 1


def test_preflight_subscription_passes(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    # No SystemExit means the happy path returned cleanly.
    _preflight(monkeypatch, model="claude-code/claude-opus-4-8", state="subscription", present=True)


def test_preflight_api_key_warns_but_continues(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    # api_key state is a warning, not a hard stop.
    _preflight(monkeypatch, model="claude-code/claude-opus-4-8", state="api_key", present=True)


def _usage(input_tokens: int, output_tokens: int) -> Usage:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = input_tokens
    usage.output_tokens = output_tokens
    usage.total_tokens = input_tokens + output_tokens
    return usage


def test_claude_code_run_records_tokens_at_zero_cost() -> None:
    # zero_cost is derived by report.state from subscription.auth_mode; here we
    # assert the ledger contract the Claude Code backend depends on.
    ledger = LLMUsageLedger()
    ledger.zero_cost = True
    ledger.record(
        agent_id="recon",
        usage=_usage(1200, 45),
        agent_name="strix",
        model="claude-code/claude-opus-4-8",
    )
    record = ledger.to_record()
    assert record["cost"] == 0.0
    assert record["total_tokens"] == 1245
    assert record["input_tokens"] == 1200
