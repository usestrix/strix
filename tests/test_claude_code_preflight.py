"""Preflight and $0 usage accounting for a ``claude-code/...`` run."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from agents.usage import Usage
from rich.console import Console

from strix.config import claude_code, loader
from strix.config.loader import load_settings
from strix.core.hooks import recomputed_budget_flags
from strix.interface import environment
from strix.report.usage import LLMUsageLedger


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("STRIX_LLM", raising=False)
    loader._cached = None
    yield
    # load_settings() memoizes into loader._cached by direct assignment, which
    # monkeypatch does not track; reset it so a claude-code model doesn't leak
    # into an unrelated test's ReportState (which would then report $0 cost).
    loader._cached = None


def _preflight(monkeypatch: pytest.MonkeyPatch, *, model: str, state: str, present: bool) -> None:
    monkeypatch.setenv("STRIX_LLM", model)
    loader._cached = None
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude" if present else None)
    monkeypatch.setattr(claude_code, "version_state", lambda: "ok")
    monkeypatch.setattr(claude_code, "session_state", lambda: state)
    monkeypatch.setattr(claude_code, "api_key_source", lambda: None)
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
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    monkeypatch.setattr(claude_code, "version_state", lambda: "too_old")
    monkeypatch.setattr(claude_code, "version", lambda: "1.0.0")
    with pytest.raises(SystemExit) as exc:
        environment._validate_claude_code(Console(), "claude-code/claude-opus-4-8")
    assert exc.value.code == 1


def test_preflight_unreadable_version_says_so(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None, capsys: pytest.CaptureFixture[str]
) -> None:
    # A binary that will not run is not the same as an old one, and "update your
    # CLI" sends the user somewhere that cannot fix it.
    monkeypatch.setenv("STRIX_LLM", "claude-code/claude-opus-4-8")
    loader._cached = None
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    monkeypatch.setattr(claude_code, "version_state", lambda: "unknown")
    monkeypatch.setattr(claude_code, "version", lambda: None)
    with pytest.raises(SystemExit) as exc:
        environment._validate_claude_code(Console(), "claude-code/claude-opus-4-8")
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "Couldn't read a version" in out
    assert "too old" not in out


def test_preflight_api_key_warning_names_the_env_override(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None, capsys: pytest.CaptureFixture[str]
) -> None:
    # An ANTHROPIC_API_KEY left in the environment silently takes over inference
    # while `claude auth status` still shows the claude.ai account, so the
    # warning has to name the cause to be actionable.
    monkeypatch.setenv("STRIX_LLM", "claude-code/claude-opus-4-8")
    loader._cached = None
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    monkeypatch.setattr(claude_code, "version_state", lambda: "ok")
    monkeypatch.setattr(claude_code, "session_state", lambda: "api_key")
    monkeypatch.setattr(claude_code, "api_key_source", lambda: "ANTHROPIC_API_KEY")
    environment._validate_claude_code(Console(), "claude-code/claude-opus-4-8")
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().out


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


def test_metered_claude_code_run_feeds_the_budget_guard() -> None:
    # An API-key session meters normally. The CLI's own per-turn cost is the only
    # cost signal this backend has (it never reaches litellm_cost_callback), so
    # the guard sees nothing at all unless the ledger takes it.
    ledger = LLMUsageLedger()
    ledger.zero_cost = False
    ledger.record(
        agent_id="recon",
        usage=_usage(1200, 45),
        agent_name="strix",
        model="claude-code/claude-opus-4-8",
    )
    ledger.record_observed_cost(4.10)
    ledger.record_observed_cost(1.05)

    cost = ledger.to_record()["cost"]
    assert cost == pytest.approx(5.15)
    # recomputed_budget_flags is what stops a headless scan.
    assert recomputed_budget_flags(cost, 5.0, interactive=False) == (True, True)
    assert recomputed_budget_flags(cost, 100.0, interactive=False) == (False, False)


def test_subscription_run_never_reaches_the_budget_guard() -> None:
    ledger = LLMUsageLedger()
    ledger.zero_cost = True
    ledger.record_observed_cost(4.10)
    assert ledger.to_record()["cost"] == 0.0
    assert recomputed_budget_flags(0.0, 5.0, interactive=False) == (False, False)
