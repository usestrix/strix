"""Regression tests for telemetry emitted by resumed runs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from agents.usage import Usage

from strix.report.state import ReportState
from strix.telemetry import posthog, scarf


def _usage(requests: int, input_tokens: int, output_tokens: int, total_tokens: int) -> Usage:
    return Usage(
        requests=requests,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
    )


def _capture(sent: list[dict[str, Any]], props: dict[str, Any]) -> bool:
    sent.append(props)
    return True


@pytest.mark.parametrize("telemetry", [posthog, scarf])
def test_scan_ended_reports_resumed_usage_delta(
    telemetry: Any,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    initial = ReportState(run_name="resumed")
    initial.record_sdk_usage(
        agent_id="agent",
        usage=_usage(10, 1000, 200, 1200),
        model="unknown",
    )
    initial.record_observed_llm_cost(1.25)
    initial.end_time = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    initial.run_record["end_time"] = initial.end_time
    initial.save_run_data()

    resumed = ReportState(run_name="resumed")
    resumed.hydrate_from_run_dir()
    resumed.record_sdk_usage(
        agent_id="agent",
        usage=_usage(3, 300, 50, 350),
        model="unknown",
    )
    resumed.record_observed_llm_cost(0.75)

    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(telemetry, "_send", lambda _event, props: _capture(sent, props))
    telemetry.end(resumed)

    assert sent[0]["llm_requests"] == 3
    assert sent[0]["llm_input_tokens"] == 300
    assert sent[0]["llm_output_tokens"] == 50
    assert sent[0]["llm_tokens"] == 350
    assert sent[0]["llm_cost"] == pytest.approx(0.75)
    assert 0 <= sent[0]["duration_seconds"] <= 2


@pytest.mark.parametrize("telemetry", [posthog, scarf])
def test_scan_ended_reports_all_fresh_run_usage(
    telemetry: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = ReportState()
    state.record_sdk_usage(
        agent_id="agent",
        usage=_usage(3, 300, 50, 350),
        model="unknown",
    )
    state.record_observed_llm_cost(0.75)

    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(telemetry, "_send", lambda _event, props: _capture(sent, props))
    telemetry.end(state)

    assert sent[0]["llm_requests"] == 3
    assert sent[0]["llm_input_tokens"] == 300
    assert sent[0]["llm_output_tokens"] == 50
    assert sent[0]["llm_tokens"] == 350
    assert sent[0]["llm_cost"] == pytest.approx(0.75)
