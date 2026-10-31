"""Error beacons carry a category, phase, and exception class — never a message."""

from __future__ import annotations

from typing import Any

import pytest
import requests

from strix.report.state import ReportState
from strix.telemetry import posthog, report_error, scarf, set_scan_phase
from strix.telemetry._common import exception_props


PRIVATE_MESSAGE = "private message that must stay on the machine"


def _capture(sent: list[dict[str, Any]], event: str, props: dict[str, Any]) -> bool:
    sent.append({"event": event, **props})
    return True


def test_exception_props_uses_bare_name_for_builtins() -> None:
    assert exception_props(ValueError(PRIVATE_MESSAGE)) == {"exception_type": "ValueError"}


def test_exception_props_prefixes_third_party_top_level_package() -> None:
    props = exception_props(requests.exceptions.ConnectTimeout(PRIVATE_MESSAGE))
    assert props == {"exception_type": "requests.ConnectTimeout"}


def _chained(cause: BaseException | None, *, explicit: bool) -> RuntimeError:
    exc = RuntimeError("wrapped")
    if explicit:
        exc.__cause__ = cause
        exc.__suppress_context__ = True
    else:
        exc.__context__ = cause
    return exc


def test_exception_props_reports_explicit_cause() -> None:
    props = exception_props(_chained(ConnectionError(PRIVATE_MESSAGE), explicit=True))
    assert props == {"exception_type": "RuntimeError", "exception_cause": "ConnectionError"}


def test_exception_props_reports_implicit_context() -> None:
    props = exception_props(_chained(KeyError("k"), explicit=False))
    assert props["exception_cause"] == "KeyError"


def test_exception_props_ignores_suppressed_context() -> None:
    exc = _chained(None, explicit=True)
    exc.__context__ = KeyError("k")
    assert exception_props(exc) == {"exception_type": "RuntimeError"}


def test_exception_props_unwraps_exception_group() -> None:
    group = ExceptionGroup("tasks", [TimeoutError("t"), ValueError("v")])
    assert exception_props(group) == {"exception_type": "TimeoutError"}


@pytest.mark.parametrize("telemetry", [posthog, scarf])
def test_error_event_carries_phase_and_class_but_no_message(
    telemetry: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(telemetry, "_send", lambda event, props: _capture(sent, event, props))
    set_scan_phase("sandbox_init")

    telemetry.error("scan_failed", RuntimeError(PRIVATE_MESSAGE))

    assert len(sent) == 1
    event = sent[0]
    assert event["event"] == "error"
    assert event["error_type"] == "scan_failed"
    assert event["phase"] == "sandbox_init"
    assert event["exception_type"] == "RuntimeError"
    assert PRIVATE_MESSAGE not in repr(event)


@pytest.mark.parametrize("telemetry", [posthog, scarf])
def test_error_event_without_exception_omits_exception_fields(
    telemetry: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(telemetry, "_send", lambda event, props: _capture(sent, event, props))
    set_scan_phase("startup")

    telemetry.error("docker_not_installed")

    assert sent[0]["error_type"] == "docker_not_installed"
    assert sent[0]["phase"] == "startup"
    assert "exception_type" not in sent[0]
    assert "exception_cause" not in sent[0]


def test_report_error_fans_out_to_both_backends(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(posthog, "_send", lambda event, props: _capture(sent, event, props))
    monkeypatch.setattr(scarf, "_send", lambda event, props: _capture(sent, event, props))

    report_error("model_connection_failed", TimeoutError(PRIVATE_MESSAGE))

    assert len(sent) == 2
    assert {e["error_type"] for e in sent} == {"model_connection_failed"}
    assert {e["exception_type"] for e in sent} == {"TimeoutError"}


@pytest.mark.parametrize("telemetry", [posthog, scarf])
def test_scan_ended_prefers_recorded_exit_reason(
    telemetry: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = ReportState()
    state.scan_ended_exit_reason = "budget_exceeded"
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(telemetry, "_send", lambda event, props: _capture(sent, event, props))

    telemetry.end(state, exit_reason="user_exit")

    assert sent[0]["event"] == "scan_ended"
    assert sent[0]["exit_reason"] == "budget_exceeded"
