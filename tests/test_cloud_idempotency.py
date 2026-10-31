"""Durable retry behavior for managed scan-launch commands."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
import requests

from strix.interface import cloud
from strix.interface.cloud import http, runner
from strix.interface.completions import completion_candidates


class FakeResponse:
    def __init__(self, payload: Any, *, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code
        self.headers = {"content-type": "application/json"}
        self.text = json.dumps(payload)
        self.closed = False

    def json(self) -> Any:
        return self._payload

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_API_TOKEN", "idempotency-test-token")
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)


def test_scan_start_generates_and_sends_one_stable_key(
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(runner, "uuid4", lambda: "generated-key")

    def request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen.append(kwargs)
        return FakeResponse({"scan_id": "scan-1", "status": "running"})

    monkeypatch.setattr(http, "request", request)
    assert cloud.run_cloud(["scans", "start", "--domain-ids", "domain-1", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["scan_id"] == "scan-1"
    assert len(seen) == 1
    assert seen[0]["idempotency_key"] == "generated-key"
    assert seen[0]["body"]["engagement_type"] == "live_test"


def test_exact_transport_retry_reuses_key_and_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[str, dict[str, Any]]] = []

    def request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen.append((kwargs["idempotency_key"], kwargs["body"]))
        if len(seen) == 1:
            raise http.CloudTransportError("response lost")
        return FakeResponse({"scan_id": "scan-1", "status": "running"})

    monkeypatch.setattr(http, "request", request)
    command = [
        "scans",
        "start",
        "--domain-ids",
        "domain-1",
        "--idempotency-key",
        "retry-key",
        "--json",
    ]
    assert cloud.run_cloud(command) == 0
    assert len(seen) == 2
    assert seen[0] == seen[1]
    assert seen[0][0] == "retry-key"


@pytest.mark.parametrize(
    "payload,status",
    [
        ({"code": "idempotency_request_in_progress", "retry_safe": True}, 409),
        ({"code": "idempotency_outcome_unknown", "retry_safe": True}, 503),
        ({"detail": "gateway unavailable"}, 502),
        ({"detail": "rate limited"}, 429),
    ],
)
def test_retryable_responses_are_closed_and_replayed(
    payload: dict[str, Any],
    status: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = FakeResponse(payload, status_code=status)
    responses = iter((first, FakeResponse({"scan_id": "scan-1", "status": "running"})))
    keys: list[str] = []

    def request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        keys.append(kwargs["idempotency_key"])
        return next(responses)

    monkeypatch.setattr(http, "request", request)
    assert (
        cloud.run_cloud(
            [
                "scans",
                "rerun",
                "scan-old",
                "--idempotency-key",
                "same-key",
                "--json",
            ]
        )
        == 0
    )
    assert keys == ["same-key", "same-key"]
    assert first.closed is True


def test_terminal_key_conflict_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    calls = 0

    def request(_method: str, _path: str, **_kwargs: Any) -> FakeResponse:
        nonlocal calls
        calls += 1
        return FakeResponse(
            {
                "detail": "key belongs to another request",
                "code": "idempotency_key_conflict",
                "terminal": True,
            },
            status_code=409,
        )

    monkeypatch.setattr(http, "request", request)
    assert (
        cloud.run_cloud(["scans", "rerun", "scan-old", "--idempotency-key", "conflict", "--json"])
        == http.EXIT_ERROR
    )
    assert calls == 1
    assert json.loads(capsys.readouterr().out)["code"] == "idempotency_key_conflict"


def test_exhausted_ambiguous_launch_reports_safe_recovery_key(
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    monkeypatch.setattr(
        http,
        "request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(http.CloudTransportError("response lost")),
    )
    assert (
        cloud.run_cloud(["scans", "rerun", "scan-old", "--idempotency-key", "recover-me", "--json"])
        == http.EXIT_ERROR
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["idempotency_key"] == "recover-me"
    assert payload["retry_safe"] is True
    assert payload["retry_same_request"] is True
    assert "--idempotency-key recover-me" in payload["error"]


@pytest.mark.parametrize("key", ["", " white", "bad key", "x\nheader", "x" * 201])
def test_invalid_idempotency_key_is_usage_error_before_request(
    key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(http, "request", lambda *_a, **_k: pytest.fail("must not request"))
    assert (
        cloud.run_cloud(["scans", "rerun", "scan-old", "--idempotency-key", key, "--json"])
        == http.EXIT_USAGE
    )


def test_idempotency_flag_is_completed_only_for_keyed_commands() -> None:
    assert "--idempotency-key" in completion_candidates(["cloud", "scans", "start", "--idemp"])
    assert "--idempotency-key" in completion_candidates(
        ["cloud", "scans", "rerun", "scan-1", "--idemp"]
    )
    assert "--idempotency-key" not in completion_candidates(["cloud", "scans", "list", "--idemp"])
    assert "--idempotency-key" in completion_candidates(["cloud", "schedules", "create", "--idemp"])
    assert "--idempotency-key" in completion_candidates(
        ["cloud", "schedules", "trigger", "schedule-1", "--idemp"]
    )


def test_http_client_places_key_in_the_header(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def request(_method: str, _url: str, **kwargs: Any) -> FakeResponse:
        seen.update(kwargs)
        return FakeResponse({"ok": True})

    monkeypatch.setattr(requests, "request", request)
    http.request("POST", "/scans", body={}, idempotency_key="header-key")
    assert seen["headers"]["Idempotency-Key"] == "header-key"
    assert seen["headers"]["Authorization"] == "Bearer idempotency-test-token"
