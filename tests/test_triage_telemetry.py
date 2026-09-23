"""Triage analytics respect consent and keep finding content off the network."""

from __future__ import annotations

import json
import os
import queue
import threading
from typing import TYPE_CHECKING, Any

import pytest
import requests

from strix.config import loader
from strix.telemetry import triage
from strix.telemetry._common import SESSION_ID


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


PRIVATE = "private finding content https://private.invalid customer@example.invalid"


def _wait_for_delivery() -> None:
    worker = triage._worker
    if worker is not None:
        worker.join(timeout=3)
        assert not worker.is_alive(), "Telemetry worker did not finish"
    assert triage._queue.unfinished_tasks == 0


@pytest.fixture(autouse=True)
def _isolated_telemetry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in list(os.environ):
        if name.upper() == "STRIX_TELEMETRY":
            monkeypatch.delenv(name)
    monkeypatch.setattr(loader, "_override", tmp_path / "config.json")
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(triage, "_queue", queue.Queue(maxsize=128))
    monkeypatch.setattr(triage, "_worker", None)
    monkeypatch.setattr(triage, "_guard", threading.Lock())
    yield
    _wait_for_delivery()


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []

    def capture(_url: str, *, json: dict[str, Any], timeout: Any) -> requests.Response:
        assert timeout is not None
        payloads.append(json)
        response = requests.Response()
        response.status_code = 200
        return response

    monkeypatch.setattr(requests, "post", capture)
    return payloads


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    path = tmp_path / "synthetic-run"
    path.mkdir()
    (path / "run.json").write_text(
        json.dumps({"scan_mode": "standard", "run_name": PRIVATE, "target": PRIVATE}),
        encoding="utf-8",
    )
    return path


def _record(run_dir: Path, **fields: Any) -> None:
    current = {
        "status": "closed",
        "resolution_reason": "false_positive",
        "reason_code": "incorrect_assumption",
        "severity": "high",
        "cwe": "CWE-79",
        "cve": "CVE-2026-12345",
        **fields,
    }
    triage.record_triage({"status": "open"}, current, run_dir=run_dir, surface="viewer")


def test_payload_contains_only_classification_metadata(
    run_dir: Path, sent: list[dict[str, Any]]
) -> None:
    _record(
        run_dir,
        **dict.fromkeys(
            (
                "id",
                "title",
                "description",
                "target",
                "endpoint",
                "email",
                "evidence",
                "poc_script_code",
                "status_note",
                "note",
                "code_locations",
                "finding_digest",
                "reviewed_digest",
                "status_changed_by",
                "status_changed_at",
                "triage_history",
                "model",
                "agent_id",
                "agent_name",
            ),
            PRIVATE,
        ),
    )
    _wait_for_delivery()

    assert len(sent) == 1
    payload = sent[0]
    assert payload["event"] == "finding_triage_changed"
    assert payload["distinct_id"] == SESSION_ID
    properties = payload["properties"]
    assert set(properties) == {
        "os",
        "arch",
        "python",
        "strix_version",
        "$lib",
        "$lib_version",
        "$process_person_profile",
        "schema_version",
        "surface",
        "previous_status",
        "new_status",
        "previous_resolution_reason",
        "resolution_reason",
        "reason_code",
        "severity",
        "cwe",
        "is_cve",
        "scan_mode",
    }
    assert properties["schema_version"] == 1
    assert properties["surface"] == "viewer"
    assert properties["previous_status"] == "open"
    assert properties["new_status"] == "closed"
    assert properties["previous_resolution_reason"] is None
    assert properties["resolution_reason"] == "false_positive"
    assert properties["reason_code"] == "incorrect_assumption"
    assert properties["severity"] == "high"
    assert properties["cwe"] == "cwe-79"
    assert properties["is_cve"] is True
    assert properties["scan_mode"] == "standard"
    assert properties["$process_person_profile"] is False
    assert PRIVATE not in json.dumps(payload)
    assert "CVE-2026-12345" not in json.dumps(payload)


@pytest.mark.parametrize("surface", ["viewer", "tui"])
def test_reopen_preserves_transition_direction(
    run_dir: Path, sent: list[dict[str, Any]], surface: str
) -> None:
    triage.record_triage(
        {"status": "closed", "resolution_reason": "false_positive", "status_note": PRIVATE},
        {"status": "open", "reason_code": "unspecified", "severity": " HIGH "},
        run_dir=run_dir,
        surface=surface,
    )
    _wait_for_delivery()
    properties = sent[0]["properties"]
    assert properties["surface"] == surface
    assert properties["previous_status"] == "closed"
    assert properties["new_status"] == "open"
    assert properties["previous_resolution_reason"] == "false_positive"
    assert properties["resolution_reason"] is None
    assert properties["severity"] == "high"
    assert properties["is_cve"] is False
    assert PRIVATE not in json.dumps(sent)


@pytest.mark.parametrize("bad_value", [PRIVATE, {"private": PRIVATE}, [PRIVATE], 42, None])
def test_untrusted_categories_cannot_be_forwarded(
    run_dir: Path, sent: list[dict[str, Any]], bad_value: Any
) -> None:
    (run_dir / "run.json").write_text(json.dumps({"scan_mode": bad_value}), encoding="utf-8")
    triage.record_triage(
        {"status": bad_value, "resolution_reason": bad_value},
        dict.fromkeys(
            ("status", "resolution_reason", "reason_code", "severity", "cwe", "cve"), bad_value
        ),
        run_dir=run_dir,
        surface=bad_value,
    )
    _wait_for_delivery()
    assert len(sent) == 1
    properties = sent[0]["properties"]
    for field in (
        "surface",
        "previous_status",
        "new_status",
        "reason_code",
        "severity",
        "cwe",
        "scan_mode",
    ):
        assert properties[field] == "unknown"
    assert properties["previous_resolution_reason"] is None
    assert properties["resolution_reason"] is None
    assert isinstance(properties["is_cve"], bool)
    assert PRIVATE not in json.dumps(sent)


@pytest.mark.parametrize(
    ("cwe", "expected"),
    [
        (" CWE-79 ", "cwe-79"),
        ("cwe-1000", "cwe-1000"),
        ("CWE-79 " + PRIVATE, "unknown"),
        ("CWE-79\n" + PRIVATE, "unknown"),
        ("cwe-0", "unknown"),
        ("cwe-00079", "unknown"),
        ("cwe-1234567", "unknown"),
        ("79", "unknown"),
    ],
)
def test_cwe_is_a_bounded_identifier(
    run_dir: Path, sent: list[dict[str, Any]], cwe: str, expected: str
) -> None:
    _record(run_dir, cwe=cwe)
    _wait_for_delivery()
    assert sent[0]["properties"]["cwe"] == expected
    assert PRIVATE not in json.dumps(sent)


@pytest.mark.parametrize("source", ["environment", "saved_config"])
@pytest.mark.parametrize("disabled", ["0", "false", "no", "off"])
def test_opt_out_does_not_send_or_replay_disabled_actions(
    run_dir: Path,
    sent: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    disabled: str,
) -> None:
    config = run_dir / "config.json"
    if source == "environment":
        config.write_text(json.dumps({"env": {"STRIX_TELEMETRY": "1"}}), encoding="utf-8")
        monkeypatch.setenv("STRIX_TELEMETRY", disabled)
    else:
        config.write_text(json.dumps({"env": {"STRIX_TELEMETRY": disabled}}), encoding="utf-8")
    loader.apply_config_override(config)

    _record(run_dir, reason_code="other")
    assert loader.load_settings().telemetry.enabled is False
    assert sent == []
    assert triage._queue.empty()
    assert triage._worker is None

    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    config.write_text(json.dumps({"env": {"STRIX_TELEMETRY": "1"}}), encoding="utf-8")
    loader.apply_config_override(config)
    _record(run_dir, reason_code="expected_behavior")
    _wait_for_delivery()
    assert len(sent) == 1
    assert sent[0]["properties"]["reason_code"] == "expected_behavior"


def test_environment_enable_overrides_saved_opt_out(
    run_dir: Path, sent: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    config = run_dir / "config.json"
    config.write_text(json.dumps({"env": {"STRIX_TELEMETRY": "0"}}), encoding="utf-8")
    monkeypatch.setenv("STRIX_TELEMETRY", "1")
    loader.apply_config_override(config)
    _record(run_dir)
    _wait_for_delivery()
    assert len(sent) == 1


def test_consent_is_rechecked_after_loading_scan_metadata(
    run_dir: Path, sent: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = loader.load_settings()

    def disable_during_read(*_args: Any, **_kwargs: Any) -> dict[str, str]:
        settings.telemetry.enabled = False
        return {"scan_mode": "standard"}

    monkeypatch.setattr(triage, "read_json", disable_during_read)
    _record(run_dir)
    assert sent == []
    assert triage._queue.empty()
    assert triage._worker is None


def test_network_delivery_never_blocks_the_caller_and_queue_is_bounded(
    run_dir: Path, sent: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    started = threading.Event()
    release = threading.Event()
    returned = threading.Event()
    capture = requests.post
    monkeypatch.setattr(triage, "_queue", queue.Queue(maxsize=2))

    def blocked_post(*args: Any, **kwargs: Any) -> requests.Response:
        started.set()
        release.wait(timeout=5)
        return capture(*args, **kwargs)

    def close_action() -> None:
        _record(run_dir)
        returned.set()

    monkeypatch.setattr(requests, "post", blocked_post)
    caller = threading.Thread(target=close_action, daemon=True)
    caller.start()
    try:
        assert started.wait(timeout=2)
        # This asserts completion order while the request is still blocked,
        # rather than imposing a performance threshold on a successful send.
        assert returned.wait(timeout=2)
        assert not release.is_set()
        _record(run_dir)
        _record(run_dir)
        _record(run_dir)  # The full queue drops this event without blocking.
        assert triage._queue.qsize() == 2
        assert triage._worker is not None
        assert triage._worker.daemon
    finally:
        release.set()
        caller.join(timeout=3)
        _wait_for_delivery()
    assert len(sent) == 3


def test_pending_event_is_dropped_if_disabled_before_worker_delivery(
    run_dir: Path, sent: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    started = threading.Event()
    release = threading.Event()
    capture = requests.post

    def blocked_post(*args: Any, **kwargs: Any) -> requests.Response:
        started.set()
        release.wait(timeout=5)
        return capture(*args, **kwargs)

    monkeypatch.setattr(requests, "post", blocked_post)
    _record(run_dir)
    try:
        assert started.wait(timeout=2)
        _record(run_dir)
        assert triage._queue.qsize() == 1
        loader.load_settings().telemetry.enabled = False
    finally:
        release.set()
        _wait_for_delivery()
    assert len(sent) == 1  # Only the request already in progress was sent.
    loader.load_settings().telemetry.enabled = True
    _record(run_dir)
    _wait_for_delivery()
    assert len(sent) == 2  # The disabled queued event was not replayed.


def test_delivery_failure_does_not_break_later_delivery(
    run_dir: Path, sent: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = requests.post
    failures: list[bool] = []

    def fail_once(*args: Any, **kwargs: Any) -> requests.Response:
        if not failures:
            failures.append(True)
            raise requests.Timeout(PRIVATE)
        return capture(*args, **kwargs)

    monkeypatch.setattr(requests, "post", fail_once)
    _record(run_dir)
    _wait_for_delivery()
    _record(run_dir)
    _wait_for_delivery()
    assert len(sent) == 1
    assert PRIVATE not in json.dumps(sent)


def test_malformed_scan_metadata_never_fails_the_local_action(
    run_dir: Path, sent: list[dict[str, Any]]
) -> None:
    (run_dir / "run.json").write_text("{" + PRIVATE, encoding="utf-8")
    _record(run_dir)
    assert sent == []
    assert triage._queue.empty()
