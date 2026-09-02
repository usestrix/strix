"""Focused regressions for managed-cloud CLI rendering and runtime safety."""

from __future__ import annotations

import argparse
import io
import json
import sys
import time
from typing import TYPE_CHECKING, Any

import pytest
import requests
from rich.console import Console

from strix.interface import cloud, platform_cli
from strix.interface.cloud import http, render, runner, source_scan
from strix.interface.cloud.source_upload import prepare_source
from strix.interface.main import main as interface_main


if TYPE_CHECKING:
    from pathlib import Path


class FakeResponse:
    def __init__(
        self,
        payload: Any = None,
        *,
        status_code: int = 200,
        content: bytes | None = None,
        content_type: str | None = None,
    ) -> None:
        self._payload = payload
        self.status_code = status_code
        self.ok = 200 <= status_code < 400
        self.content = content if content is not None else json.dumps(payload).encode()
        self.text = self.content.decode("utf-8", errors="replace")
        self.headers = {
            "content-type": content_type
            or ("application/json" if payload is not None else "application/octet-stream")
        }
        self.closed = False

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("not JSON")
        return self._payload

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_API_TOKEN", "runtime-test-token")


def _console_output(data: Any, *, view: str | None = None, width: int = 160) -> str:
    output = io.StringIO()
    render.emit(Console(file=output, width=width), data, as_json=False, view=view)
    return output.getvalue()


def test_paginated_envelope_with_scalar_metadata_is_a_compact_list() -> None:
    output = _console_output(
        {
            "items": [{"id": "scan-1", "status": "running", "title": "Acceptance"}],
            "scansThisMonth": 42,
            "total": 1,
        },
        view="GET /scans",
    )
    assert "Acceptance" in output
    assert "running" in output
    assert "scansThisMonth" not in output
    assert "42" not in output
    assert len(output.splitlines()) < 10


@pytest.mark.parametrize("width", [80, 160])
def test_scan_lists_flatten_actionable_targets_findings_and_ids(width: int) -> None:
    output = _console_output(
        {
            "items": [
                {
                    "id": "scan-code-uuid",
                    "title": "Source review",
                    "engagement_type": "code_review",
                    "scan_type": "ultra",
                    "status": "running",
                    "repositories": [
                        {
                            "url": "https://github.com/usestrix/strix",
                            "branch": "feature",
                            "provider": "github",
                        }
                    ],
                    "findings": {"total": 4, "critical": 1, "high": 3},
                    "created_at": "2026-08-28T12:00:00Z",
                },
                {
                    "id": "scan-live-uuid",
                    "title": "Staging pentest",
                    "engagement_type": "live_test",
                    "scan_type": "ultra",
                    "status": "completed",
                    "urls": ["https://staging.example.test"],
                    "findings": {"total": 2, "high": 2},
                    "created_at": "2026-08-28T13:00:00Z",
                },
            ],
            "total": 2,
        },
        view="GET /scans",
        width=width,
    )
    for value in (
        "https://github.com/usestrix/strix @ feature",
        "https://staging.example.test",
        "running",
        "completed",
        "scan-code-uuid",
        "scan-live-uuid",
    ):
        assert value in output
    assert "findings" in output
    assert "4" in output
    assert "2" in output
    assert "scans get ID" in output


@pytest.mark.parametrize("width", [80, 160])
def test_vulnerability_lists_always_include_the_actionable_uuid(width: int) -> None:
    vulnerability_id = "12345678-1234-4321-8765-123456789abc"
    output = _console_output(
        {
            "items": [
                {
                    "id": vulnerability_id,
                    "scan_id": "internal-scan-id",
                    "title": "SQL injection",
                    "target": "https://example.test/search",
                    "severity": "critical",
                    "cve": "CVE-2026-0001",
                    "cvss": 9.8,
                    "status": "open",
                    "created_at": "2026-08-28T12:00:00Z",
                    "dependency_metadata": {"package": "example"},
                    "display_number": "VULN-42",
                    "finding_type": "dast",
                }
            ]
        },
        view="GET /vulnerabilities",
        width=width,
    )
    assert vulnerability_id in output
    assert "internal-scan-id" not in output
    assert "SQL injection" in output
    assert "critical" in output
    assert "vulns get ID" in output


def test_connector_enrollment_command_is_complete_multiline_and_terminal_safe(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    command = (
        "docker run --rm \\\n"
        "  -e TS_AUTHKEY=tskey-" + "a" * 180 + " \\\n"
        "  -e LABEL=before\x1b]52;c;copied\x07after \\\n"
        "  ghcr.io/usestrix/connector:latest"
    )
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_args, **_kwargs: FakeResponse(
            {"id": "connector-1", "name": "Private network", "docker_command": command}
        ),
    )

    assert cloud.run_cloud(["connectors", "get", "connector-1", "--include-command"]) == 0
    output = capsys.readouterr().out
    assert "TS_AUTHKEY=tskey-" + "a" * 180 in output
    assert "ghcr.io/usestrix/connector:latest" in output
    assert "\\x0a" not in output
    assert "\x1b" not in output
    assert "\\x1b]52;c;copied\\x07" in output


def test_detail_field_cap_counts_only_populated_values() -> None:
    payload = {**{f"unused_{index}": None for index in range(40)}, "result": "visible"}
    output = _console_output(payload)
    assert "visible" in output
    assert "additional field" not in output


def test_empty_envelope_has_a_clear_empty_state() -> None:
    output = _console_output({"webhooks": [], "total": 0}, view="GET /webhooks")
    assert "No items." in output
    assert "{}" not in output


def test_pr_detail_summarizes_nested_findings() -> None:
    findings = [{"severity": "high", "title": f"Finding {index}"} for index in range(12)]
    output = _console_output(
        {
            "id": "review-1",
            "repository_full_name": "usestrix/strix",
            "pr_number": 1177,
            "findings": findings,
        },
        view="GET /pr-reviews/{reviewId}",
    )
    assert "usestrix/strix" in output
    assert "Finding 0" in output
    assert "7 more; use --json" in output
    assert "Finding 11" not in output
    assert len(output.splitlines()) < 25


def test_analytics_views_are_bounded_and_frequency_prefers_activity() -> None:
    overview = {
        f"section_{index}": {f"metric_{inner}": inner for inner in range(10)} for index in range(20)
    }
    overview_output = _console_output(overview, view="GET /analytics/overview")
    assert "Showing 36 of 200 summary metrics" in overview_output
    assert len(overview_output.splitlines()) < 45

    points = [{"date": f"day-{index}", "count": 0} for index in range(300)]
    points[100]["count"] = 3
    points[250]["count"] = 7
    frequency_output = _console_output(
        {"items": points, "total": 300}, view="GET /analytics/scan-frequency"
    )
    assert "day-100" in frequency_output
    assert "day-250" in frequency_output
    assert "day-299" not in frequency_output
    assert "2 non-zero point(s) from 300 total" in frequency_output
    assert len(frequency_output.splitlines()) < 15


def test_nested_webhook_envelope_and_events_render_cleanly() -> None:
    output = _console_output(
        {
            "data": {
                "webhooks": [
                    {
                        "id": "hook-1",
                        "url": "https://example.test/hook",
                        "events": ["scan.completed", "finding.created"],
                        "is_active": True,
                    }
                ],
                "pagination": {"page": 1, "total": 1},
            }
        },
        view="GET /webhooks",
    )
    assert "https://example.test/hook" in output
    assert "scan.completed, finding.created" in output
    assert "pagination" not in output


def test_human_rendering_neutralizes_osc_and_csi_control_sequences() -> None:
    dangerous = "before\x1b]52;c;copied\x07after\x1b[2J\x9b31m"
    outputs = (
        _console_output(dangerous),
        _console_output([{"name": dangerous}], view="GET /scans"),
        _console_output({f"field{dangerous}": dangerous}),
        _console_output({"source": {"files": [dangerous]}}, view="source_manifest"),
    )

    for output in outputs:
        assert "\x1b" not in output
        assert "\x07" not in output
        assert "\x9b" not in output
        assert "\\x1b]52;c;copied\\x07" in output
        assert "\\x1b[2J\\x9b31m" in output


def test_source_prompt_shows_paths_and_literal_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    dangerous_name = "visible\x1b]52;c;copied\x07\x1b[2J.py"
    (tmp_path / dangerous_name).write_text("print('safe')\n", encoding="utf-8")
    output = io.StringIO()
    console = Console(file=output, width=100)
    prompts: list[tuple[str, bool]] = []

    def answer(prompt: str, *, markup: bool = True, **_kwargs: Any) -> str:
        prompts.append((prompt, markup))
        return "n"

    monkeypatch.setattr(console, "input", answer)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    args = argparse.Namespace(
        source=str(tmp_path),
        dry_run=False,
        show_files=True,
        include_hidden=False,
        include_sensitive=False,
        include_archives=False,
        exclude=[],
        yes=False,
    )
    with pytest.raises(http.CloudError, match="cancelled"):
        source_scan.prepare_scan_source(console, args, as_json=False)
    rendered = output.getvalue()
    assert "app.py" in rendered
    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "visible\\x1b]52;c;copied\\x07\\x1b[2J.py" in rendered
    assert prompts == [("Upload this source and start the scan? [y/N]: ", False)]


@pytest.mark.parametrize("failure", [KeyboardInterrupt(), EOFError()])
def test_source_prompt_interruption_removes_temporary_archive(
    failure: BaseException,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    console = Console(file=io.StringIO(), width=100)
    archive_paths: list[Path] = []
    original_prepare = prepare_source

    def capture_bundle(*args: Any, **kwargs: Any) -> Any:
        bundle = original_prepare(*args, **kwargs)
        archive_paths.append(bundle.archive_path)
        return bundle

    def interrupt(*_args: Any, **_kwargs: Any) -> str:
        raise failure

    monkeypatch.setattr(source_scan, "prepare_source", capture_bundle)
    monkeypatch.setattr(console, "input", interrupt)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    args = argparse.Namespace(
        source=str(tmp_path),
        dry_run=False,
        show_files=False,
        include_hidden=False,
        include_sensitive=False,
        include_archives=False,
        exclude=[],
        yes=False,
    )

    with pytest.raises(type(failure)):
        source_scan.prepare_scan_source(console, args, as_json=False)

    assert archive_paths
    assert all(not path.exists() for path in archive_paths)


def test_human_error_neutralizes_terminal_control_sequences() -> None:
    output = io.StringIO()
    console = Console(file=output, width=100)
    runner._emit_error(
        console,
        http.CloudError("failed\x1b]52;c;copied\x07\x1b[2J"),
        as_json=False,
    )
    rendered = output.getvalue()
    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "failed\\x1b]52;c;copied\\x07\\x1b[2J" in rendered


def test_session_human_output_neutralizes_server_control_sequences() -> None:
    dangerous = "value\x1b]52;c;copied\x07\x1b[2J"
    output = io.StringIO()
    console = Console(file=output, width=100)

    platform_cli._print_success(
        console,
        {
            "email": dangerous,
            "organization_name": dangerous,
            "scopes": [dangerous],
        },
    )

    rendered = output.getvalue()
    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert rendered.count("\\x1b]52;c;copied\\x07\\x1b[2J") == 2


def test_device_login_rejects_non_http_verification_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        requests,
        "post",
        lambda *_a, **_k: FakeResponse(
            {
                "device_code": "device-1",
                "user_code": "ABCD",
                "verification_uri": "javascript:alert(1)",
                "expires_in": 300,
            }
        ),
    )

    with pytest.raises(platform_cli.PlatformAuthError, match="invalid verification URL"):
        platform_cli._run_device_flow(Console(file=io.StringIO()), open_browser=False)


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_invalid_timeout_is_a_usage_error_without_request(
    value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(http, "request", lambda *_a, **_k: pytest.fail("must not request"))
    assert cloud.run_cloud(["scans", "list", "--timeout", value, "--json"]) == 2


def test_boolean_query_values_are_lowercase_for_url_search_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _url: str, **kwargs: Any) -> FakeResponse:
        seen["params"] = kwargs.get("params")
        return FakeResponse({"items": []})

    monkeypatch.setattr(requests, "request", fake_request)
    http.request("GET", "/test", query={"enabled": True, "disabled": False})
    assert seen["params"] == {"enabled": "true", "disabled": "false"}


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_workspace_use_invalid_timeout_is_clean(
    value: str, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(http, "request", lambda *_a, **_k: pytest.fail("must not request"))
    assert cloud.run_cloud(["workspaces", "use", "1", "--timeout", value, "--json"]) == 2
    assert "greater than 0" in json.loads(capsys.readouterr().out)["error"]


def test_json_argument_errors_do_not_leak_argparse_prose(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(http, "request", lambda *_a, **_k: pytest.fail("must not request"))

    assert cloud.run_cloud(["scans", "get", "--json"]) == http.EXIT_USAGE
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "SCAN_ID" in payload["error"]
    assert captured.err == ""

    assert cloud.run_cloud(["workspaces", "use", "--json"]) == http.EXIT_USAGE
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "WORKSPACE" in payload["error"]
    assert captured.err == ""


@pytest.mark.parametrize("command", ["whoami", "logout"])
def test_redirected_session_argument_errors_are_json_only(command: str, capsys: Any) -> None:
    assert cloud.run_cloud([command, "--bogus"]) == http.EXIT_USAGE
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert f"strix cloud {command}" in payload["error"]
    assert captured.err == ""


@pytest.mark.parametrize(
    "content_type,payload",
    [
        ("application/pdf", b"%PDF-1.7\n\x1b]52;c;copied\x07"),
        ("application/zip", b"PK\x03\x04\x1b[2J"),
    ],
)
def test_binary_response_refuses_to_write_to_a_terminal(
    content_type: str,
    payload: bytes,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(content=payload, content_type=content_type),
    )

    assert cloud.run_cloud(["scans", "report", "scan-1"]) == http.EXIT_USAGE
    output = capsys.readouterr().out
    assert "binary responses" in output
    assert "--output FILE" in output
    assert "\x1b" not in output


def test_binary_response_can_be_intentionally_redirected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RedirectedStdout:
        def __init__(self) -> None:
            self.buffer = io.BytesIO()

        @staticmethod
        def isatty() -> bool:
            return False

        def write(self, value: str) -> int:
            return len(value)

        def flush(self) -> None:
            return None

    redirected = RedirectedStdout()
    monkeypatch.setattr(sys, "stdout", redirected)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            content=b"PK\x03\x04archive", content_type="application/zip"
        ),
    )

    assert cloud.run_cloud(["chat", "files", "archive", "chat-1"]) == 0
    assert redirected.buffer.getvalue() == b"PK\x03\x04archive"


@pytest.mark.parametrize("failure", ["rejected", "interrupted"])
def test_redirected_binary_errors_never_append_diagnostics_to_stdout(
    failure: str, monkeypatch: pytest.MonkeyPatch, capsysbinary: Any
) -> None:
    class InterruptedResponse(FakeResponse):
        def iter_content(self, *, chunk_size: int) -> Any:
            assert chunk_size == 1024 * 1024
            yield b"%PDF-partial"
            raise requests.ConnectionError("connection lost")

    response = (
        FakeResponse({"detail": "report rejected"}, status_code=500)
        if failure == "rejected"
        else InterruptedResponse(content=b"unused", content_type="application/pdf")
    )
    monkeypatch.setattr(http, "request", lambda *_a, **_k: response)

    assert cloud.run_cloud(["scans", "report", "scan-1"]) == http.EXIT_ERROR
    captured = capsysbinary.readouterr()
    assert captured.out == (b"" if failure == "rejected" else b"%PDF-partial")
    assert b"Error:" in captured.err
    expected = b"report rejected" if failure == "rejected" else b"connection lost"
    assert expected in captured.err


def test_redirected_binary_parse_errors_go_only_to_stderr(
    monkeypatch: pytest.MonkeyPatch, capsysbinary: Any
) -> None:
    monkeypatch.setattr(
        http, "request", lambda *_a, **_k: pytest.fail("invalid usage must not request a report")
    )

    assert cloud.run_cloud(["scans", "report", "scan-1", "--not-an-option"]) == http.EXIT_USAGE
    captured = capsysbinary.readouterr()
    assert captured.out == b""
    assert b"invalid arguments" in captured.err


def test_explicit_json_binary_response_requires_an_output_file(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: pytest.fail("usage must be rejected before downloading"),
    )

    assert cloud.run_cloud(["scans", "report", "scan-1", "--json"]) == http.EXIT_USAGE
    payload = json.loads(capsys.readouterr().out)
    assert "requires --output FILE" in payload["error"]


def test_binary_output_can_return_json_download_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(content=b"%PDF-report", content_type="application/pdf"),
    )
    target = tmp_path / "report.pdf"

    assert (
        cloud.run_cloud(["scans", "report", "scan-1", "--output", str(target), "--json"])
        == http.EXIT_OK
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "output": str(target),
        "bytes": len(b"%PDF-report"),
        "content_type": "application/pdf",
    }
    assert target.read_bytes() == b"%PDF-report"


def test_binary_download_creates_parents_and_requires_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contents = iter((b"first", b"second", b"third"))
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(content=next(contents), content_type="application/pdf"),
    )
    target = tmp_path / "nested" / "report.pdf"
    command = ["scans", "report", "scan-1", "--output", str(target)]
    assert cloud.run_cloud(command) == 0
    assert target.read_bytes() == b"first"
    assert cloud.run_cloud(command) == 1
    assert target.read_bytes() == b"first"
    assert cloud.run_cloud([*command, "--force"]) == 0
    assert target.read_bytes() == b"third"


def test_binary_download_bad_parent_is_a_clean_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(content=b"report", content_type="application/pdf"),
    )
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x", encoding="utf-8")
    assert (
        cloud.run_cloud(["scans", "report", "scan-1", "--output", str(blocker / "report.pdf")]) == 1
    )
    assert "could not write" in capsys.readouterr().out


def test_binary_download_streams_and_preserves_existing_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class InterruptedResponse(FakeResponse):
        closed = False

        def iter_content(self, *, chunk_size: int) -> Any:
            assert chunk_size == 1024 * 1024
            yield b"partial"
            raise requests.ConnectionError("connection lost")

        def close(self) -> None:
            self.closed = True

    response = InterruptedResponse(content=b"must not be buffered", content_type="application/pdf")
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["stream"] = kwargs.get("stream")
        return response

    monkeypatch.setattr(http, "request", fake_request)
    target = tmp_path / "report.pdf"
    target.write_bytes(b"original")
    assert (
        cloud.run_cloud(["scans", "report", "scan-1", "--output", str(target), "--force", "--json"])
        == 1
    )
    assert seen["stream"] is True
    assert target.read_bytes() == b"original"
    assert response.closed is True
    assert list(tmp_path.iterdir()) == [target]


def test_audit_csv_downloads_while_json_remains_parsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    responses = iter(
        (
            FakeResponse(content=b"action,actor\nlogin,alex\n", content_type="text/csv"),
            FakeResponse(payload={"items": [{"action": "login"}], "total": 1}),
        )
    )
    monkeypatch.setattr(http, "request", lambda *_a, **_k: next(responses))
    target = tmp_path / "exports" / "audit.csv"
    assert cloud.run_cloud(["audit", "list", "--format", "csv", "--output", str(target)]) == 0
    assert target.read_text(encoding="utf-8") == "action,actor\nlogin,alex\n"
    capsys.readouterr()
    assert cloud.run_cloud(["audit", "list", "--format", "json", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["items"][0]["action"] == "login"


@pytest.mark.parametrize("format_name", ["ndjson", "jsonl", "snowflake", "splunk"])
def test_audit_ndjson_compatible_formats_download_raw(
    format_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            content=b'{"action":"login"}\n', content_type="application/x-ndjson"
        ),
    )
    target = tmp_path / f"audit-{format_name}.ndjson"
    assert cloud.run_cloud(["audit", "list", "--format", format_name, "--output", str(target)]) == 0
    assert target.read_bytes() == b'{"action":"login"}\n'


def test_credit_limit_payload_code_maps_to_payment_exit() -> None:
    response = FakeResponse(
        {"code": "scan_credit_limit_reached", "detail": "monthly scan credits exhausted"},
        status_code=403,
    )
    with pytest.raises(http.CloudError) as raised:
        http.check(response)  # type: ignore[arg-type]
    assert raised.value.exit_code == http.EXIT_PAYMENT


def test_wait_timeout_is_bounded(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    def response(method: str, _path: str, **_kwargs: Any) -> FakeResponse:
        if method == "POST":
            return FakeResponse({"id": "scan-1", "status": "pending"})
        return FakeResponse({"id": "scan-1", "status": "running"})

    monkeypatch.setattr(http, "request", response)
    assert (
        cloud.run_cloud(
            [
                "scans",
                "start",
                "--domain-ids",
                "domain-1",
                "--wait",
                "--wait-timeout",
                "0.000001",
                "--json",
            ]
        )
        == 1
    )
    assert "wait timed out" in json.loads(capsys.readouterr().out)["error"]


def test_wait_interruption_returns_130_with_remote_operation_id(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    def response(method: str, _path: str, **_kwargs: Any) -> FakeResponse:
        if method == "POST":
            return FakeResponse({"id": "scan-interrupted", "status": "pending"})
        raise KeyboardInterrupt

    monkeypatch.setattr(http, "request", response)
    assert (
        cloud.run_cloud(["scans", "start", "--domain-ids", "domain-1", "--wait", "--json"]) == 130
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["interrupted"] is True
    assert payload["status_unknown"] is True
    assert payload["operation_id"] == "scan-interrupted"


def test_session_help_is_specific_and_human_whoami_shows_scopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.delenv("STRIX_API_TOKEN", raising=False)
    monkeypatch.setattr(platform_cli, "AUTH_PATH", tmp_path / "auth.json")
    platform_cli.save_record(
        {
            "api_token": "secret",
            "email": "alex@example.test",
            "organization_name": "Demo",
            "scopes": ["scans:read", "organizations:read"],
        }
    )
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert cloud.run_cloud(["whoami", "--help"]) == 0
    who_help = capsys.readouterr().out
    assert "strix cloud whoami" in who_help
    assert "--no-browser" not in who_help
    assert cloud.run_cloud(["whoami", "--show-scopes"]) == 0
    assert "scans:read organizations:read" in capsys.readouterr().out


def test_non_tty_whoami_and_logout_emit_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.delenv("STRIX_API_TOKEN", raising=False)
    monkeypatch.setattr(platform_cli, "AUTH_PATH", tmp_path / "auth.json")
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    platform_cli.save_record(
        {
            "api_token": "secret",
            "email": "agent@example.test",
            "organization_name": "Demo",
            "scopes": ["scans:read"],
            "app_url": "https://app.example.test",
        }
    )

    assert cloud.run_cloud(["whoami"]) == 0
    assert json.loads(capsys.readouterr().out)["email"] == "agent@example.test"

    monkeypatch.setattr(
        requests,
        "delete",
        lambda *_args, **_kwargs: type("Response", (), {"status_code": 200})(),
    )
    assert cloud.run_cloud(["logout"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "signed_in": False,
        "removed": True,
        "remotely_revoked": True,
        "local_only": False,
    }
    assert not platform_cli.AUTH_PATH.exists()


def test_scope_picker_labels_match_the_server_presets() -> None:
    output = io.StringIO()
    console = Console(file=output, width=120)
    console.input = lambda *_args, **_kwargs: "1"  # type: ignore[method-assign]
    assert platform_cli._choose_scopes(
        console,
        [{"scope": "scans:read", "min_role": "viewer", "minimum": True}],
        "admin",
    ) == ("recommended", None)
    rendered = output.getvalue()
    assert "uploads" in rendered
    assert "workspace switching" in rendered
    assert "scan read/write and billing read" in rendered


def test_noninteractive_login_never_prompts_for_workspace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    console = Console(file=io.StringIO())
    console.input = lambda *_args, **_kwargs: pytest.fail("must not prompt")  # type: ignore[method-assign]

    with pytest.raises(platform_cli.PlatformAuthError, match="--workspace NAME_OR_ID"):
        platform_cli._choose_workspace(
            console,
            [
                {"id": "org-1", "name": "One"},
                {"id": "org-2", "name": "Two"},
            ],
            None,
        )


def test_login_workspace_selector_prefers_ids_and_rejects_duplicate_names() -> None:
    console = Console(file=io.StringIO())
    organizations = [
        {"id": "org_1", "name": "org_2"},
        {"id": "org_2", "name": "Strix"},
        {"id": "org_3", "name": "Strix"},
    ]

    assert platform_cli._choose_workspace(console, organizations, "org_2")["id"] == "org_2"
    with pytest.raises(platform_cli.PlatformAuthError, match="org_2, org_3"):
        platform_cli._choose_workspace(console, organizations, "Strix")


def test_device_flow_slow_down_never_exceeds_the_poll_interval_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization = FakeResponse(
        {
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://example.test/device",
            "device_code": "device-1",
            "expires_in": 1000,
            "interval": 60,
        }
    )
    polls = iter(
        [
            FakeResponse({"error": "slow_down"}, status_code=400),
            FakeResponse({"error": "slow_down"}, status_code=400),
            FakeResponse({"error": "expired_token"}, status_code=400),
        ]
    )
    calls = 0

    def post(*_args: Any, **_kwargs: Any) -> FakeResponse:
        nonlocal calls
        calls += 1
        return authorization if calls == 1 else next(polls)

    now = 0.0
    sleeps: list[float] = []

    def monotonic() -> float:
        return now

    def sleep(seconds: float) -> None:
        nonlocal now
        sleeps.append(seconds)
        now += seconds

    monkeypatch.setattr(requests, "post", post)
    monkeypatch.setattr(platform_cli, "_app_url", lambda: "https://example.test")
    monkeypatch.setattr(time, "monotonic", monotonic)
    monkeypatch.setattr(time, "sleep", sleep)

    with pytest.raises(platform_cli.PlatformAuthError, match="expired"):
        platform_cli._run_device_flow(
            Console(file=io.StringIO()),
            open_browser=False,
            scopes=["scans:read"],
        )
    assert sleeps == [60, 60, 60]


def test_device_flow_accepts_external_authkit_url_and_binds_token_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = iter(
        [
            FakeResponse(
                {
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "https://auth.example-workos.com/device?code=ABCD",
                    "device_code": "device-1",
                    "expires_in": 300,
                    "interval": 1,
                }
            ),
            FakeResponse(
                {
                    "api_token": "strix_pat_test",
                    "organization_id": "org-1",
                    "scopes": ["scans:read"],
                }
            ),
        ]
    )
    monkeypatch.setattr(requests, "post", lambda *_a, **_k: next(responses))
    monkeypatch.setattr(platform_cli, "_app_url", lambda: "https://preview.strix.ai")
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)

    record = platform_cli._run_device_flow(
        Console(file=io.StringIO()),
        open_browser=False,
        scopes=["scans:read"],
    )

    assert record["app_url"] == "https://preview.strix.ai"
    assert record["requested_scopes"] == ["scans:read"]


def test_missing_verb_json_is_structured(capsys: Any) -> None:
    assert cloud.run_cloud(["uploads", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "strix cloud uploads"
    assert any(item["name"] == "request" for item in payload["verbs"])


@pytest.mark.parametrize(
    "argv",
    [
        ["pr-reviews", "--json", "-h"],
        ["pr-reviews", "--help", "--json"],
        ["workspaces", "--json", "help"],
    ],
)
def test_group_help_accepts_json_and_help_in_either_order(argv: list[str], capsys: Any) -> None:
    assert cloud.run_cloud(argv) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verbs"]
    assert "error" not in payload


def test_root_help_accepts_json_before_help_and_leaf_help_stays_specific(
    capsys: Any,
) -> None:
    assert cloud.run_cloud(["--json", "--help"]) == 0
    assert json.loads(capsys.readouterr().out)["command"] == "strix cloud"

    assert cloud.run_cloud(["scans", "get", "scan-1", "-h"]) == 0
    leaf_help = capsys.readouterr().out
    assert "strix cloud scans get" in leaf_help
    assert "scans verbs" not in leaf_help


def test_non_tty_dispatcher_always_emits_structured_json(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)

    assert cloud.run_cloud([]) == 0
    assert json.loads(capsys.readouterr().out)["command"] == "strix cloud"

    assert cloud.run_cloud(["uploads"]) == 0
    assert json.loads(capsys.readouterr().out)["command"] == "strix cloud uploads"

    assert cloud.run_cloud(["does-not-exist"]) == http.EXIT_USAGE
    assert json.loads(capsys.readouterr().out) == {"error": "unknown command: does-not-exist"}

    assert cloud.run_cloud(["scans", "does-not-exist"]) == http.EXIT_USAGE
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "strix cloud scans"
    assert payload["error"] == "unknown verb"


@pytest.mark.parametrize(
    "signed_url",
    [
        "http://project.supabase.co/storage/v1/object/upload/sign/bucket/file",
        "https://127.0.0.1/storage/v1/object/upload/sign/bucket/file",
        "https://10.0.0.1/storage/v1/object/upload/sign/bucket/file",
        "https://app.strix.ai@127.0.0.1/storage/v1/object/upload/sign/bucket/file",
        "https://evil.example/storage/v1/object/upload/sign/bucket/file",
        "https://project.supabase.co.evil/storage/v1/object/upload/sign/bucket/file",
        "https://project.supabase.co/not-storage/file",
    ],
)
def test_source_upload_rejects_untrusted_destinations_before_reading_file(
    signed_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "approved.zip"
    source.write_bytes(b"approved source")
    monkeypatch.setattr(http, "_app_url_override", "https://app.strix.ai")
    monkeypatch.setattr(
        requests,
        "put",
        lambda *_args, **_kwargs: pytest.fail("an untrusted URL must not receive source bytes"),
    )

    with pytest.raises(http.CloudError, match=r"(untrusted storage origin|storage API|invalid)"):
        http.upload_file(signed_url, "upload-token", source)


@pytest.mark.parametrize(
    "app_url,signed_url",
    [
        (
            "https://app.strix.ai",
            "https://project-ref.supabase.co/storage/v1/object/upload/sign/bucket/file?token=signed%2Fvalue",
        ),
        (
            "https://strix.corp.internal",
            "https://strix.corp.internal/storage/v1/object/upload/sign/bucket/file",
        ),
        (
            "http://127.0.0.1:3000",
            "http://127.0.0.1:3000/storage/v1/object/upload/sign/bucket/file",
        ),
    ],
)
def test_source_upload_allows_only_managed_or_same_origin_storage(
    app_url: str, signed_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "approved.zip"
    source.write_bytes(b"approved source")
    response = FakeResponse({"ok": True})
    request_options: dict[str, Any] = {}

    def put(*_args: Any, **kwargs: Any) -> FakeResponse:
        request_options.update(kwargs)
        return response

    monkeypatch.setattr(http, "_app_url_override", app_url)
    monkeypatch.setattr(requests, "put", put)
    http.upload_file(signed_url, "upload-token", source)

    assert request_options["allow_redirects"] is False
    assert response.closed is True


def test_source_upload_refuses_redirects_without_following_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "approved.zip"
    source.write_bytes(b"approved source")
    response = FakeResponse(None, status_code=307)
    response.headers["location"] = "http://169.254.169.254/latest/meta-data"
    request_options: dict[str, Any] = {}

    def put(*_args: Any, **kwargs: Any) -> FakeResponse:
        request_options.update(kwargs)
        return response

    monkeypatch.setattr(http, "_app_url_override", "https://app.strix.ai")
    monkeypatch.setattr(requests, "put", put)

    with pytest.raises(http.CloudError, match="unexpected redirect"):
        http.upload_file(
            "https://project-ref.supabase.co/storage/v1/object/upload/sign/bucket/file",
            "upload-token",
            source,
        )
    assert request_options["allow_redirects"] is False
    assert response.closed is True


def test_one_time_api_token_has_save_now_warning(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse({"id": "token-1", "token": "strix_pat_once"}),
    )
    assert cloud.run_cloud(["tokens", "create", "--type", "personal", "--name", "test"]) == 0
    output = capsys.readouterr().out
    assert "Save this now" in output
    assert "shown only once" in output


def test_root_help_advertises_cloud_and_completions(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys, "argv", ["strix", "--help"])
    with pytest.raises(SystemExit) as raised:
        interface_main()
    assert raised.value.code == 0
    output = capsys.readouterr().out
    assert "strix cloud" in output
    assert "strix completions" in output
