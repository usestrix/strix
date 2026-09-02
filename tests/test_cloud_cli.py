"""Tests for the `strix cloud` CLI: routing, request building, and output."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any

import pytest
import requests
from rich.console import Console

from strix.interface import cloud, platform_cli
from strix.interface.cloud import http, render, runner, workspaces
from strix.interface.cloud.spec import GROUP_HELP, SPEC


class FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        payload: Any = None,
        text: str = "",
        content: bytes = b"",
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text if payload is None else json.dumps(payload)
        self.content = content
        self.ok = 200 <= status_code < 400
        self.headers = {"content-type": "application/json" if payload is not None else "text/plain"}

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no JSON")
        return self._payload

    def iter_content(self, chunk_size: int) -> Any:
        for index in range(0, len(self.content), chunk_size):
            yield self.content[index : index + chunk_size]

    def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _token_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_API_TOKEN", "test-token")


def test_help_returns_zero() -> None:
    assert cloud.run_cloud([]) == 0
    assert cloud.run_cloud(["--help"]) == 0


def test_unknown_group_returns_usage_error() -> None:
    assert cloud.run_cloud(["bogus"]) == 2


def test_unknown_verb_returns_usage_error() -> None:
    assert cloud.run_cloud(["scans", "bogus"]) == 2


def test_successful_html_response_is_reported_without_dumping_html(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(text="<!DOCTYPE html><html>preview gate</html>"),
    )

    assert cloud.run_cloud(["workspaces", "list", "--json"]) == 1
    output = capsys.readouterr().out
    assert "non-JSON response" in output
    assert "STRIX_APP_URL" in output
    assert "<!DOCTYPE" not in output


def test_successful_malformed_json_response_is_rejected(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    response = FakeResponse(text="accepted")
    response.headers = {"content-type": "application/json"}
    monkeypatch.setattr(http, "request", lambda *_a, **_k: response)

    assert cloud.run_cloud(["workspaces", "list", "--json"]) == 1
    output = capsys.readouterr().out
    assert "malformed JSON" in output
    assert "accepted" not in output


def test_group_without_safe_read_default_lists_verbs() -> None:
    assert cloud.run_cloud(["uploads"]) == 0


def test_resolve_prefers_two_word_verbs() -> None:
    resolved = runner.resolve("billing", ["auto-topup", "update", "--enabled"])
    assert resolved is not None
    cmd, remaining = resolved
    assert cmd.path == "/billing/auto-topup"
    assert cmd.method == "PUT"
    assert remaining == ["--enabled"]


def test_resolve_default_verb() -> None:
    resolved = runner.resolve("audit", [])
    assert resolved is not None
    cmd, remaining = resolved
    assert cmd.method == "GET"
    assert remaining == []


@pytest.mark.parametrize(
    ("group", "verb"),
    [
        ("scans", "list"),
        ("vulns", "list"),
        ("domains", "list"),
        ("repos", "list"),
        ("schedules", "list"),
        ("pr-reviews", "list"),
        ("billing", "credits"),
        ("chat", "list"),
        ("knowledge", "list"),
        ("org", "get"),
        ("integrations", "list"),
        ("connectors", "list"),
        ("webhooks", "list"),
        ("analytics", "overview"),
        ("audit", "list"),
        ("costs", "overview"),
        ("llm-settings", "get"),
        ("settings", "notifications"),
        ("license", "show"),
        ("tokens", "list"),
        ("supply-chain", "summary"),
        ("workspaces", "list"),
    ],
)
def test_read_groups_have_safe_defaults(group: str, verb: str) -> None:
    resolved = runner.resolve(group, [])
    assert resolved is not None
    command, remaining = resolved
    assert command is SPEC[group][verb]
    assert remaining == []


def test_dest_converts_camel_case() -> None:
    assert runner._dest("scanId") == "scan_id"
    assert runner._dest("chatId") == "chat_id"
    assert runner._metavar("findingId") == "FINDING_ID"


def test_placeholder_substitution(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    seen: dict[str, Any] = {}

    def fake_request(method: str, path: str, **kwargs: Any) -> FakeResponse:
        seen.update(method=method, path=path, query=kwargs.get("query"))
        return FakeResponse(payload={"id": "abc"})

    monkeypatch.setattr(http, "request", fake_request)
    code = cloud.run_cloud(["scans", "get", "abc-123", "--json"])
    assert code == 0
    assert seen["method"] == "GET"
    assert seen["path"] == "/scans/abc-123"
    assert json.loads(capsys.readouterr().out) == {"id": "abc"}


def test_placeholder_substitution_percent_encodes_path_segments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, path: str, **_kwargs: Any) -> FakeResponse:
        seen["path"] = path
        return FakeResponse(payload={"entries": []})

    monkeypatch.setattr(http, "request", fake_request)
    code = cloud.run_cloud(["knowledge", "repos", "entries", "usestrix/.github", "--json"])
    assert code == 0
    assert seen["path"] == "/knowledge/repos/usestrix%2F.github/entries"


def test_query_and_body_collection(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_request(method: str, path: str, **kwargs: Any) -> FakeResponse:
        seen.update(query=kwargs.get("query"), body=kwargs.get("body"))
        if method == "POST" and path == "/scans":
            return FakeResponse(payload={"scan_id": "scan-1", "status": "pending"})
        return FakeResponse(payload={"ok": True})

    monkeypatch.setattr(http, "request", fake_request)
    assert cloud.run_cloud(["scans", "list", "--status", "running", "--json"]) == 0
    assert seen["query"] == {"status": "running"}

    assert (
        cloud.run_cloud(
            [
                "scans",
                "start",
                "--engagement-type",
                "live_test",
                "--domain-ids",
                "d1",
                "d2",
                "--json",
            ]
        )
        == 0
    )
    assert seen["body"] == {"engagement_type": "live_test", "domain_ids": ["d1", "d2"]}


def test_data_merges_extra_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["body"] = kwargs.get("body")
        return FakeResponse(payload={"scan_id": "scan-1", "status": "pending"})

    monkeypatch.setattr(http, "request", fake_request)
    code = cloud.run_cloud(
        ["scans", "start", "--data", '{"engagement_type": "code_review"}', "--json"]
    )
    assert code == 0
    assert seen["body"] == {"engagement_type": "code_review"}


def test_token_create_accepts_expiry_and_rbac_scope_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["body"] = kwargs.get("body")
        return FakeResponse(payload={"id": "token-1", "token": "strix_pat_once"})

    monkeypatch.setattr(http, "request", fake_request)
    code = cloud.run_cloud(
        [
            "tokens",
            "create",
            "--type",
            "service",
            "--name",
            "ci",
            "--expires-at",
            "2026-09-30T12:00:00Z",
            "--rbac-scopes",
            '[{"type":"tag","value":"staging"}]',
            "--json",
        ]
    )

    assert code == 0
    assert seen["body"] == {
        "type": "service",
        "name": "ci",
        "expires_at": "2026-09-30T12:00:00Z",
        "rbac_scopes": [{"type": "tag", "value": "staging"}],
    }


def test_token_create_rejects_non_array_rbac_scopes(capsys: Any) -> None:
    code = cloud.run_cloud(
        [
            "tokens",
            "create",
            "--type",
            "service",
            "--name",
            "ci",
            "--rbac-scopes",
            '{"type":"tag","value":"staging"}',
            "--json",
        ]
    )

    assert code == http.EXIT_USAGE
    assert json.loads(capsys.readouterr().out)["error"] == ("--rbac-scopes must be a JSON array")


def test_token_create_rejects_two_expiration_modes(capsys: Any) -> None:
    code = cloud.run_cloud(
        [
            "tokens",
            "create",
            "--type",
            "personal",
            "--name",
            "local",
            "--expires-at",
            "2026-09-30T12:00:00Z",
            "--expires-in-days",
            "30",
            "--json",
        ]
    )

    assert code == http.EXIT_USAGE
    assert json.loads(capsys.readouterr().out)["error"] == (
        "--expires-at and --expires-in-days are mutually exclusive."
    )


def test_data_reads_a_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["body"] = kwargs.get("body")
        return FakeResponse(payload={"scan_id": "scan-1", "status": "pending"})

    monkeypatch.setattr(http, "request", fake_request)
    request_file = tmp_path / "request.json"
    request_file.write_text('{"focus": "IDOR"}', encoding="utf-8")
    assert cloud.run_cloud(["scans", "start", "--data", f"@{request_file}", "--json"]) == 0
    assert seen["body"] == {"focus": "IDOR"}


def test_data_reads_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["body"] = kwargs.get("body")
        return FakeResponse(payload={"scan_id": "scan-1", "status": "pending"})

    monkeypatch.setattr(http, "request", fake_request)
    monkeypatch.setattr("sys.stdin", io.StringIO('{"context": "staging"}'))
    assert cloud.run_cloud(["scans", "start", "--data", "-", "--json"]) == 0
    assert seen["body"] == {"context": "staging"}


def test_required_secret_body_field_can_come_from_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["body"] = kwargs.get("body")
        return FakeResponse(payload={"ok": True})

    monkeypatch.setattr(http, "request", fake_request)
    monkeypatch.setattr("sys.stdin", io.StringIO('{"access_token":"provider-secret"}'))

    assert cloud.run_cloud(["integrations", "connect", "gitlab", "--data", "-", "--json"]) == 0
    assert seen["body"] == {"access_token": "provider-secret"}


def test_provider_token_does_not_override_strix_api_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen.update(token=kwargs.get("token"), body=kwargs.get("body"))
        return FakeResponse(payload={"ok": True})

    monkeypatch.setattr(http, "request", fake_request)

    assert (
        cloud.run_cloud(
            [
                "integrations",
                "connect",
                "gitlab",
                "--provider-token",
                "provider-secret",
                "--instance-url",
                "https://gitlab.com",
                "--json",
            ]
        )
        == 0
    )
    assert seen == {
        "token": None,
        "body": {
            "access_token": "provider-secret",
            "instance_url": "https://gitlab.com",
        },
    }


def test_required_body_field_is_validated_after_data_merge(capsys: Any) -> None:
    assert cloud.run_cloud(["integrations", "connect", "gitlab", "--json"]) == http.EXIT_USAGE
    assert "--provider-token" in json.loads(capsys.readouterr().out)["error"]


def test_data_reports_a_missing_file(tmp_path: Path) -> None:
    assert cloud.run_cloud(["scans", "start", "--data", f"@{tmp_path / 'nope.json'}"]) == 1


def test_auto_topup_removes_the_monthly_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["body"] = kwargs.get("body")
        return FakeResponse(payload={"ok": True})

    monkeypatch.setattr(http, "request", fake_request)
    code = cloud.run_cloud(
        [
            "billing",
            "auto-topup",
            "update",
            "--enabled",
            "--topup-credits",
            "20",
            "--no-monthly-cap",
            "--json",
        ]
    )
    assert code == 0
    assert seen["body"] == {
        "enabled": True,
        "topup_credits": 20,
        "monthly_cap_credits": None,
    }


def test_costs_default_verb_is_the_overview(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, path: str, **_kwargs: Any) -> FakeResponse:
        seen["path"] = path
        return FakeResponse(payload={"total_cost": 1})

    monkeypatch.setattr(http, "request", fake_request)
    assert cloud.run_cloud(["costs", "--json"]) == 0
    assert seen["path"] == "/llm-costs"


def test_binary_download_writes_a_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        http, "request", lambda *_a, **_k: FakeResponse(status_code=200, content=b"%PDF-1.7")
    )
    target = tmp_path / "report.pdf"
    assert cloud.run_cloud(["scans", "report", "scan-1", "--output", str(target)]) == 0
    assert target.read_bytes() == b"%PDF-1.7"


def test_wait_polls_until_the_status_is_final(monkeypatch: pytest.MonkeyPatch) -> None:
    statuses = iter(["running", "completed"])

    def fake_request(method: str, _path: str, **_kwargs: Any) -> FakeResponse:
        if method == "POST":
            return FakeResponse(payload={"id": "scan-1", "status": "pending"})
        return FakeResponse(payload={"id": "scan-1", "status": next(statuses)})

    monkeypatch.setattr(http, "request", fake_request)
    monkeypatch.setattr(runner, "_WAIT_POLL_S", 0)
    assert cloud.run_cloud(["scans", "start", "--domain-ids", "d1", "--wait", "--json"]) == 0
    assert next(statuses, None) is None


def test_wait_failure_keeps_the_created_operation_id(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    def fake_request(method: str, _path: str, **_kwargs: Any) -> FakeResponse:
        if method == "POST":
            return FakeResponse(payload={"id": "scan-created", "status": "running"})
        return FakeResponse(status_code=503, payload={"detail": "temporarily unavailable"})

    monkeypatch.setattr(http, "request", fake_request)
    assert cloud.run_cloud(["scans", "start", "--domain-ids", "d1", "--wait", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["operation_id"] == "scan-created"
    assert payload["status_unknown"] is True


def test_ambiguous_scan_request_warns_before_retry(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(
        http,
        "request",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(http.CloudError("connection reset")),
    )

    assert cloud.run_cloud(["scans", "start", "--domain-ids", "d1", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["launch_outcome_unknown"] is True
    assert "scans list" in payload["error"]


@pytest.mark.parametrize("response_payload", [{}, "accepted"])
def test_malformed_scan_success_is_reported_as_ambiguous(
    response_payload: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(
        http,
        "request",
        lambda *_args, **_kwargs: FakeResponse(payload=response_payload),
    )

    assert cloud.run_cloud(["scans", "start", "--domain-ids", "d1", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["launch_outcome_unknown"] is True
    assert payload["retry_safe"] is True
    assert payload["idempotency_key"]
    assert "scans list" in payload["error"]


@pytest.mark.parametrize(
    "command",
    [
        ["scans", "rerun", "scan-1", "--wait", "--json"],
        ["vulns", "retest", "vuln-1", "--wait", "--json"],
    ],
)
def test_waitable_scan_mutation_requires_an_operation_id(
    command: list[str], monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(http, "request", lambda *_a, **_k: FakeResponse(payload={}))

    assert cloud.run_cloud(command) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["launch_outcome_unknown"] is True
    assert "successful operation response without an operation ID" in payload["error"]


def test_insufficient_credits_exits_with_payment_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        http, "request", lambda *_a, **_k: FakeResponse(status_code=402, payload={})
    )
    assert cloud.run_cloud(["scans", "start", "--domain-ids", "d1"]) == http.EXIT_PAYMENT


def test_insufficient_credits_always_prints_topup_instruction(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            status_code=402,
            payload={"detail": "Out of credits.", "code": "scan_credit_limit_reached"},
        ),
    )
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    argv = ["scans", "start", "--domain-ids", "d1", "--app-url", "https://app.strix.ai"]
    assert cloud.run_cloud(argv) == http.EXIT_PAYMENT
    output = " ".join(capsys.readouterr().out.split())
    assert "Error: Out of credits." in output
    assert "Next step:" in output
    assert "strix cloud billing topup --credits <count>" in output
    assert "https://app.strix.ai/settings/billing" in output
    assert "strix cloud billing credits" in output


def test_insufficient_credits_shows_platform_hint_once(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    hint = "Buy credits at https://app.strix.ai/settings/billing. Then retry this request."
    payload = {
        "detail": f"Out of credits. {hint}",
        "code": "scan_credit_limit_reached",
        "hint": hint,
        "topup_url": "https://app.strix.ai/settings/billing",
    }
    monkeypatch.setattr(
        http, "request", lambda *_a, **_k: FakeResponse(status_code=402, payload=payload)
    )
    assert cloud.run_cloud(["scans", "start", "--domain-ids", "d1", "--json"]) == http.EXIT_PAYMENT
    result = json.loads(capsys.readouterr().out)
    assert result["error"] == "Out of credits."
    assert result["next_step"] == hint
    assert result["topup_url"] == "https://app.strix.ai/settings/billing"

    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert cloud.run_cloud(["scans", "start", "--domain-ids", "d1"]) == http.EXIT_PAYMENT
    output = " ".join(capsys.readouterr().out.split())
    assert output.count(hint) == 1
    assert "Error: Out of credits." in output
    assert f"Next step: {hint}" in output


def test_payment_required_without_body_names_the_topup_command(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(
        http, "request", lambda *_a, **_k: FakeResponse(status_code=402, payload={})
    )
    argv = ["scans", "start", "--domain-ids", "d1", "--json", "--app-url", "https://app.strix.ai"]
    assert cloud.run_cloud(argv) == http.EXIT_PAYMENT
    result = json.loads(capsys.readouterr().out)
    assert result["error"] == "Not enough credits to run this command."
    assert "strix cloud billing topup --credits <count>" in result["next_step"]
    assert "https://app.strix.ai/settings/billing" in result["next_step"]


def test_data_rejects_non_object() -> None:
    assert cloud.run_cloud(["scans", "start", "--data", "[1,2]"]) == http.EXIT_USAGE
    assert cloud.run_cloud(["scans", "start", "--data", "not json"]) == http.EXIT_USAGE


def test_typed_json_flag_parse_error_is_usage_error() -> None:
    assert cloud.run_cloud(["scans", "start", "--domain-paths", "not-json"]) == http.EXIT_USAGE


def test_missing_token_exits_with_auth_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("STRIX_API_TOKEN", raising=False)
    monkeypatch.setattr(platform_cli, "AUTH_PATH", tmp_path / "platform-auth.json")
    assert cloud.run_cloud(["credits"]) == http.EXIT_AUTH


def test_stored_token_is_never_sent_to_a_different_platform_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_API_TOKEN", raising=False)
    monkeypatch.setattr(http, "_app_url_override", "https://attacker.example")
    monkeypatch.setattr(
        http,
        "read_record",
        lambda: {"api_token": "stored-secret", "app_url": "https://app.strix.ai"},
    )
    monkeypatch.setattr(
        requests,
        "request",
        lambda *_args, **_kwargs: pytest.fail("a mismatched origin must not receive the token"),
    )

    with pytest.raises(http.CloudError, match="different platform") as raised:
        http.request("GET", "/billing/credits")
    assert raised.value.exit_code == http.EXIT_AUTH


def test_stored_token_requires_an_issuer_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_API_TOKEN", raising=False)
    monkeypatch.setattr(http, "_app_url_override", "https://app.strix.ai")
    monkeypatch.setattr(http, "read_record", lambda: {"api_token": "legacy-secret"})
    monkeypatch.setattr(
        requests,
        "request",
        lambda *_args, **_kwargs: pytest.fail("an unbound token must not be sent"),
    )

    with pytest.raises(http.CloudError, match="not bound") as raised:
        http.request("GET", "/billing/credits")
    assert raised.value.exit_code == http.EXIT_AUTH


def test_stored_token_is_sent_only_to_its_bound_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_API_TOKEN", raising=False)
    monkeypatch.setattr(http, "_app_url_override", "https://preview.strix.ai")
    monkeypatch.setattr(
        http,
        "read_record",
        lambda: {"api_token": "stored-secret", "app_url": "https://preview.strix.ai"},
    )
    seen: dict[str, Any] = {}

    def request(_method: str, url: str, **kwargs: Any) -> FakeResponse:
        seen.update(url=url, headers=kwargs["headers"])
        return FakeResponse(payload={"balance": 1})

    monkeypatch.setattr(requests, "request", request)
    response = http.request("GET", "/billing/credits")

    assert response.status_code == 200
    assert seen["url"] == "https://preview.strix.ai/api/v1/billing/credits"
    assert seen["headers"]["Authorization"] == "Bearer stored-secret"


def test_explicit_token_can_target_an_explicit_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_API_TOKEN", raising=False)
    monkeypatch.setattr(http, "_app_url_override", "https://preview.strix.ai")
    monkeypatch.setattr(
        http,
        "read_record",
        lambda: {"api_token": "stored-secret", "app_url": "https://app.strix.ai"},
    )
    seen: dict[str, Any] = {}

    def request(_method: str, url: str, **kwargs: Any) -> FakeResponse:
        seen.update(url=url, headers=kwargs["headers"])
        return FakeResponse(payload={"balance": 1})

    monkeypatch.setattr(requests, "request", request)
    override_value = "explicit-preview-" + str(1)
    response = http.request("GET", "/billing/credits", token=override_value)

    assert response.status_code == 200
    assert seen["url"] == "https://preview.strix.ai/api/v1/billing/credits"
    assert seen["headers"]["Authorization"] == f"Bearer {override_value}"


def test_http_error_exit_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    for status, expected in ((401, http.EXIT_AUTH), (403, http.EXIT_AUTH), (500, http.EXIT_ERROR)):
        monkeypatch.setattr(
            http,
            "request",
            lambda *_a, _s=status, **_k: FakeResponse(status_code=_s, payload={"error": "x"}),
        )
        assert cloud.run_cloud(["scans", "list"]) == expected


def test_credits_alias_routes_to_billing(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, path: str, **_kwargs: Any) -> FakeResponse:
        seen["path"] = path
        return FakeResponse(payload={"balance": 3})

    monkeypatch.setattr(http, "request", fake_request)
    assert cloud.run_cloud(["credits", "--json"]) == 0
    assert seen["path"] == "/billing/credits"


def test_whoami_json_is_machine_readable_and_omits_the_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: Any
) -> None:
    monkeypatch.delenv("STRIX_API_TOKEN", raising=False)
    monkeypatch.setattr(platform_cli, "AUTH_PATH", tmp_path / "platform-auth.json")
    platform_cli.save_record(
        {
            "api_token": "strix_pat_secret",
            "email": "agent@example.test",
            "organization_id": "org_1",
            "organization_name": "Example",
            "scopes": ["scans:read"],
            "expires_at": "2026-09-01T00:00:00Z",
        }
    )

    assert cloud.run_cloud(["whoami", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "signed_in": True,
        "email": "agent@example.test",
        "organization_id": "org_1",
        "organization_name": "Example",
        "scopes": ["scans:read"],
        "expires_at": "2026-09-01T00:00:00Z",
    }
    assert "api_token" not in payload


def test_topup_no_pay_prints_challenge(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    challenge = {"payment_requirements": [{"amount": 500}]}
    monkeypatch.setattr(
        http, "request", lambda *_a, **_k: FakeResponse(status_code=402, payload=challenge)
    )
    code = cloud.run_cloud(["billing", "topup", "--credits", "5", "--no-pay", "--json"])
    assert code == http.EXIT_PAYMENT
    assert json.loads(capsys.readouterr().out) == {
        "error": "Payment required",
        "challenge": challenge,
    }


def test_topup_noninteractive_requires_explicit_payment_approval(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    challenge = {"payment_requirements": [{"amount": 500}]}
    monkeypatch.setattr(
        http, "request", lambda *_a, **_k: FakeResponse(status_code=402, payload=challenge)
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: pytest.fail("wallet must not run without --yes"),
    )

    code = cloud.run_cloud(["billing", "topup", "--credits", "5", "--json"])

    assert code == http.EXIT_PAYMENT
    payload = json.loads(capsys.readouterr().out)
    assert "requires explicit approval" in payload["error"]
    assert payload["challenge"] == challenge


@pytest.mark.parametrize("explicit_json,stdout_tty", [(True, True), (False, False)])
def test_topup_machine_output_never_prompts_even_with_terminal_stdin(
    explicit_json: bool,
    stdout_tty: bool,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    challenge = {"payment_requirements": [{"amount": 500}]}
    monkeypatch.setattr(
        http, "request", lambda *_a, **_k: FakeResponse(status_code=402, payload=challenge)
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: stdout_tty)
    monkeypatch.setattr(
        Console,
        "input",
        lambda *_a, **_k: pytest.fail("machine-readable top-up must not prompt"),
    )

    argv = ["billing", "topup", "--credits", "5"]
    if explicit_json:
        argv.append("--json")
    assert cloud.run_cloud(argv) == http.EXIT_PAYMENT

    payload = json.loads(capsys.readouterr().out)
    assert "requires explicit approval" in payload["error"]
    assert payload["challenge"] == challenge


def test_topup_payment_flags_are_mutually_exclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(http, "request", lambda *_a, **_k: pytest.fail("must not request"))
    assert (
        cloud.run_cloud(["billing", "topup", "--credits", "5", "--yes", "--no-pay", "--json"])
        == http.EXIT_USAGE
    )


def test_data_cannot_override_an_explicit_payment_amount(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(http, "request", lambda *_a, **_k: pytest.fail("must not request"))

    assert (
        cloud.run_cloud(
            [
                "billing",
                "topup",
                "--credits",
                "5",
                "--data",
                '{"credits": 500}',
                "--yes",
                "--json",
            ]
        )
        == http.EXIT_USAGE
    )
    assert "cannot override explicit" in json.loads(capsys.readouterr().out)["error"]


def test_topup_missing_wallet_keeps_json_machine_readable(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    challenge = {"payment_requirements": [{"amount": 500}]}
    monkeypatch.setattr(
        http, "request", lambda *_a, **_k: FakeResponse(status_code=402, payload=challenge)
    )
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    code = cloud.run_cloud(["billing", "topup", "--credits", "5", "--yes", "--json"])

    assert code == http.EXIT_PAYMENT
    payload = json.loads(capsys.readouterr().out)
    assert "wallet client" in payload["error"]
    assert payload["challenge"] == challenge


def test_topup_success_without_payment(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    receipt = {"credits_granted": 5, "duplicate": False, "balance": 5}
    monkeypatch.setattr(
        http, "request", lambda *_a, **_k: FakeResponse(status_code=200, payload=receipt)
    )
    code = cloud.run_cloud(["billing", "topup", "--credits", "5", "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out) == receipt


def test_topup_keeps_token_out_of_wallet_process_and_forwards_payment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    challenge = {"payment_requirements": [{"amount": 500}]}
    receipt = {
        "credits_granted": 5,
        "duplicate": False,
        "reference": "pay_test_1",
        "balance": 10,
    }
    api_credential = "opaque-test-api-credential-value"
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".npmrc").write_text("registry=https://malicious.invalid\n", encoding="utf-8")
    monkeypatch.setenv("UNRELATED_CODING_AGENT_SECRET", "must-not-reach-wallet")
    monkeypatch.setattr(
        http, "request", lambda *_a, **_k: FakeResponse(status_code=402, payload=challenge)
    )
    monkeypatch.setattr(http, "api_token", lambda *_a, **_k: api_credential)
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/npx")
    commands: list[list[str]] = []
    child_envs: list[dict[str, str]] = []
    child_cwds: list[Path] = []
    upstream: dict[str, Any] = {}

    def fake_upstream_request(method: str, url: str, **kwargs: Any) -> FakeResponse:
        upstream.update(method=method, url=url, **kwargs)
        return FakeResponse(payload=receipt, content=json.dumps(receipt).encode())

    monkeypatch.setattr(requests, "request", fake_upstream_request)

    def fake_run(command: list[str], **kwargs: Any) -> Any:
        commands.append(command)
        child_envs.append(kwargs["env"])
        child_cwds.append(Path(kwargs["cwd"]))
        wallet_url = next(
            argument for argument in command if argument.startswith("http://127.0.0.1:")
        )
        request = urllib.request.Request(  # noqa: S310
            wallet_url,
            data=json.dumps({"credits": 5}).encode(),
            headers={
                "Authorization": "Payment wallet-credential",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=2) as response:  # noqa: S310
            stdout = response.read().decode()
        return type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": stdout,
                "stderr": "",
            },
        )()

    monkeypatch.setattr(subprocess, "run", fake_run)
    code = cloud.run_cloud(
        ["billing", "topup", "--credits", "5", "--yes", "--payment-method", "pm_card_visa"]
    )
    assert code == 0
    assert all(api_credential not in argument for argument in commands[0])
    assert "mppx@0.8.17" in commands[0]
    assert "--registry=https://registry.npmjs.org" in commands[0]
    assert "--ignore-scripts" in commands[0]
    assert "-H" not in commands[0]
    assert "--fail" in commands[0]
    assert child_envs[0].get("STRIX_API_TOKEN") is None
    assert child_envs[0].get("UNRELATED_CODING_AGENT_SECRET") is None
    for name in ("NO_PROXY", "no_proxy"):
        bypasses = child_envs[0][name].split(",")
        assert "127.0.0.1" in bypasses
        assert "localhost" in bypasses
        assert "::1" in bypasses
    assert child_cwds[0] != tmp_path
    assert upstream["method"] == "POST"
    assert upstream["url"].endswith("/api/v1/billing/topup")
    assert upstream["headers"]["X-Strix-Authorization"] == f"Bearer {api_credential}"
    assert upstream["headers"]["Authorization"] == "Payment wallet-credential"
    assert upstream["data"] == json.dumps({"credits": 5}).encode()
    assert "-M" in commands[0]
    assert "paymentMethod=pm_card_visa" in commands[0]


def test_topup_wallet_failure_is_one_redacted_json_object(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    challenge = {"payment_requirements": [{"amount": 500}]}
    monkeypatch.setattr(
        http, "request", lambda *_a, **_k: FakeResponse(status_code=402, payload=challenge)
    )
    monkeypatch.setattr(http, "api_token", lambda *_a, **_k: "tok")
    monkeypatch.setenv("MPPX_ACCOUNT", "agent")
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/npx")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: type(
            "Result",
            (),
            {
                "returncode": 9,
                "stdout": "",
                "stderr": (
                    "failed with Bearer super-secret and "
                    "Authorization: Payment wallet-super-secret\x1b[2J"
                ),
            },
        )(),
    )

    assert cloud.run_cloud(["billing", "topup", "--credits", "5", "--yes", "--json"]) == 5
    payload = json.loads(capsys.readouterr().out)
    assert payload["wallet_exit_code"] == 9
    assert payload["payment_outcome_unknown"] is True
    assert "billing credits" in payload["error"]
    assert "super-secret" not in payload["detail"]
    assert "Bearer [redacted]" in payload["detail"]
    assert "Payment [redacted]" in payload["detail"]
    assert "\x1b" not in payload["detail"]


def test_topup_wallet_interruption_reports_unknown_payment_outcome(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            status_code=402,
            payload={"payment_requirements": [{"amount": 500}]},
        ),
    )
    monkeypatch.setattr(http, "api_token", lambda *_a, **_k: "tok")
    monkeypatch.setenv("MPPX_ACCOUNT", "agent")
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/npx")
    monkeypatch.setattr(
        subprocess, "run", lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt)
    )

    assert cloud.run_cloud(["billing", "topup", "--credits", "5", "--yes", "--json"]) == 130
    payload = json.loads(capsys.readouterr().out)
    assert payload["interrupted"] is True
    assert payload["payment_outcome_unknown"] is True
    assert "billing credits" in payload["error"]
    assert "before retrying" in payload["error"]


def test_topup_non_json_wallet_success_requires_balance_verification(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            status_code=402,
            payload={"payment_requirements": [{"amount": 500}]},
        ),
    )
    monkeypatch.setattr(http, "api_token", lambda *_a, **_k: "tok")
    monkeypatch.setenv("MPPX_ACCOUNT", "agent")
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/npx")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: type("Result", (), {"returncode": 0, "stdout": "paid", "stderr": ""})(),
    )

    assert cloud.run_cloud(["billing", "topup", "--credits", "5", "--yes", "--json"]) == 5
    payload = json.loads(capsys.readouterr().out)
    assert "did not return JSON" in payload["error"]
    assert "before retrying" in payload["error"]
    assert payload["payment_outcome_unknown"] is True


def test_topup_rejects_parseable_wallet_error_as_a_success(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            status_code=402,
            payload={"payment_requirements": [{"amount": 500}]},
        ),
    )
    monkeypatch.setattr(http, "api_token", lambda *_a, **_k: "tok")
    monkeypatch.setenv("MPPX_ACCOUNT", "agent")
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/npx")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": '{"detail":"Failed to process the top-up payment"}',
                "stderr": "",
            },
        )(),
    )

    assert cloud.run_cloud(["billing", "topup", "--credits", "5", "--yes", "--json"]) == 5
    payload = json.loads(capsys.readouterr().out)
    assert "invalid top-up receipt" in payload["error"]
    assert payload["payment_outcome_unknown"] is True


def test_topup_does_not_trust_an_unobserved_wallet_receipt(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    receipt = {
        "credits_granted": 5,
        "duplicate": False,
        "reference": "untrusted-wallet-output",
        "balance": 10,
    }
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            status_code=402,
            payload={"payment_requirements": [{"amount": 500}]},
        ),
    )
    monkeypatch.setattr(http, "api_token", lambda *_a, **_k: "tok")
    monkeypatch.setenv("MPPX_ACCOUNT", "agent")
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/npx")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: type(
            "Result",
            (),
            {"returncode": 0, "stdout": json.dumps(receipt), "stderr": ""},
        )(),
    )

    assert cloud.run_cloud(["billing", "topup", "--credits", "5", "--yes", "--json"]) == 5
    payload = json.loads(capsys.readouterr().out)
    assert "did not confirm" in payload["error"]
    assert payload["payment_outcome_unknown"] is True


def test_topup_human_mode_requires_a_bridge_confirmed_receipt(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            status_code=402,
            payload={"payment_requirements": [{"amount": 500}]},
        ),
    )
    monkeypatch.setattr(http, "api_token", lambda *_a, **_k: "tok")
    monkeypatch.setenv("MPPX_ACCOUNT", "agent")
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/npx")
    monkeypatch.setattr(
        requests,
        "request",
        lambda *_a, **_k: FakeResponse(status_code=200, content=b"<html>not a receipt</html>"),
    )

    def fake_run(command: list[str], **_kwargs: Any) -> Any:
        wallet_url = next(
            argument for argument in command if argument.startswith("http://127.0.0.1:")
        )
        request = urllib.request.Request(  # noqa: S310
            wallet_url,
            data=json.dumps({"credits": 5}).encode(),
            headers={"Authorization": "Payment wallet-credential"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=2) as response:  # noqa: S310
            response.read()
        return type("Result", (), {"returncode": 0, "stdout": None, "stderr": None})()

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert cloud.run_cloud(["billing", "topup", "--credits", "5", "--yes"]) == 5
    output = capsys.readouterr().out
    assert "without a confirmed receipt" in output
    assert "outcome is unknown" in output
    assert "billing credits" in output


def test_render_json_mode_when_not_a_tty() -> None:
    assert render.json_mode(flag=True) is True
    # Under pytest, stdout is captured and is not a terminal.
    assert render.json_mode(flag=False) is True


def test_render_list_extraction() -> None:
    rows = render._list_of_dicts({"scans": [{"id": "a"}, {"id": "b"}]})
    assert rows == [{"id": "a"}, {"id": "b"}]
    assert render._list_of_dicts({"scans": [], "total": 1}) == []
    assert render._list_of_dicts(
        {"organization_id": "org_1", "docs": [{"id": "doc_1"}], "total": 1}
    ) == [{"id": "doc_1"}]
    assert render._list_of_dicts([{"id": "a"}, "x"]) is None


def test_spec_paths_are_well_formed() -> None:
    for group, commands in SPEC.items():
        for verb, cmd in commands.items():
            assert cmd.path.startswith("/"), f"{group} {verb}"
            assert cmd.method in ("GET", "POST", "PUT", "PATCH", "DELETE"), f"{group} {verb}"
            assert cmd.help, f"{group} {verb} has no help text"
            for param in cmd.query + cmd.body:
                assert param.kind in (
                    "str",
                    "int",
                    "float",
                    "bool",
                    "list",
                    "json",
                    "json-list",
                ), f"{group} {verb} {param.name}"


@pytest.mark.parametrize(
    ("group", "verb"),
    [
        ("scans", "list"),
        ("vulns", "list"),
        ("domains", "list"),
        ("repos", "list"),
        ("pr-reviews", "list"),
        ("pr-reviews", "findings"),
        ("webhooks", "deliveries"),
        ("audit", "list"),
    ],
)
def test_paginated_commands_expose_integer_page_and_limit(group: str, verb: str) -> None:
    params = {param.name: param for param in SPEC[group][verb].query}
    assert params["page"].kind == "int"
    assert params["limit"].kind == "int"


def test_list_query_types_match_the_api_contract() -> None:
    scans = {param.name: param for param in SPEC["scans"]["list"].query}
    assert scans["include_retests"].kind == "bool"
    assert {"sort_by", "sort_order"} <= scans.keys()

    vulnerabilities = {param.name: param for param in SPEC["vulns"]["list"].query}
    assert "sort_order" in vulnerabilities

    for group in ("domains", "repos"):
        params = {param.name: param for param in SPEC[group]["list"].query}
        assert params["limit"].kind == "int"
        assert "sort_order" in params

    reviews = {param.name: param for param in SPEC["pr-reviews"]["list"].query}
    findings = {param.name: param for param in SPEC["pr-reviews"]["findings"].query}
    audit = {param.name: param for param in SPEC["audit"]["list"].query}
    assert reviews["include_counts"].kind == "bool"
    assert findings["include_stats"].kind == "bool"
    assert audit["all"].kind == "bool"

    components = {param.name: param for param in SPEC["repos"]["supply-chain components"].query}
    knowledge = {param.name: param for param in SPEC["knowledge"]["list"].query}
    assert components["limit"].kind == "int"
    assert components["offset"].kind == "int"
    assert knowledge["limit"].kind == "int"


def test_scan_creating_replay_commands_support_bounded_waits() -> None:
    assert SPEC["scans"]["rerun"].wait_path == "/scans/{id}"
    assert SPEC["vulns"]["retest"].wait_path == "/scans/{id}"


def test_scan_start_parameter_contract_and_help() -> None:
    params = {param.name: param for param in SPEC["scans"]["start"].body}
    assert params["headers"].kind == "json"
    assert "array" in params["headers"].help.lower()
    assert params["concerns"].kind == "str"
    assert all(tier in params["scan_tier"].help for tier in ("lite", "standard", "ultra"))
    assert "pro" not in params["scan_tier"].help
    assert "max" not in params["scan_tier"].help
    assert "self-hosted" in params["model_config_id"].help.lower()
    assert "self-hosted" in params["max_budget_usd"].help.lower()


def test_report_branding_flags_preserve_the_api_query_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["query"] = kwargs.get("query")
        return FakeResponse(content=b"report")

    monkeypatch.setattr(http, "request", fake_request)
    output = tmp_path / "report.pdf"
    assert (
        cloud.run_cloud(
            [
                "scans",
                "report",
                "scan-1",
                "--provider-name",
                "Strix Partner",
                "--member-name-0",
                "Alex",
                "--member-email-0",
                "alex@example.test",
                "--member-name-1",
                "Sam",
                "--member-email-1",
                "sam@example.test",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert output.read_bytes() == b"report"
    assert seen["query"] == {
        "providerName": "Strix Partner",
        "memberName0": "Alex",
        "memberEmail0": "alex@example.test",
        "memberName1": "Sam",
        "memberEmail1": "sam@example.test",
    }


def test_scan_start_collects_header_array_and_string_concerns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["body"] = kwargs.get("body")
        return FakeResponse(payload={"id": "scan-1"})

    monkeypatch.setattr(http, "request", fake_request)
    assert (
        cloud.run_cloud(
            [
                "scans",
                "start",
                "--headers",
                '[{"name":"X-Test","value":"one"}]',
                "--concerns",
                "authorization boundaries",
                "--scan-tier",
                "standard",
                "--json",
            ]
        )
        == 0
    )
    assert seen["body"] == {
        "headers": [{"name": "X-Test", "value": "one"}],
        "concerns": "authorization boundaries",
        "scan_tier": "standard",
    }


def test_control_only_scan_and_chat_messages_do_not_require_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, Any] | None]] = []

    def fake_request(_method: str, path: str, **kwargs: Any) -> FakeResponse:
        calls.append((path, kwargs.get("body")))
        return FakeResponse(payload={"success": True})

    monkeypatch.setattr(http, "request", fake_request)
    assert cloud.run_cloud(["scans", "message", "scan-1", "--cancel-current", "--json"]) == 0
    assert (
        cloud.run_cloud(
            ["chat", "send", "chat-1", "--stop-agent", "--agent-id", "agent-1", "--json"]
        )
        == 0
    )
    assert calls == [
        ("/scans/scan-1/message", {"cancel_current": True}),
        ("/chat/chat-1/message", {"stop_agent": True, "agent_id": "agent-1"}),
    ]


def test_chat_repositories_use_the_api_object_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["body"] = kwargs.get("body")
        return FakeResponse(payload={"id": "chat-1"})

    monkeypatch.setattr(http, "request", fake_request)
    assert (
        cloud.run_cloud(
            [
                "chat",
                "start",
                "--message",
                "Review this repository",
                "--repos",
                '[{"repoId":"repo-1","branch":"main"}]',
                "--json",
            ]
        )
        == 0
    )
    assert seen["body"] == {
        "message": "Review this repository",
        "repos": [{"repoId": "repo-1", "branch": "main"}],
    }


def test_schedule_budget_accepts_fractional_usd(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["body"] = kwargs.get("body")
        return FakeResponse(payload={"id": "schedule-1"})

    monkeypatch.setattr(http, "request", fake_request)
    assert (
        cloud.run_cloud(["schedules", "update", "schedule-1", "--max-budget-usd", "1.5", "--json"])
        == 0
    )
    assert seen["body"] == {"max_budget_usd": 1.5}


def test_integration_disconnect_sends_installation_id_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_request(method: str, path: str, **kwargs: Any) -> FakeResponse:
        seen.update(method=method, path=path, query=kwargs.get("query"))
        return FakeResponse(payload={"success": True})

    monkeypatch.setattr(http, "request", fake_request)
    assert (
        cloud.run_cloud(
            ["integrations", "disconnect", "github", "--installation-id", "42", "--json"]
        )
        == 0
    )
    assert seen == {
        "method": "DELETE",
        "path": "/integrations/github",
        "query": {"installation_id": 42},
    }


def test_connector_command_flag_is_boolean_and_warns_that_it_is_sensitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    param = next(
        param for param in SPEC["connectors"]["get"].query if param.name == "include_command"
    )
    assert param.kind == "bool"
    assert "sensitive" in param.help.lower()

    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["query"] = kwargs.get("query")
        return FakeResponse(payload={"id": "connector-1"})

    monkeypatch.setattr(http, "request", fake_request)
    assert cloud.run_cloud(["connectors", "get", "connector-1", "--include-command", "--json"]) == 0
    assert seen["query"] == {"include_command": True}


def test_corrected_help_distinguishes_inboxes_reports_and_self_hosted_commands() -> None:
    inbox = SPEC["domains"]["test-users provision-inbox"]
    assert "does not create a test user" in inbox.help

    for command_name in ("test-users add", "test-users update"):
        parameters = {param.name: param.help for param in SPEC["domains"][command_name].body}
        assert "email_otp" in parameters["mfa_method"]
        assert "magic_link" in parameters["mfa_method"]
        assert " or email." not in parameters["mfa_method"]

    vulnerability_update = {param.name: param.help for param in SPEC["vulns"]["update"].body}
    assert "in_progress" in vulnerability_update["status"]
    assert "not_affected" in vulnerability_update["status"]
    assert "triaged" not in vulnerability_update["status"]
    assert "false_positive" not in vulnerability_update["status"]

    chat_download = {param.name: param.help for param in SPEC["chat"]["files download"].query}
    assert "Relative path" in chat_download["path"]
    assert "/workspace" in chat_download["path"]

    report = {param.name: param.help for param in SPEC["scans"]["report"].query}
    assert "Report content" in report["format"]
    assert "file type" in report["type"]

    for command in (*SPEC["costs"].values(), *SPEC["llm-settings"].values()):
        assert "self-hosted only" in command.help.lower()
    assert "self-hosted only" in GROUP_HELP["costs"].lower()
    assert "self-hosted only" in GROUP_HELP["llm-settings"].lower()


def test_every_command_builds_a_parser() -> None:
    for group, commands in SPEC.items():
        for verb, cmd in commands.items():
            parser = runner._build_parser(group, verb, cmd)
            assert parser.prog == f"strix cloud {group} {verb}"


def test_app_url_and_timeout_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, url: str, **kwargs: Any) -> FakeResponse:
        seen["url"] = url
        seen["timeout"] = kwargs.get("timeout")
        return FakeResponse(status_code=200, payload={"balance": 1})

    monkeypatch.setattr(http, "api_token", lambda _override=None: "t")
    monkeypatch.setattr(requests, "request", fake_request)
    code = cloud.run_cloud(
        ["credits", "--app-url", "https://example.test/", "--timeout", "7", "--json"]
    )
    assert code == 0
    assert seen["url"] == "https://example.test/api/v1/billing/credits"
    assert seen["timeout"] == 7


def test_created_id_reads_resource_id() -> None:
    assert runner._created_id({"scan_id": "abc", "status": "pending"}) == "abc"
    assert runner._created_id({"id": "xyz"}) == "xyz"
    assert runner._created_id({"status": "pending"}) is None
    assert runner._created_id({"scan_id": ""}) is None
    assert runner._created_id({"id": "   "}) is None


def test_billing_subscribe_prints_checkout_url(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    seen: dict[str, Any] = {}

    def fake_request(method: str, path: str, **kwargs: Any) -> FakeResponse:
        seen["method"], seen["path"] = method, path
        seen["body"] = kwargs.get("body")
        return FakeResponse(status_code=200, payload={"checkout_url": "https://pay.test/session"})

    monkeypatch.setattr(http, "request", fake_request)
    code = cloud.run_cloud(["billing", "subscribe", "--plan", "strix_cloud", "--json"])
    assert code == 0
    assert seen["method"] == "POST"
    assert seen["path"] == "/billing/checkout"
    assert seen["body"] == {"product": "strix_cloud"}
    assert "https://pay.test/session" in capsys.readouterr().out


def test_knowledge_policy_flags_use_the_api_field_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["body"] = kwargs.get("body")
        return FakeResponse(payload={"success": True})

    monkeypatch.setattr(http, "request", fake_request)
    code = cloud.run_cloud(
        [
            "knowledge",
            "policies",
            "add",
            "--key",
            "no-production-data",
            "--content",
            "Never test production data.",
            "--policy-type",
            "constraint",
            "--no-enabled",
            "--metadata",
            '{"owner":"security"}',
            "--json",
        ]
    )
    assert code == 0
    assert seen["body"] == {
        "policy_key": "no-production-data",
        "policy_value": "Never test production data.",
        "policy_type": "constraint",
        "is_active": False,
        "metadata": {"owner": "security"},
    }


def test_pr_review_start_sends_provider_installation_and_pull_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["body"] = kwargs.get("body")
        return FakeResponse(payload={"review_id": "review-1", "status": "pending"})

    monkeypatch.setattr(http, "request", fake_request)
    code = cloud.run_cloud(
        [
            "pr-reviews",
            "start",
            "--provider",
            "github",
            "--installation-id",
            "123",
            "--repository-full-name",
            "org/app",
            "--pr-number",
            "42",
            "--json",
        ]
    )
    assert code == 0
    assert seen["body"] == {
        "provider": "github",
        "installation_id": 123,
        "repository_full_name": "org/app",
        "pr_number": 42,
    }


def test_llm_settings_uses_kebab_case_flag_for_camel_case_api_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen["body"] = kwargs.get("body")
        return FakeResponse(payload={"ok": True})

    monkeypatch.setattr(http, "request", fake_request)
    code = cloud.run_cloud(
        [
            "llm-settings",
            "update",
            "--model-configs",
            "[]",
            "--assignments",
            "{}",
            "--json",
        ]
    )
    assert code == 0
    assert seen["body"] == {"modelConfigs": [], "assignments": {}}


def test_integration_install_url_does_not_open_browser(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    opened: list[str] = []
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(status_code=200, payload={"url": "https://github.test/app"}),
    )

    def fake_open(url: str) -> bool:
        opened.append(url)
        return True

    monkeypatch.setattr(webbrowser, "open", fake_open)
    code = cloud.run_cloud(["integrations", "install", "github", "--json"])
    assert code == 0
    assert opened == []
    assert "https://github.test/app" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv,payload",
    [
        (
            ["billing", "subscribe", "--plan", "strix_cloud"],
            {"checkout_url": "file:///tmp/not-a-checkout"},
        ),
        (
            ["integrations", "install", "github"],
            {"url": "javascript:alert(1)"},
        ),
    ],
)
def test_handoff_links_reject_non_http_schemes(
    argv: list[str],
    payload: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(status_code=200, payload=payload),
    )
    monkeypatch.setattr(
        webbrowser,
        "open",
        lambda _url: pytest.fail("an untrusted URL must never be opened"),
    )

    assert cloud.run_cloud(argv) == http.EXIT_ERROR
    output = capsys.readouterr().out
    assert "invalid continuation URL" in output
    assert next(iter(payload.values())) not in output


def test_handoff_missing_expected_url_is_an_error(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(status_code=200, payload={"status": "created"}),
    )
    assert cloud.run_cloud(["integrations", "install", "github", "--json"]) == 1
    assert "expected url URL" in json.loads(capsys.readouterr().out)["error"]


def test_workspaces_use_switches_stored_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: Any
) -> None:
    monkeypatch.delenv("STRIX_API_TOKEN", raising=False)
    auth_path = tmp_path / "platform-auth.json"
    monkeypatch.setattr(platform_cli, "AUTH_PATH", auth_path)
    monkeypatch.setattr(workspaces, "AUTH_PATH", auth_path)
    platform_cli.save_record(
        {
            "api_token": "old",
            "email": "a@b.test",
            "scopes": ["scans:read", "organizations:read", "tokens:write"],
            "requested_scopes": [
                "scans:read",
                "scans:write",
                "organizations:read",
                "tokens:write",
            ],
        }
    )

    calls: list[tuple[str, str]] = []
    token_body: dict[str, Any] | None = None

    def fake_request(method: str, path: str, **kwargs: Any) -> FakeResponse:
        nonlocal token_body
        calls.append((method, path))
        if path == "/workspaces":
            return FakeResponse(
                status_code=200,
                payload={"workspaces": [{"id": "org_1", "name": "Team One", "role": "admin"}]},
            )
        token_body = kwargs.get("body")
        return FakeResponse(
            status_code=200,
            payload={
                "api_token": "old",
                "organization_id": "org_1",
                "organization_name": "Team One",
                "scopes": ["scans:read"],
            },
        )

    monkeypatch.setattr(http, "request", fake_request)
    monkeypatch.setattr(
        workspaces,
        "read_or_create_identity",
        lambda: {"client_instance_id": "client-test", "device_name": "Test CLI"},
    )
    code = cloud.run_cloud(["workspaces", "use", "team one", "--json"])
    assert code == 0
    assert calls == [("GET", "/workspaces"), ("POST", "/workspaces/org_1/token")]
    assert token_body == {"client_instance_id": "client-test", "device_name": "Test CLI"}
    record = platform_cli.read_record()
    assert record is not None
    assert record["api_token"] == "old"
    assert record["organization_name"] == "Team One"
    assert record["email"] == "a@b.test"
    output = json.loads(capsys.readouterr().out)
    assert output["workspace_id"] == "org_1"
    assert output["scope_profile"] == "custom"
    assert output["stored"] is True


def test_workspace_use_explicit_token_starts_with_fresh_account_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: Any
) -> None:
    auth_path = tmp_path / "platform-auth.json"
    monkeypatch.setattr(platform_cli, "AUTH_PATH", auth_path)
    monkeypatch.setattr(workspaces, "AUTH_PATH", auth_path)
    platform_cli.save_record(
        {
            "api_token": "account-a-token",
            "email": "account-a@example.test",
            "organization_id": "org_a",
            "organization_name": "Account A",
            "scopes": ["scans:read"],
            "requested_scopes": ["scans:read", "tokens:write"],
        }
    )
    switch_body: dict[str, Any] | None = None

    def fake_request(method: str, path: str, **kwargs: Any) -> FakeResponse:
        nonlocal switch_body
        assert kwargs.get("token") == "account-b-token"
        if method == "GET":
            return FakeResponse(payload={"workspaces": [{"id": "org_b", "name": "Account B"}]})
        assert path == "/workspaces/org_b/token"
        switch_body = kwargs.get("body")
        return FakeResponse(
            payload={
                "api_token": "account-b-token",
                "organization_id": "org_b",
                "organization_name": "Account B",
                "scopes": ["scans:read", "organizations:read"],
            }
        )

    monkeypatch.setattr(http, "request", fake_request)
    assert (
        cloud.run_cloud(["workspaces", "use", "Account B", "--token", "account-b-token", "--json"])
        == 0
    )
    assert switch_body is None
    record = platform_cli.read_record()
    assert record is not None
    assert record["api_token"] == "account-a-token"
    assert record["organization_id"] == "org_a"
    assert record["email"] == "account-a@example.test"
    output = json.loads(capsys.readouterr().out)
    assert output["workspace_id"] == "org_b"
    assert output["stored"] is False


def test_workspace_use_environment_token_starts_with_fresh_account_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    auth_path = tmp_path / "platform-auth.json"
    monkeypatch.setattr(platform_cli, "AUTH_PATH", auth_path)
    monkeypatch.setattr(workspaces, "AUTH_PATH", auth_path)
    monkeypatch.setenv("STRIX_API_TOKEN", "account-b-token")
    platform_cli.save_record(
        {
            "api_token": "account-a-token",
            "email": "account-a@example.test",
            "organization_id": "org_a",
            "organization_name": "Account A",
            "scopes": ["scans:read"],
            "requested_scopes": ["scans:read", "tokens:write"],
        }
    )
    switch_body: dict[str, Any] | None = None

    def fake_request(method: str, path: str, **kwargs: Any) -> FakeResponse:
        nonlocal switch_body
        assert kwargs.get("token") is None
        if method == "GET":
            return FakeResponse(payload={"workspaces": [{"id": "org_b", "name": "Account B"}]})
        assert path == "/workspaces/org_b/token"
        switch_body = kwargs.get("body")
        return FakeResponse(
            payload={
                "api_token": "account-b-token",
                "organization_id": "org_b",
                "organization_name": "Account B",
                "email": "account-b@example.test",
                "scopes": ["scans:read", "organizations:read"],
            }
        )

    monkeypatch.setattr(http, "request", fake_request)
    assert cloud.run_cloud(["workspaces", "use", "Account B", "--json"]) == 0
    assert switch_body is None
    record = platform_cli.read_record()
    assert record is not None
    assert record["api_token"] == "account-a-token"
    assert record["organization_id"] == "org_a"
    assert record["email"] == "account-a@example.test"


def test_workspaces_use_reports_unknown_workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            status_code=200, payload={"workspaces": [{"id": "org_1", "name": "Team One"}]}
        ),
    )
    assert cloud.run_cloud(["workspaces", "use", "missing", "--json"]) == 1


def test_workspaces_use_reports_auth_storage_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.delenv("STRIX_API_TOKEN", raising=False)

    def fake_request(method: str, path: str, **_kwargs: Any) -> FakeResponse:
        if method == "GET":
            return FakeResponse(payload={"workspaces": [{"id": "org_1", "name": "Team One"}]})
        assert path == "/workspaces/org_1/token"
        return FakeResponse(
            payload={
                "api_token": "test-token",
                "organization_id": "org_1",
                "organization_name": "Team One",
                "scopes": ["scans:read"],
            }
        )

    monkeypatch.setattr(http, "request", fake_request)
    monkeypatch.setattr(
        workspaces, "save_record", lambda _record: (_ for _ in ()).throw(OSError("disk full"))
    )

    assert cloud.run_cloud(["workspaces", "use", "1", "--json"]) == http.EXIT_ERROR
    payload = json.loads(capsys.readouterr().out)
    assert "could not be stored" in payload["error"]
    assert payload["workspace_switched"] is True
    assert payload["local_record_updated"] is False
    assert payload["retry_safe"] is True


@pytest.mark.parametrize(
    "failure",
    [
        requests.ConnectionError("connection reset"),
        FakeResponse(status_code=503, text="temporarily unavailable"),
        FakeResponse(status_code=200, text="not JSON"),
        FakeResponse(status_code=200, payload={"organization_id": "org_1"}),
    ],
)
def test_workspace_use_reports_retry_safe_unknown_outcomes(
    failure: Exception | FakeResponse,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    def fake_request(method: str, path: str, **_kwargs: Any) -> FakeResponse:
        if method == "GET":
            return FakeResponse(payload={"workspaces": [{"id": "org_1", "name": "Team One"}]})
        assert path == "/workspaces/org_1/token"
        if isinstance(failure, Exception):
            raise http.CloudError(str(failure)) from failure
        return failure

    monkeypatch.setattr(http, "request", fake_request)

    assert cloud.run_cloud(["workspaces", "use", "1", "--json"]) == http.EXIT_ERROR
    payload = json.loads(capsys.readouterr().out)
    assert payload["switch_outcome_unknown"] is True
    assert payload["retry_safe"] is True
    assert "safely rerun" in payload["error"]


def test_workspace_use_preserves_definitive_conflict(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    def fake_request(method: str, path: str, **_kwargs: Any) -> FakeResponse:
        if method == "GET":
            return FakeResponse(payload={"workspaces": [{"id": "org_1", "name": "Team One"}]})
        return FakeResponse(
            status_code=409,
            payload={"error": {"code": "token_conflict", "message": "token changed"}},
        )

    monkeypatch.setattr(http, "request", fake_request)

    assert cloud.run_cloud(["workspaces", "use", "1", "--json"]) == http.EXIT_ERROR
    payload = json.loads(capsys.readouterr().out)
    assert "token changed" in payload["error"]
    assert "switch_outcome_unknown" not in payload


def test_group_help_lists_all_verbs_instead_of_default_verb_help(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert cloud.run_cloud(["workspaces", "-h"]) == 0
    output = capsys.readouterr().out
    assert "workspaces verbs" in output
    assert "list" in output
    assert "create" in output
    assert "use" in output


def test_workspace_alias_routes_to_workspaces(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, str] = {}

    def fake_request(method: str, path: str, **_kwargs: Any) -> FakeResponse:
        seen.update(method=method, path=path)
        return FakeResponse(payload={"workspaces": []})

    monkeypatch.setattr(http, "request", fake_request)
    assert cloud.run_cloud(["workspace", "list", "--json"]) == 0
    assert seen == {"method": "GET", "path": "/workspaces"}


def test_workspace_human_list_is_numbered_and_hides_ids(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            payload={
                "workspaces": [
                    {"id": "org_secret", "name": "Team One", "role": "admin", "current": True}
                ]
            }
        ),
    )

    assert cloud.run_cloud(["workspaces", "list"]) == 0
    output = capsys.readouterr().out
    assert "1." in output
    assert "Team One" in output
    assert "yes" in output
    assert "org_secret" not in output
    assert "workspaces use NUMBER" in output


def test_integrations_human_list_exposes_installation_id_and_json_stays_full(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    payload = {
        "integrations": [
            {
                "id": "integration-uuid",
                "organization_id": "org-secret",
                "connected_by": "user-secret",
                "provider": "github",
                "installation_id": 154419799,
                "account_login": "usestrix",
                "repository_selection": "selected",
                "connected_at": "2026-08-27T12:00:00Z",
            }
        ],
        "merge_accounts": [
            {
                "id": "merge-uuid",
                "provider": "jira",
                "status": "linked",
                "default_collection_name": "Security",
            }
        ],
        "bitbucket_oauth_enabled": True,
    }
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(http, "request", lambda *_a, **_k: FakeResponse(payload=payload))

    assert cloud.run_cloud(["integrations", "list"]) == 0
    output = capsys.readouterr().out
    for value in ("1.", "2.", "github", "usestrix", "154419799", "jira", "Security"):
        assert value in output
    for value in ("integration-uuid", "merge-uuid", "org-secret", "user-secret"):
        assert value not in output
    assert "--installation-id INSTALLATION_ID" in output

    assert cloud.run_cloud(["integrations", "list", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == payload


def test_pr_review_human_list_prioritizes_actionable_fields(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            payload={
                "items": [
                    {
                        "id": "review-id",
                        "organization_id": "org-id",
                        "user_id": "user-id",
                        "installation_id": 42,
                        "repository_full_name": "usestrix/strix",
                        "pr_number": 1177,
                        "pr_title": "Improve cloud CLI",
                        "head_branch": "feature",
                        "base_branch": "main",
                        "pr_state": "merged",
                        "verdict": "request_changes",
                        "status": "posted",
                        "findings_count": 99,
                        "open_findings_count": 88,
                        "findings": {
                            "total": 7,
                            "critical": 1,
                            "high": 2,
                            "medium": 3,
                            "low": 1,
                            "unresolved": {"total": 2},
                            "snoozed": 1,
                            "fixed": 4,
                        },
                    }
                ],
                "meta": {"total": 1},
                "counts": {
                    "all": 12,
                    "open": 3,
                    "attention": 2,
                    "merged_open": 1,
                    "passed": 6,
                    "running": 1,
                },
            }
        ),
    )

    assert cloud.run_cloud(["pr-reviews", "list", "--include-counts"]) == 0
    output = capsys.readouterr().out
    for value in (
        "usestrix/strix",
        "1177",
        "Improve cloud CLI",
        "merged",
        "feature",
        "main",
        "posted",
        "request_changes",
        "2 open / 7 total",
        "Review counts",
        "attention 2",
        "passed 6",
        "review-id",
    ):
        assert value in output
    for value in ("org-id", "user-id", "installation_id"):
        assert value not in output


@pytest.mark.parametrize("pr_state", ("open", "merged", "closed"))
def test_pr_review_human_list_shows_pull_request_state(
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
    pr_state: str,
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            payload={
                "items": [
                    {
                        "id": f"{pr_state}-review-id",
                        "repository_full_name": "usestrix/strix",
                        "pr_number": 1177,
                        "pr_title": "Renderer test",
                        "head_branch": "feature",
                        "base_branch": "main",
                        "pr_state": pr_state,
                        "status": "posted",
                        "findings": {"total": 0, "unresolved": {"total": 0}},
                    }
                ],
                "meta": {"total": 1},
            }
        ),
    )

    assert cloud.run_cloud(["pr-reviews", "list"]) == 0
    assert f"[{pr_state}]" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("record", "expected_targets"),
    [
        (
            {
                "id": "internal-scan-id",
                "title": "Private network review",
                "engagement_type": "internal_infra",
                "scan_type": "blackbox",
                "status": "running",
                "internal_targets": ["10.24.0.0/16", "db.internal"],
                "findings": {"total": 0},
            },
            ("10.24.0.0/16", "db.internal"),
        ),
        (
            {
                "id": "upload-scan-id",
                "title": "Local source review",
                "engagement_type": "code_review",
                "scan_type": "whitebox",
                "status": "pending",
                "has_code_upload": True,
                "findings": {"total": 0},
            },
            ("uploaded source",),
        ),
    ],
)
def test_scan_human_list_identifies_internal_and_uploaded_targets(
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
    record: dict[str, Any],
    expected_targets: tuple[str, ...],
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            payload={
                "items": [record],
                "meta": {
                    "page": 1,
                    "limit": 20,
                    "total_items": 1,
                    "total_pages": 1,
                    "has_next": False,
                },
            }
        ),
    )

    assert cloud.run_cloud(["scans", "list"]) == 0
    output = capsys.readouterr().out
    for target in expected_targets:
        assert target in output


@pytest.mark.parametrize(
    ("command", "payload", "visible", "hidden"),
    [
        (
            ["vulns", "list"],
            {
                "items": [
                    {
                        "id": "vuln-id",
                        "scan_id": "scan-secret",
                        "display_number": 17,
                        "title": "Missing authorization",
                        "severity": "high",
                        "status": "open",
                        "target": None,
                        "method": "get",
                        "endpoint": "/api/admin",
                        "cvss": 8.2,
                        "finding_type": "dynamic",
                    }
                ],
                "meta": {"total_items": 1},
            },
            ("17", "Missing authorization", "GET /api/admin", "vuln-id"),
            ("scan-secret",),
        ),
        (
            ["domains", "list"],
            {
                "items": [
                    {
                        "id": "domain-id",
                        "organization_id": "org-secret",
                        "domain": "staging.example.com",
                        "asset_type": "web_app",
                        "verified": True,
                        "context": "staging",
                        "tags": ["customer-facing"],
                        "business_unit": "product",
                        "last_scan_at": "2026-08-27T12:00:00Z",
                        "added_by": "user-secret",
                    }
                ],
                "meta": {"total_items": 1},
            },
            ("staging.example.com", "web_app", "yes", "staging", "domain-id"),
            ("org-secret", "user-secret", "added by"),
        ),
        (
            ["repos", "list"],
            {
                "items": [
                    {
                        "id": "repo-id",
                        "organization_id": "org-secret",
                        "full_name": "usestrix/strix",
                        "provider": "github",
                        "pr_review_enabled": True,
                        "tags": ["core"],
                        "business_unit": "product",
                        "last_scan_at": "2026-08-27T12:00:00Z",
                        "added_by": "user-secret",
                    }
                ],
                "meta": {"total_items": 1},
            },
            ("usestrix/strix", "github", "yes", "repo-id"),
            ("org-secret", "user-secret", "added by"),
        ),
        (
            ["knowledge", "list"],
            {
                "organization_id": "org-secret",
                "docs": [
                    {
                        "id": (
                            "doc-id-that-is-deliberately-long-enough-to-require-a-lossless-"
                            "copyable-value"
                        ),
                        "organization_id": "org-secret",
                        "title": "Authentication",
                        "source_type": "manual",
                        "source_id": "dashboard/notes/auth.md",
                        "content": "Long private content should stay out of the list.",
                        "tags": ["auth"],
                        "severity": None,
                        "status": None,
                        "updated_at": "2026-08-27T12:00:00Z",
                    }
                ],
                "total": 1,
            },
            (
                "Authentication",
                "manual",
                "dashboard/notes/auth.md",
                "doc-id-that-is-deliberately-long-enough-to-require-a-lossless-copyable-value",
                "Copyable selectors",
            ),
            ("org-secret", "Long private content"),
        ),
        (
            ["domains", "test-users", "list", "domain-id"],
            {
                "items": [
                    {
                        "id": "test-user-id",
                        "organization_id": "org-secret",
                        "domain_id": "domain-id",
                        "label": "Staging admin",
                        "username": "admin@example.com",
                        "mfa_method": "email_otp",
                        "mfa_email": "inbox@security-mail.strix.ai",
                        "has_password": True,
                        "login_url": "https://staging.example.com/login",
                        "updated_at": "2026-08-27T12:00:00Z",
                        "created_by": "user-secret",
                    }
                ],
                "agentmail_configured": True,
            },
            (
                "Staging admin",
                "admin@example.com",
                "email_otp",
                "inbox@security-mail.strix.ai",
                "test-user-id",
            ),
            ("org-secret", "user-secret", "domain id"),
        ),
    ],
)
def test_human_lists_prioritize_actionable_fields(
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
    command: list[str],
    payload: dict[str, Any],
    visible: tuple[str, ...],
    hidden: tuple[str, ...],
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(http, "request", lambda *_a, **_k: FakeResponse(payload=payload))

    assert cloud.run_cloud(command) == 0
    output = capsys.readouterr().out
    for value in visible:
        assert value in output
    for value in hidden:
        assert value not in output


def test_token_human_list_shows_lifecycle_status(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            payload={
                "tokens": [
                    {
                        "id": "active-id",
                        "organization_id": "org-secret",
                        "name": "Active CI",
                        "type": "service",
                        "scopes": ["scans:read"],
                        "rbac_scopes": [],
                        "secret_prefix": "strix_svc_a",
                        "expires_at": "2099-01-01T00:00:00Z",
                        "last_used_at": None,
                        "revoked_at": None,
                    },
                    {
                        "id": "revoked-id",
                        "organization_id": "org-secret",
                        "name": "Old CI",
                        "type": "service",
                        "scopes": ["scans:read"],
                        "rbac_scopes": [{"type": "tag", "value": "staging"}],
                        "secret_prefix": "strix_svc_r",
                        "expires_at": None,
                        "last_used_at": None,
                        "revoked_at": "2026-08-27T12:00:00Z",
                    },
                    {
                        "id": "expired-id",
                        "organization_id": "org-secret",
                        "name": "Expired CI",
                        "type": "service",
                        "scopes": ["scans:read"],
                        "rbac_scopes": [{"type": "business_unit", "value": "payments"}],
                        "secret_prefix": "strix_svc_e",
                        "expires_at": "2000-01-01T00:00:00Z",
                        "last_used_at": None,
                        "revoked_at": None,
                    },
                ]
            }
        ),
    )

    assert cloud.run_cloud(["tokens", "list"]) == 0
    output = capsys.readouterr().out
    for value in (
        "Active CI",
        "active",
        "all assets",
        "Old CI",
        "revoked",
        "tag:staging",
        "Expired CI",
        "expired",
        "business_unit:payments",
        "scans:read",
    ):
        assert value in output
    assert "org-secret" not in output


@pytest.mark.parametrize(
    ("command", "payload", "visible", "hidden"),
    [
        (
            ["chat", "list"],
            {
                "chats": [
                    {
                        "id": "chat-id",
                        "title": "Investigate auth",
                        "status": "running",
                        "created_at": "2026-08-27T10:00:00Z",
                        "last_message_at": "2026-08-27T11:00:00Z",
                    }
                ]
            },
            ("Investigate auth", "running", "chat-id"),
            (),
        ),
        (
            ["chat", "files", "chat-id"],
            {
                "files": [
                    {
                        "path": "/workspace/" + "nested/" * 12 + "report.md",
                        "size": 42,
                    }
                ]
            },
            (
                "/workspace/" + "nested/" * 12 + "report.md",
                "Copyable selectors",
                "42",
            ),
            (),
        ),
        (
            ["chat", "findings", "chat-id"],
            {
                "findings": [
                    {
                        "id": "finding-id",
                        "chat_id": "chat-secret",
                        "filed_by": "user-secret",
                        "title": "Broken access control",
                        "severity": "high",
                        "status": "open",
                        "target": None,
                        "method": "post",
                        "endpoint": "/admin/users",
                        "cvss": 8.1,
                        "filed_at": "2026-08-27T11:00:00Z",
                        "created_at": "2026-08-27T10:00:00Z",
                    }
                ]
            },
            ("Broken access control", "high", "POST /admin/users", "finding-id"),
            ("chat-secret", "user-secret"),
        ),
        (
            ["scans", "agents", "scan-id"],
            {
                "scan_id": "scan-secret",
                "agents": [
                    {
                        "id": "agent-id",
                        "name": "Authorization tester",
                        "status": "completed",
                        "task": "Test object ownership",
                        "parent_id": None,
                        "created_at": "2026-08-27T10:00:00Z",
                        "finding_count": 2,
                    }
                ],
            },
            ("Authorization tester", "completed", "Test object ownership", "agent-id"),
            ("scan-secret",),
        ),
        (
            ["scans", "retests", "scan-id"],
            {
                "runs": [
                    {
                        "vulnerability_id": "vuln-id",
                        "title": "IDOR",
                        "severity": "high",
                        "issue_status": "open",
                        "retest_scan_id": "retest-id",
                        "retest_status": "running",
                        "created_at": "2026-08-27T10:00:00Z",
                    }
                ],
                "total": 1,
                "completed": 0,
                "running": 1,
            },
            ("IDOR", "high", "vuln-id", "retest-id", "0/1 retest(s) complete"),
            (),
        ),
        (
            ["pr-reviews", "findings", "--include-stats"],
            {
                "items": [
                    {
                        "id": "pr-finding-id",
                        "pr_review_id": "review-secret",
                        "provider": "github",
                        "repository_full_name": "usestrix/strix",
                        "pr_number": 1177,
                        "pr_title": "Improve cloud CLI",
                        "pr_state": "open",
                        "title": "Unsafe redirect",
                        "severity": "medium",
                        "status": "open",
                        "created_at": "2026-08-27T10:00:00Z",
                    }
                ],
                "meta": {"total_items": 1},
                "stats": {
                    "prs_reviewed": 9,
                    "issues_found": 1,
                    "critical_high_found": 1,
                    "merges_blocked": 2,
                },
            },
            (
                "usestrix/strix",
                "1177",
                "Improve cloud CLI",
                "Unsafe redirect",
                "pr-finding-id",
                "Impact",
                "prs reviewed 9",
                "merges blocked 2",
            ),
            ("review-secret",),
        ),
        (
            ["vulns", "history", "vuln-id"],
            [
                {
                    "id": "history-secret",
                    "vulnerability_id": "vuln-secret",
                    "previous_status": "snoozed",
                    "new_status": "snoozed",
                    "previous_severity": "high",
                    "new_severity": "medium",
                    "previous_snoozed_until": "2026-09-01T00:00:00Z",
                    "new_snoozed_until": "2026-09-15T00:00:00Z",
                    "changed_by": "user-secret",
                    "note": "Extended pending vendor fix",
                    "reason": "Vendor ETA changed",
                    "created_at": "2026-08-27T10:00:00Z",
                },
                {
                    "id": "history-clear-secret",
                    "vulnerability_id": "vuln-secret",
                    "previous_status": "snoozed",
                    "new_status": "snoozed",
                    "previous_severity": "medium",
                    "new_severity": "medium",
                    "previous_snoozed_until": "2026-09-15T00:00:00Z",
                    "new_snoozed_until": None,
                    "changed_by": "user-secret",
                    "note": "Snooze removed",
                    "reason": "Fix available",
                    "created_at": "2026-08-28T10:00:00Z",
                },
            ],
            (
                "snoozed",
                "high",
                "medium",
                "2026-09-01T00:00:00Z",
                "2026-09-15T00:00:00Z",
                "cleared",
                "Extended pending vendor fix",
                "Vendor ETA changed",
                "Snooze removed",
                "Fix available",
            ),
            ("history-secret", "history-clear-secret", "vuln-secret", "user-secret"),
        ),
        (
            ["repos", "supply-chain", "findings", "repo-id"],
            {
                "snapshot": {"id": "snapshot-secret"},
                "findings": [
                    {
                        "id": "dependency-id",
                        "repository_id": "repo-secret",
                        "title": "Vulnerable package",
                        "package_name": "lodash",
                        "package_version": "1.0.0",
                        "severity": "high",
                        "status": "open",
                        "fixed_version": "4.17.21",
                        "manifest_path": "package-lock.json",
                        "direct": True,
                    }
                ],
            },
            ("Vulnerable package", "lodash@1.0.0", "4.17.21", "dependency-id"),
            ("snapshot-secret", "repo-secret"),
        ),
        (
            ["repos", "supply-chain", "components", "repo-id"],
            {
                "snapshot": {"id": "snapshot-secret"},
                "components": [
                    {
                        "id": "component-id",
                        "snapshot_id": "snapshot-secret",
                        "name": "requests",
                        "version": "2.0.0",
                        "ecosystem": "pypi",
                        "relationship": "direct",
                        "status": "active",
                        "highest_open_severity": "critical",
                        "manifest_path": "requirements.txt",
                    }
                ],
                "meta": {"total": 3, "limit": 1, "offset": 0},
            },
            ("requests", "2.0.0", "pypi", "critical", "component-id", "--offset 1"),
            ("snapshot-secret",),
        ),
        (
            ["domains", "test-users", "inbox", "domain-id", "test-user-id"],
            {
                "address": "inbox@security-mail.strix.ai",
                "messages": [
                    {
                        "id": "message-id",
                        "from": "login@example.com",
                        "subject": "Your code",
                        "preview": "Code 123456",
                        "timestamp": "2026-08-27T10:00:00Z",
                        "detected_code": "123456",
                    }
                ],
            },
            (
                "login@example.com",
                "Your code",
                "123456",
                "message-id",
                "Inbox: inbox@security-mail.strix.ai",
            ),
            (),
        ),
        (
            ["knowledge", "repos", "entries", "usestrix/strix"],
            {
                "organization_id": "org-secret",
                "repo_key": "usestrix/strix",
                "profile": {"id": "profile-secret", "title": "Profile"},
                "docs": [
                    {
                        "id": "doc-id",
                        "title": "Auth notes",
                        "source_type": "system",
                        "source_id": "repos/usestrix__strix/auth.md",
                        "tags": [],
                        "updated_at": "2026-08-27T10:00:00Z",
                    }
                ],
                "insights": [],
                "policies": [{"id": "policy-secret", "policy_key": "no-prod"}],
                "stats": {"docs_count": 1},
            },
            (
                "Auth notes",
                "system",
                "repos/usestrix__strix/auth.md",
                "doc-id",
                "Repository profile: Profile",
                "1 policy apply",
            ),
            ("org-secret", "profile-secret", "policy-secret", "nested field"),
        ),
    ],
)
def test_nonstandard_human_list_envelopes_are_actionable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
    command: list[str],
    payload: Any,
    visible: tuple[str, ...],
    hidden: tuple[str, ...],
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(http, "request", lambda *_a, **_k: FakeResponse(payload=payload))

    assert cloud.run_cloud(command) == 0
    output = capsys.readouterr().out
    for value in visible:
        assert value in output
    for value in hidden:
        assert value not in output


def test_chat_credentials_human_view_separates_attached_and_available_sources(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    payload = {
        "credentials": [
            {
                "label": "Attached admin",
                "username": "admin@example.com",
                "login_url": "https://example.com/login",
                "mfa_method": "totp",
                "has_password": True,
                "has_totp_secret": True,
                "test_user_id": "attached-test-user-id",
            }
        ],
        "available_test_users": [
            {
                "id": "available-test-user-id",
                "label": "Saved analyst",
                "username": "analyst@example.com",
                "domain": "example.com",
                "login_url": "https://example.com/login",
                "mfa_method": "email_otp",
                "has_password": False,
                "has_totp_secret": False,
            }
        ],
        "available_scan_credentials": [
            {
                "scan_id": "source-scan-id",
                "scan_title": "August staging pentest",
                "username": "scan-user@example.com",
                "login_url": "https://staging.example.com/login",
                "mfa_method": "none",
                "has_password": True,
                "has_totp_secret": False,
            }
        ],
    }
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(http, "request", lambda *_a, **_k: FakeResponse(payload=payload))

    command = ["chat", "credentials", "chat-id", "--scan-ids", "source-scan-id"]
    assert cloud.run_cloud(command) == 0
    output = capsys.readouterr().out
    for value in (
        "Attached credentials",
        "Attached admin",
        "attached-test-user-id",
        "Available saved test users",
        "Saved analyst",
        "available-test-user-id",
        "Credentials from requested scans",
        "August staging pentest",
        "source-scan-id",
        "password: set",
        "password: not set",
        "--test-user-ids ID",
        "--scan-ids SCAN_ID",
    ):
        assert value in output

    assert cloud.run_cloud([*command, "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == payload


@pytest.mark.parametrize(
    ("command", "payload", "visible", "hidden"),
    [
        (
            ["schedules", "list"],
            {
                "schedules": [
                    {
                        "id": "schedule-id",
                        "organization_id": "org-secret",
                        "created_by": "user-secret",
                        "name": "Weekly staging",
                        "cron": "0 9 * * 1",
                        "timezone": "America/New_York",
                        "isPaused": True,
                        "supply_chain": True,
                        "domain_ids": [],
                        "repository_ids": ["repo-id"],
                        "internal_targets": ["10.24.0.0/16"],
                        "connector_id": "connector-secret",
                        "last_run_status": "ok",
                        "next_run_at": "2026-08-31T13:00:00Z",
                        "run_count": 4,
                    }
                ]
            },
            (
                "Weekly staging",
                "supply chain",
                "1 repo",
                "10.24.0.0/16",
                "network connector",
                "0 9 * * 1",
                "paused",
                "ok",
                "schedule-id",
                "schedules get ID",
            ),
            ("org-secret", "user-secret", "connector-secret"),
        ),
        (
            ["connectors", "list"],
            [
                {
                    "id": "connector-id",
                    "name": "Private network",
                    "last_status": "healthy",
                    "last_status_checked_at": "2026-08-27T10:00:00Z",
                    "created_at": "2026-08-20T10:00:00Z",
                    "unexpected": "hidden",
                }
            ],
            ("Private network", "healthy", "connector-id"),
            ("unexpected", "hidden"),
        ),
        (
            ["org", "members"],
            {
                "members": [
                    {
                        "id": "membership-id",
                        "userId": "user-secret",
                        "email": "analyst@example.com",
                        "firstName": "Ada",
                        "lastName": "Lovelace",
                        "role": "analyst",
                        "scopes": [
                            {"type": "tag", "value": "production"},
                            {"type": "business_unit", "value": "payments"},
                        ],
                        "status": "active",
                        "joinedAt": "2026-08-20T10:00:00Z",
                    }
                ]
            },
            (
                "analyst@example.com",
                "Ada",
                "Lovelace",
                "tag:production",
                "business_unit:payments",
                "active",
                "membership-id",
            ),
            ("user-secret",),
        ),
        (
            ["org", "invitations"],
            {
                "invitations": [
                    {
                        "id": "invitation-id",
                        "email": "invitee@example.com",
                        "role": "analyst",
                        "scopes": [],
                        "state": "pending",
                        "expiresAt": "2026-09-01T10:00:00Z",
                        "createdAt": "2026-08-27T10:00:00Z",
                    }
                ]
            },
            ("invitee@example.com", "analyst", "all assets", "pending", "invitation-id"),
            (),
        ),
        (
            ["webhooks", "list"],
            {
                "webhooks": [
                    {
                        "id": "webhook-id",
                        "organization_id": "org-secret",
                        "url": "https://example.com/hook",
                        "events": ["scan.completed"],
                        "business_unit": "product",
                        "is_active": True,
                        "last_success_at": "2026-08-27T10:00:00Z",
                        "last_failure_at": None,
                        "created_at": "2026-08-20T10:00:00Z",
                    }
                ]
            },
            ("https://example.com/hook", "scan.completed", "product", "webhook-id"),
            ("org-secret", "last delivery"),
        ),
        (
            ["webhooks", "deliveries", "webhook-id"],
            {
                "items": [
                    {
                        "id": "delivery-id",
                        "subscription_id": "subscription-secret",
                        "organization_id": "org-secret",
                        "event_type": "scan.completed",
                        "status": "delivered",
                        "response_status": 200,
                        "last_error": "temporary timeout",
                        "attempts": 1,
                        "sent_at": "2026-08-27T10:01:00Z",
                        "next_attempt_at": None,
                        "created_at": "2026-08-27T10:00:00Z",
                    }
                ],
                "meta": {"total_items": 1},
            },
            ("scan.completed", "delivered", "200", "temporary timeout", "delivery-id"),
            ("subscription-secret", "org-secret"),
        ),
        (
            ["knowledge", "repos"],
            {
                "repos": [
                    {
                        "repo_key": "usestrix/strix",
                        "docs_count": 4,
                        "last_updated_at": "2026-08-27T10:00:00Z",
                        "future_internal_field": "hidden",
                    }
                ]
            },
            ("usestrix/strix", "4", "2026-08-27"),
            ("future_internal_field", "hidden"),
        ),
        (
            ["audit", "list"],
            {
                "data": [
                    {
                        "id": "audit-row-secret",
                        "organization_id": "org-secret",
                        "actor_id": "actor-secret",
                        "actor_email": "ada@example.com",
                        "action": "scan.started",
                        "resource_type": "scan",
                        "resource_id": "scan-id",
                        "metadata": {"private": "details"},
                        "ip_address": "192.0.2.1",
                        "created_at": "2026-08-27T10:00:00Z",
                    }
                ],
                "pagination": {
                    "page": 1,
                    "limit": 20,
                    "total": 41,
                    "total_pages": 3,
                },
            },
            ("scan.started", "scan", "scan-id", "ada@example.com", "192.0.2.1", "--page 2"),
            ("audit-row-secret", "org-secret", "actor-secret", "private"),
        ),
    ],
)
def test_named_human_list_views_match_api_fields(
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
    command: list[str],
    payload: Any,
    visible: tuple[str, ...],
    hidden: tuple[str, ...],
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(http, "request", lambda *_a, **_k: FakeResponse(payload=payload))

    assert cloud.run_cloud(command) == 0
    output = capsys.readouterr().out
    for value in visible:
        assert value in output
    for value in hidden:
        assert value not in output


def test_supply_chain_org_summary_human_view_shows_totals_and_repository_risk(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            payload={
                "totals": {
                    "repositories": 2,
                    "components": 145,
                    "findings": 9,
                    "open_issues": 4,
                    "malicious": 1,
                    "suspicious": 2,
                    "vulnerable": 6,
                    "ecosystems": {"npm": 100, "pypi": 45},
                    "severities": {"critical": 1, "high": 3, "medium": 5},
                },
                "repositories": [
                    {
                        "repository": {
                            "id": "repo-id",
                            "organization_id": "org-secret",
                            "full_name": "usestrix/strix",
                            "provider": "github",
                        },
                        "summary": {
                            "component_count": 100,
                            "finding_count": 7,
                            "malicious_count": 1,
                            "suspicious_count": 2,
                            "vulnerable_count": 4,
                            "severity_counts": {"critical": 1, "high": 2, "medium": 4},
                            "policy": {
                                "enabled": True,
                                "pr_checks_enabled": False,
                                "mode": "block",
                            },
                        },
                        "latest_supply_chain_scan": {
                            "id": "scan-secret",
                            "status": "completed",
                            "created_at": "2026-08-27T10:00:00Z",
                        },
                    },
                    {
                        "repository": {
                            "id": "repo-id-2",
                            "organization_id": "org-secret",
                            "full_name": "usestrix/sdk",
                            "provider": "github",
                        },
                        "summary": {
                            "component_count": 45,
                            "finding_count": 2,
                            "malicious_count": 0,
                            "suspicious_count": 0,
                            "vulnerable_count": 2,
                            "severity_counts": {"high": 1, "medium": 1},
                            "policy": {"enabled": False},
                        },
                        "latest_supply_chain_scan": None,
                    },
                ],
            }
        ),
    )

    assert cloud.run_cloud(["supply-chain", "summary"]) == 0
    output = capsys.readouterr().out
    for value in (
        "Supply-chain totals",
        "145",
        "open issues",
        "usestrix/strix",
        "critical 1",
        "1 malicious",
        "completed",
        "block",
        "PR checks off",
        "usestrix/sdk",
        "not run",
        "disabled",
        "repo-id",
    ):
        assert value in output
    for value in ("org-secret", "scan-secret", "ecosystems"):
        assert value not in output
    assert "Use --json for complete totals and repository records" in output


@pytest.mark.parametrize(
    ("command", "payload", "visible", "hidden"),
    [
        (
            ["webhooks", "get", "webhook-id"],
            {
                "webhook": {
                    "id": "webhook-id",
                    "organization_id": "org-secret",
                    "url": "https://example.com/hook",
                    "events": ["scan.completed", "scan.failed"],
                    "business_unit": None,
                    "secret_prefix": "whsec_1234",
                    "is_active": True,
                    "last_success_at": "2026-08-27T10:00:00Z",
                    "last_failure_at": "2026-08-26T10:00:00Z",
                    "created_by": "user-secret",
                    "created_at": "2026-08-20T10:00:00Z",
                    "updated_at": "2026-08-27T10:00:00Z",
                }
            },
            (
                "webhook-id",
                "https://example.com/hook",
                "scan.completed",
                "scan.failed",
                "all organization",
                "whsec_1234",
                "yes",
                "2026-08-26T10:00:00Z",
            ),
            ("org-secret", "user-secret", "nested field"),
        ),
        (
            ["chat", "get", "chat-id"],
            {
                "chat": {
                    "workspace_state": "running",
                    "id": "chat-id",
                    "title": "Investigate auth",
                    "status": "active",
                    "run_id": "run-id",
                    "sandbox_api_url": True,
                    "created_at": "2026-08-20T10:00:00Z",
                    "updated_at": "2026-08-27T10:00:00Z",
                    "last_message_at": "2026-08-27T09:59:00Z",
                }
            },
            (
                "chat-id",
                "Investigate auth",
                "active",
                "workspace state",
                "running",
                "run-id",
                "sandbox attached",
                "yes",
                "2026-08-27T09:59:00Z",
            ),
            ("sandbox api url", "nested field"),
        ),
    ],
)
def test_wrapped_detail_human_views_are_unwrapped_and_actionable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
    command: list[str],
    payload: dict[str, Any],
    visible: tuple[str, ...],
    hidden: tuple[str, ...],
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(http, "request", lambda *_a, **_k: FakeResponse(payload=payload))

    assert cloud.run_cloud(command) == 0
    output = capsys.readouterr().out
    for value in visible:
        assert value in output
    for value in hidden:
        assert value not in output


def test_trace_human_view_summarizes_events_and_preserves_selector(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    seen_query: dict[str, Any] = {}

    def fake_trace_request(_method: str, _path: str, **kwargs: Any) -> FakeResponse:
        seen_query.update(kwargs.get("query") or {})
        return FakeResponse(
            payload={
                "scan_id": "scan-id",
                "agent_id": "agent-id",
                "steps": [
                    {
                        "timestamp": "2026-08-27T10:00:00Z",
                        "kind": "tool_call",
                        "event_id": "event-id",
                        "tool_name": "browser",
                        "args": {
                            "url": "https://example.com",
                            "password": "trace-password-must-not-render",
                            "headers": {"Authorization": "Bearer trace-token-must-not-render"},
                            "sk_live_secret-as-dictionary-key": True,
                        },
                        "truncated": True,
                    },
                    {
                        "timestamp": "2026-08-27T10:01:00Z",
                        "kind": "finding",
                        "event_id": "finding-event-id",
                        "finding": {"title": "IDOR", "severity": "high"},
                    },
                    {
                        "timestamp": "2026-08-27T10:02:00Z",
                        "kind": "tool_result",
                        "event_id": "result-event-id",
                        "tool_name": "browser",
                        "status": "completed",
                        "result": "result-token-must-not-render",
                    },
                ],
                "cursor": "next-secret",
                "has_more": True,
                "note": "Older trace events remain available.",
            }
        )

    monkeypatch.setattr(
        http,
        "request",
        fake_trace_request,
    )

    assert (
        cloud.run_cloud(
            [
                "scans",
                "trace",
                "scan-id",
                "--agent-id",
                "agent-id",
                "--tool-name",
                "browser",
                "--limit",
                "25",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    for value in (
        "tool_call",
        "browser",
        "arguments: 4 field(s)",
        "high: IDOR",
        "event-id",
        "tool_result",
        "result: text (",
    ):
        assert value in output
    assert seen_query == {"agent_id": "agent-id", "tool_name": "browser", "limit": 25}
    for secret in (
        "trace-password-must-not-render",
        "trace-token-must-not-render",
        "result-token-must-not-render",
        "password",
        "sk_live_secret-as-dictionary-key",
    ):
        assert secret not in output
    assert "scans trace-event scan-id EVENT_ID" in output
    normalized_output = " ".join(output.replace("`", "").split())
    assert "same trace command with --cursor next-secret" in normalized_output
    assert "keep its --agent-id, --tool-name, and --limit options" in normalized_output
    assert "Older trace events remain available." in normalized_output


def test_paginated_human_list_shows_total_and_continuation_command(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            payload={
                "items": [
                    {
                        "id": "domain-id",
                        "domain": "staging.example.com",
                        "asset_type": "web_app",
                    }
                ],
                "meta": {
                    "page": 1,
                    "limit": 20,
                    "total_items": 51,
                    "total_pages": 3,
                    "has_next": True,
                },
            }
        ),
    )

    assert cloud.run_cloud(["domains", "list"]) == 0
    output = capsys.readouterr().out
    assert "Page 1/3" in output
    assert "51 total" in output
    assert "--page 2" in output


def test_empty_paginated_human_list_does_not_claim_page_one_of_zero() -> None:
    stream = io.StringIO()
    console = Console(file=stream, width=120, color_system=None, force_terminal=False)

    render.emit(
        console,
        {
            "items": [],
            "meta": {
                "page": 1,
                "limit": 25,
                "total_items": 0,
                "total_pages": 0,
                "has_next": False,
            },
        },
        as_json=False,
        view="GET /domains",
    )

    output = stream.getvalue()
    assert "0 total." in output
    assert "Page 1/0" not in output


def test_offset_pagination_explains_an_out_of_range_page() -> None:
    stream = io.StringIO()
    console = Console(file=stream, width=120, color_system=None, force_terminal=False)

    render.emit(
        console,
        {"components": [], "meta": {"total": 3, "limit": 2, "offset": 4}},
        as_json=False,
        view="GET /repositories/{repositoryId}/supply-chain/components",
    )

    output = stream.getvalue()
    assert "No items at offset 4; 3 total." in output
    assert "--offset 2" in output
    assert "Showing 3-3" not in output


def test_page_pagination_explains_an_out_of_range_page() -> None:
    stream = io.StringIO()
    console = Console(file=stream, width=120, color_system=None, force_terminal=False)

    render.emit(
        console,
        {
            "items": [],
            "meta": {
                "page": 4,
                "limit": 20,
                "total_items": 51,
                "total_pages": 3,
                "has_next": False,
            },
        },
        as_json=False,
        view="GET /domains",
    )

    output = stream.getvalue()
    assert "No items on page 4; 51 total." in output
    assert "--page 3" in output
    assert "Page 4/3" not in output


def test_human_detail_preserves_long_prose_beyond_table_cell_limit(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    description = (
        " ".join(["authorization context"] * 12) + " final-description-marker\nsecond-line-marker"
    )
    assert len(description) > 60
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            payload={
                "id": "vuln-id",
                "title": "Cross-tenant access",
                "description": description,
                "remediation_steps": "Validate tenant ownership before every object lookup.",
            }
        ),
    )

    assert cloud.run_cloud(["vulns", "get", "vuln-id"]) == 0
    output = capsys.readouterr().out
    assert "final-description-marker" in output
    assert "second-line-marker" in output
    assert "\\x0a" not in output
    assert "Validate tenant ownership" in output


def test_human_detail_bounds_extreme_scalar_values() -> None:
    assert render._detail_cell("x" * 2500).endswith("… [truncated; use --json]")
    assert len(render._detail_cell("x" * 2500)) == 2000
    assert render._detail_cell("first\nsecond") == "first\nsecond"


def test_large_vulnerability_detail_prioritizes_evidence_and_remediation() -> None:
    stream = io.StringIO()
    console = Console(file=stream, width=240, color_system=None, force_terminal=False)
    payload: dict[str, Any] = {f"future_field_{index}": f"value-{index}" for index in range(45)}
    payload.update(
        {
            "id": "vuln-id",
            "title": "Cross-tenant access",
            "status": "open",
            "severity": "high",
            "description": "A caller can read another tenant's object.",
            "technical_analysis": "The object lookup omits the tenant predicate.",
            "evidence": "GET /objects/other-tenant returned HTTP 200.",
            "remediation_steps": "Bind every object lookup to the authenticated tenant.",
            "cwe": ["CWE-639"],
            "location_meta": {"path": "src/routes/objects.ts", "line": 42},
            "fix_pr_eligible": True,
            "fix_pr_reason": "A repository and exact code location are available.",
            "fix_pr_url": "https://github.com/example/app/pull/42",
            "filed_at": "2026-08-28T12:00:00Z",
            "dependency_metadata": {"package": "example", "installed_version": "1.0.0"},
        }
    )

    render.emit(console, payload, as_json=False, view="GET /vulnerabilities/{vulnerabilityId}")

    output = stream.getvalue()
    for value in (
        "Cross-tenant access",
        "The object lookup omits the tenant predicate.",
        "GET /objects/other-tenant returned HTTP 200.",
        "Bind every object lookup to the authenticated tenant.",
        "CWE-639",
        "src/routes/objects.ts",
        "A repository and exact code location are available.",
        "https://github.com/example/app/pull/42",
        "2026-08-28T12:00:00Z",
        "package: example",
    ):
        assert value in output
    assert "additional field(s) omitted" in output


def test_test_user_human_view_joins_latest_verification(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            payload={
                "items": [
                    {
                        "id": "test-user-id",
                        "label": "Admin",
                        "username": "admin@example.com",
                        "mfa_method": "totp",
                        "has_password": True,
                        "has_totp_secret": True,
                        "login_url": "https://example.com/login",
                        "updated_at": "2026-08-27T10:00:00Z",
                    }
                ],
                "auth_checks": {
                    "test-user-id": {
                        "status": "failed",
                        "failure_code": "invalid_credentials",
                    }
                },
            }
        ),
    )

    assert cloud.run_cloud(["domains", "test-users", "list", "domain-id"]) == 0
    output = capsys.readouterr().out
    for value in ("password: set", "totp (secret set)", "failed: invalid_credentials"):
        assert value in output


def test_explicit_human_view_is_an_allowlist_and_preserves_uuid() -> None:
    stream = io.StringIO()
    console = Console(file=stream, width=120, color_system=None, force_terminal=False)
    uuid = "4d3a33cc-5c96-4e91-921c-682093efe780"

    render.emit(
        console,
        {
            "items": [
                {
                    "id": uuid,
                    "domain": "staging.example.com",
                    "asset_type": "web_app",
                    "verified": False,
                    "unknown_internal_scalar": "must-not-render",
                }
            ],
            "meta": {"total_items": 1},
        },
        as_json=False,
        view="GET /domains",
    )

    output = stream.getvalue()
    assert uuid in output
    assert "must-not-render" not in output


def test_wide_knowledge_table_keeps_title_readable_with_long_identifiers() -> None:
    stream = io.StringIO()
    console = Console(file=stream, width=120, color_system=None, force_terminal=False)
    document_id = "document-selector-" + "x" * 80
    source_id = "repos/usestrix__strix/" + "nested/" * 12 + "authentication.md"

    render.emit(
        console,
        {
            "organization_id": "org-secret",
            "docs": [
                {
                    "id": document_id,
                    "title": "Authentication guidance",
                    "source_type": "system",
                    "source_id": source_id,
                    "tags": ["auth"],
                    "updated_at": "2026-08-27T10:00:00Z",
                }
            ],
            "total": 1,
        },
        as_json=False,
        view="GET /knowledge",
    )

    output = stream.getvalue()
    assert "Authentication guidance" in output
    assert document_id in output
    assert "Copyable selectors" in output


def test_human_get_prioritizes_details_and_hides_internal_identity_fields(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        http,
        "request",
        lambda *_a, **_k: FakeResponse(
            payload={
                "id": "review-id",
                "organization_id": "org-id",
                "user_id": "user-id",
                "repository_full_name": "usestrix/strix",
                "pr_number": 1177,
                "pr_title": "Improve cloud CLI",
                "verdict": "pass",
                "findings": [{"severity": "high", "title": "Example"}],
            }
        ),
    )

    assert cloud.run_cloud(["pr-reviews", "get", "review-id"]) == 0
    output = capsys.readouterr().out
    for value in ("usestrix/strix", "1177", "Improve cloud CLI", "pass", "Example"):
        assert value in output
    assert "org-id" not in output
    assert "user-id" not in output
    assert "lossless machine-readable" in output


def test_workspace_use_accepts_list_number(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    auth_path = tmp_path / "platform-auth.json"
    monkeypatch.setattr(platform_cli, "AUTH_PATH", auth_path)
    monkeypatch.setattr(workspaces, "AUTH_PATH", auth_path)
    platform_cli.save_record({"api_token": "old", "scopes": ["organizations:read", "tokens:write"]})
    called_paths: list[str] = []

    def fake_request(_method: str, path: str, **_kwargs: Any) -> FakeResponse:
        called_paths.append(path)
        if path == "/workspaces":
            return FakeResponse(
                payload={
                    "workspaces": [
                        {"id": "org_1", "name": "One"},
                        {"id": "org_2", "name": "Two"},
                    ]
                }
            )
        return FakeResponse(
            status_code=200,
            payload={
                "api_token": "old",
                "organization_id": "org_2",
                "organization_name": "Two",
                "scopes": ["organizations:read", "tokens:write"],
            },
        )

    monkeypatch.setattr(http, "request", fake_request)
    assert cloud.run_cloud(["workspaces", "use", "2", "--json"]) == 0
    assert called_paths == ["/workspaces", "/workspaces/org_2/token"]
    record = platform_cli.read_record()
    assert record is not None
    assert record["api_token"] == "old"


def test_logout_help_does_not_remove_stored_auth(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: Any
) -> None:
    auth_path = tmp_path / "platform-auth.json"
    monkeypatch.setattr(platform_cli, "AUTH_PATH", auth_path)
    platform_cli.save_record({"api_token": "keep-me"})

    assert cloud.run_cloud(["logout", "--help"]) == 0
    assert platform_cli.read_record() == {"api_token": "keep-me"}
    assert "usage: strix cloud logout" in capsys.readouterr().out


def test_logout_rejects_unknown_arguments_without_removing_stored_auth(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    auth_path = tmp_path / "platform-auth.json"
    monkeypatch.setattr(platform_cli, "AUTH_PATH", auth_path)
    platform_cli.save_record({"api_token": "keep-me"})

    assert cloud.run_cloud(["logout", "--bogus"]) == 2
    assert platform_cli.read_record() == {"api_token": "keep-me"}
