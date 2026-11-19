"""CLI-session lifecycle, scope, and workspace-race behavior."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any

import pytest
import requests
from rich.console import Console

from strix.interface import cloud, platform_cli, platform_identity
from strix.interface.cloud import http
from strix.interface.cloud import session as cloud_session


if TYPE_CHECKING:
    from pathlib import Path


class Response:
    def __init__(self, payload: Any = None, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code
        self.ok = 200 <= status_code < 400
        self.text = json.dumps(payload) if payload is not None else ""
        self.headers = {"content-type": "application/json"}

    def json(self) -> Any:
        return self._payload


@pytest.fixture
def auth_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "platform-auth.json"
    monkeypatch.setattr(platform_cli, "AUTH_PATH", path)
    monkeypatch.delenv("STRIX_API_TOKEN", raising=False)
    monkeypatch.delenv("STRIX_WORKSPACE_ID", raising=False)
    return path


def test_http_workspace_pin_is_captured_once(
    auth_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    platform_cli.save_record(
        {
            "api_token": "secret",
            "organization_id": "org_start",
            "app_url": "https://app.example.test",
        }
    )
    assert auth_path.exists()
    sent: list[dict[str, str]] = []

    def fake_request(*_args: Any, **kwargs: Any) -> Response:
        sent.append(dict(kwargs["headers"]))
        return Response({})

    monkeypatch.setattr(requests, "request", fake_request)
    http.configure()
    platform_cli.save_record(
        {
            "api_token": "secret",
            "organization_id": "org_changed_elsewhere",
            "app_url": "https://app.example.test",
        }
    )
    http.request("GET", "/scans")
    assert sent[0]["X-Strix-Workspace"] == "org_start"


def test_session_scope_update_persists_only_for_stored_session(
    auth_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    platform_cli.save_record(
        {
            "api_token": "secret",
            "organization_id": "org_1",
            "app_url": "https://app.example.test",
            "scopes": ["scans:read"],
        }
    )
    monkeypatch.setattr(
        http,
        "request",
        lambda *_args, **_kwargs: Response(
            {
                "scopes": ["scans:read", "scans:write", "billing:read"],
                "requested_scopes": ["scans:read", "scans:write", "billing:read"],
                "scope_ceiling": ["scans:read", "scans:write", "billing:read"],
                "scope_profile": "minimal",
            }
        ),
    )
    assert cloud.run_cloud(["session", "scopes", "set", "minimal", "--json"]) == 0
    stored = platform_cli.read_record()
    assert stored is not None
    assert stored["scope_profile"] == "minimal"
    assert json.loads(capsys.readouterr().out)["scope_profile"] == "minimal"

    before = auth_path.read_text(encoding="utf-8")
    assert (
        cloud.run_cloud(["session", "scopes", "set", "minimal", "--token", "override", "--json"])
        == 0
    )
    assert auth_path.read_text(encoding="utf-8") == before


def test_logout_keeps_local_token_when_remote_outcome_is_not_definitive(
    auth_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    platform_cli.save_record(
        {
            "api_token": "secret",
            "organization_id": "org_1",
            "app_url": "https://app.example.test",
        }
    )
    monkeypatch.setattr(
        requests,
        "delete",
        lambda *_args, **_kwargs: Response({"detail": "unavailable"}, 503),
    )
    assert cloud.run_cloud(["logout", "--json"]) == 1
    assert auth_path.exists()
    assert json.loads(capsys.readouterr().out)["removed"] is False


@pytest.mark.parametrize("as_json", [False, True])
def test_session_scope_update_reports_local_storage_failure(
    auth_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, as_json: bool
) -> None:
    platform_cli.save_record(
        {
            "api_token": "secret",
            "organization_id": "org_1",
            "app_url": "https://app.example.test",
            "scopes": ["scans:read", "scans:write"],
        }
    )
    before = auth_path.read_text(encoding="utf-8")
    calls: list[tuple[str, str]] = []

    def request(method: str, path: str, **_kwargs: Any) -> Response:
        calls.append((method, path))
        return Response({"scopes": ["scans:read"], "scope_profile": "custom"})

    def fail_save(_record: dict[str, Any]) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(http, "request", request)
    monkeypatch.setattr(cloud_session, "save_record", fail_save)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

    argv = ["session", "scopes", "set", "--scopes", "scans:read"]
    assert cloud.run_cloud([*argv, *(["--json"] if as_json else [])]) == 1
    output = capsys.readouterr().out
    if as_json:
        payload = json.loads(output)
        assert payload["scopes_updated"] is True
        assert payload["local_record_updated"] is False
        output = payload["error"]
    assert "disk full" in output
    assert "session scopes" in output
    assert "platform updated the session scopes" in output
    assert calls == [("PATCH", "/cli/session")]
    assert auth_path.read_text(encoding="utf-8") == before


@pytest.mark.parametrize("environment_token", [False, True])
def test_session_scope_update_override_does_not_need_writable_local_storage(
    auth_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, environment_token: bool
) -> None:
    platform_cli.save_record({"api_token": "stored-secret", "scopes": ["scans:read"]})
    before = auth_path.read_text(encoding="utf-8")
    monkeypatch.setattr(
        http,
        "request",
        lambda *_args, **_kwargs: Response({"scopes": ["scans:read"], "scope_profile": "custom"}),
    )

    def fail_save(_record: dict[str, Any]) -> None:
        pytest.fail("an override session must not update the local record")

    monkeypatch.setattr(cloud_session, "save_record", fail_save)
    token_args = ["--token", "override"]
    if environment_token:
        monkeypatch.setenv("STRIX_API_TOKEN", "override")
        token_args = []
    argv = ["session", "scopes", "set", "--scopes", "scans:read", "--json", *token_args]
    assert cloud.run_cloud(argv) == 0
    assert json.loads(capsys.readouterr().out)["scopes"] == ["scans:read"]
    assert auth_path.read_text(encoding="utf-8") == before


def test_local_only_logout_is_explicit_and_recoverable(auth_path: Path, capsys: Any) -> None:
    platform_cli.save_record({"api_token": "secret"})
    assert cloud.run_cloud(["logout", "--local-only", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["local_only"] is True
    assert payload["remotely_revoked"] is False
    assert not auth_path.exists()


def test_session_json_errors_preserve_machine_readable_server_details(capsys: Any) -> None:
    error = http.CloudError(
        "workspace changed",
        payload={
            "detail": "workspace changed",
            "code": "workspace_session_changed",
            "current_organization_id": "org_current",
        },
    )

    assert cloud_session._error(Console(), error, as_json=True) == http.EXIT_ERROR
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "code": "workspace_session_changed",
        "current_organization_id": "org_current",
        "error": "workspace changed",
    }


def test_cli_device_identity_is_stable_and_privacy_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "cli-identity.json"
    monkeypatch.setattr(platform_identity, "IDENTITY_PATH", path)
    first = platform_identity.read_or_create_identity()
    second = platform_identity.read_or_create_identity(device_name="  Build   laptop  ")
    assert second["client_instance_id"] == first["client_instance_id"]
    assert second["device_name"] == "Build laptop"
    assert path.stat().st_mode & 0o777 == 0o600
