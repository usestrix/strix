"""Tests for Anthropic Workload Identity Federation: exchange, refresh, routing."""

from __future__ import annotations

import asyncio
import json
import shlex
import subprocess
import sys
import time
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest
import requests
from agents.extensions.models.litellm_model import LitellmModel

from strix.config import anthropic_wif, codex, entra_user, loader
from strix.config.models import StrixProvider


if TYPE_CHECKING:
    from pathlib import Path


_WIF_ENV = {
    "ANTHROPIC_FEDERATION_RULE_ID": "fdrl_rule",
    "ANTHROPIC_ORGANIZATION_ID": "00000000-0000-0000-0000-000000000000",
    "ANTHROPIC_SERVICE_ACCOUNT_ID": "svac_sa",
}


@pytest.fixture
def token_file(tmp_path: Path) -> Path:
    path = tmp_path / "jwt"
    path.write_text("jwt-1\n", encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, token_file: Path) -> None:
    for key in (
        "STRIX_LLM",
        "LLM_API_KEY",
        "OPENAI_API_KEY",
        "LLM_API_BASE",
        "OPENAI_API_BASE",
        "OPENAI_BASE_URL",
        "LITELLM_BASE_URL",
        "OLLAMA_API_BASE",
        "ANTHROPIC_WORKSPACE_ID",
        "ANTHROPIC_IDENTITY_TOKEN",
        "ANTHROPIC_IDENTITY_TOKEN_COMMAND",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "STRIX_ENTRA_TENANT_ID",
        "STRIX_ENTRA_APP_ID",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in _WIF_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("ANTHROPIC_IDENTITY_TOKEN_FILE", str(token_file))
    monkeypatch.setattr(entra_user, "AUTH_PATH", tmp_path / "entra-auth.json")
    monkeypatch.setattr(loader, "_override", tmp_path / "missing-config.json")
    monkeypatch.setattr(loader, "_cached", None)
    anthropic_wif.reset_cache()


def _response(status: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> Any:
    resp = mock.MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = body
    resp.headers = headers or {}
    return resp


def _ok(token: str = "sk-ant-oat01-a", expires_in: int = 600) -> Any:  # noqa: S107
    return _response(200, {"access_token": token, "token_type": "Bearer", "expires_in": expires_in})


def test_configured_only_with_ids_and_a_token_source(monkeypatch: pytest.MonkeyPatch) -> None:
    assert anthropic_wif.is_configured()
    monkeypatch.delenv("ANTHROPIC_IDENTITY_TOKEN_FILE")
    monkeypatch.setattr(loader, "_cached", None)
    assert not anthropic_wif.is_configured()
    monkeypatch.setenv("ANTHROPIC_IDENTITY_TOKEN", "jwt-literal")
    assert anthropic_wif.is_configured()
    monkeypatch.delenv("ANTHROPIC_SERVICE_ACCOUNT_ID")
    monkeypatch.setattr(loader, "_cached", None)
    assert not anthropic_wif.is_configured()


def test_exchange_sends_jwt_bearer_grant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_WORKSPACE_ID", "wrkspc_ws")
    with mock.patch.object(anthropic_wif.requests, "post", return_value=_ok()) as post:
        token, expires_at = anthropic_wif.exchange()
    assert token == "sk-ant-oat01-a"  # noqa: S105
    assert expires_at > 0
    url = post.call_args.args[0]
    assert url == "https://api.anthropic.com/v1/oauth/token"
    assert post.call_args.kwargs["json"] == {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": "jwt-1",
        "federation_rule_id": "fdrl_rule",
        "organization_id": "00000000-0000-0000-0000-000000000000",
        "service_account_id": "svac_sa",
        "workspace_id": "wrkspc_ws",
    }


def test_exchange_omits_unset_workspace() -> None:
    with mock.patch.object(anthropic_wif.requests, "post", return_value=_ok()) as post:
        anthropic_wif.exchange()
    assert "workspace_id" not in post.call_args.kwargs["json"]


def test_token_url_follows_api_base() -> None:
    assert anthropic_wif.token_url("https://gw.example/v1/") == "https://gw.example/v1/oauth/token"
    assert anthropic_wif.token_url(None) == "https://api.anthropic.com/v1/oauth/token"


def test_exchange_rereads_the_token_file(token_file: Path) -> None:
    with mock.patch.object(anthropic_wif.requests, "post", return_value=_ok()) as post:
        anthropic_wif.exchange()
        token_file.write_text("jwt-2", encoding="utf-8")
        anthropic_wif.exchange()
    assertions = [call.kwargs["json"]["assertion"] for call in post.call_args_list]
    assert assertions == ["jwt-1", "jwt-2"]


def test_exchange_error_names_status_but_not_the_jwt() -> None:
    body = {
        "type": "error",
        "error": {"type": "authentication_error", "message": "Authentication failed"},
    }
    resp = _response(401, body, {"request-id": "req_1"})
    with (
        mock.patch.object(anthropic_wif.requests, "post", return_value=resp),
        pytest.raises(anthropic_wif.WifAuthError) as exc_info,
    ):
        anthropic_wif.exchange()
    message = str(exc_info.value)
    assert "HTTP 401" in message
    assert "authentication_error" in message
    assert "req_1" in message
    assert "jwt-1" not in message


def test_github_actions_oidc_token_used_without_a_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_IDENTITY_TOKEN_FILE")
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://gh.example/token?x=1")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "gh-req")
    gh = _response(200, {"value": "gh-jwt"})
    with mock.patch.object(anthropic_wif.requests, "get", return_value=gh) as get:
        assert anthropic_wif.read_identity_token() == "gh-jwt"
    assert get.call_args.kwargs["params"] == {"audience": "https://api.anthropic.com"}
    assert get.call_args.kwargs["headers"] == {"Authorization": "Bearer gh-req"}


def _python_command(code: str) -> str:
    return shlex.join([sys.executable, "-c", code])


def _use_token_command(monkeypatch: pytest.MonkeyPatch, command: str) -> None:
    monkeypatch.delenv("ANTHROPIC_IDENTITY_TOKEN_FILE")
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setenv("ANTHROPIC_IDENTITY_TOKEN_COMMAND", command)


def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> Any:
    return subprocess.CompletedProcess(["cmd"], returncode, stdout, stderr)


def test_token_command_used_without_a_file(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_token_command(monkeypatch, _python_command("print('cmd-jwt')"))
    assert anthropic_wif.is_configured()
    assert anthropic_wif.read_identity_token() == "cmd-jwt"


def test_token_file_wins_over_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_IDENTITY_TOKEN_COMMAND", "should-not-run")
    monkeypatch.setattr(loader, "_cached", None)
    with mock.patch.object(anthropic_wif.subprocess, "run") as run:
        assert anthropic_wif.read_identity_token() == "jwt-1"
    run.assert_not_called()


def test_token_command_runs_on_every_exchange(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_token_command(monkeypatch, "issue-token --audience x")
    outputs = [_completed(stdout="jwt-a\n"), _completed(stdout="jwt-b\n")]
    with (
        mock.patch.object(anthropic_wif.subprocess, "run", side_effect=outputs) as run,
        mock.patch.object(anthropic_wif.requests, "post", return_value=_ok()) as post,
    ):
        anthropic_wif.exchange()
        anthropic_wif.exchange()
    assert run.call_args.args[0] == ["issue-token", "--audience", "x"]
    assert run.call_args.kwargs["stdin"] == subprocess.DEVNULL
    assertions = [call.kwargs["json"]["assertion"] for call in post.call_args_list]
    assert assertions == ["jwt-a", "jwt-b"]


def test_token_command_failure_names_status_and_stderr_but_not_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    code = "import sys; print('secret-jwt'); print('boom', file=sys.stderr); sys.exit(3)"
    _use_token_command(monkeypatch, _python_command(code))
    with pytest.raises(anthropic_wif.WifAuthError) as exc:
        anthropic_wif.read_identity_token()
    assert "status 3" in str(exc.value)
    assert "boom" in str(exc.value)
    assert "secret-jwt" not in str(exc.value)


@pytest.mark.parametrize(
    ("stdout", "message"),
    [("\n", "printed no token"), ("jwt-a jwt-b\n", "single JWT")],
)
def test_token_command_output_must_be_one_jwt(
    monkeypatch: pytest.MonkeyPatch, stdout: str, message: str
) -> None:
    _use_token_command(monkeypatch, "issue-token")
    with (
        mock.patch.object(anthropic_wif.subprocess, "run", return_value=_completed(stdout=stdout)),
        pytest.raises(anthropic_wif.WifAuthError, match=message),
    ):
        anthropic_wif.read_identity_token()


def test_token_command_not_found(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _use_token_command(monkeypatch, str(tmp_path / "no-such-command"))
    with pytest.raises(anthropic_wif.WifAuthError, match="could not run"):
        anthropic_wif.read_identity_token()


def test_token_command_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_token_command(monkeypatch, "issue-token")
    timeout = subprocess.TimeoutExpired(["issue-token"], 30)
    with (
        mock.patch.object(anthropic_wif.subprocess, "run", side_effect=timeout),
        pytest.raises(anthropic_wif.WifAuthError, match="timed out"),
    ):
        anthropic_wif.read_identity_token()


def test_token_command_expands_home_in_program(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_token_command(monkeypatch, "~/bin/issue-token token")
    monkeypatch.setenv("HOME", "/home/someone")
    with mock.patch.object(
        anthropic_wif.subprocess, "run", return_value=_completed(stdout="jwt\n")
    ) as run:
        anthropic_wif.read_identity_token()
    assert run.call_args.args[0] == ["/home/someone/bin/issue-token", "token"]


def test_token_command_persists_and_is_read_from_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = tmp_path / "config.json"
    config.write_text('{"env": {}}', encoding="utf-8")
    monkeypatch.setattr(loader, "_override", config)
    command = "issue-token --from-config"
    _use_token_command(monkeypatch, command)
    loader.persist_current()
    saved = json.loads(config.read_text(encoding="utf-8"))["env"]
    assert saved.get("ANTHROPIC_IDENTITY_TOKEN_COMMAND") == command

    monkeypatch.delenv("ANTHROPIC_IDENTITY_TOKEN_COMMAND")
    monkeypatch.setattr(loader, "_cached", None)
    with mock.patch.object(
        anthropic_wif.subprocess, "run", return_value=_completed(stdout="jwt\n")
    ) as run:
        assert anthropic_wif.read_identity_token() == "jwt"
    assert run.call_args.args[0] == ["issue-token", "--from-config"]


def test_empty_env_clears_saved_token_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"env": {"ANTHROPIC_IDENTITY_TOKEN_COMMAND": "issue-token"}}), encoding="utf-8"
    )
    monkeypatch.setattr(loader, "_override", config)
    _use_token_command(monkeypatch, "")
    assert not anthropic_wif.is_configured()
    loader.persist_current()
    saved = json.loads(config.read_text(encoding="utf-8"))["env"]
    assert "ANTHROPIC_IDENTITY_TOKEN_COMMAND" not in saved


def _sign_in_to_entra(**overrides: Any) -> None:
    record = {
        "type": "oauth",
        "provider": "entra",
        "tenant": "tenant-id",
        "app": "app-id",
        "access": "entra-jwt",
        "refresh": "entra-refresh",
        "expires_at": time.time() + 3600,
    }
    record.update(overrides)
    entra_user.save_record(record)


def _without_token_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_IDENTITY_TOKEN_FILE")
    monkeypatch.setattr(loader, "_cached", None)


def test_entra_sign_in_used_without_other_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    _without_token_file(monkeypatch)
    assert not anthropic_wif.is_configured()
    _sign_in_to_entra()
    assert anthropic_wif.is_configured()
    assert anthropic_wif.read_identity_token() == "entra-jwt"


def test_token_command_wins_over_entra_sign_in(monkeypatch: pytest.MonkeyPatch) -> None:
    _sign_in_to_entra()
    _use_token_command(monkeypatch, "issue-token")
    with mock.patch.object(
        anthropic_wif.subprocess, "run", return_value=_completed(stdout="cmd-jwt\n")
    ):
        assert anthropic_wif.read_identity_token() == "cmd-jwt"


def test_entra_refresh_failure_names_the_fix(monkeypatch: pytest.MonkeyPatch) -> None:
    _without_token_file(monkeypatch)
    _sign_in_to_entra(expires_at=time.time() - 1)
    refused = entra_user.EntraAuthError("invalid_grant", "invalid_grant: AADSTS70000")
    with (
        mock.patch.object(entra_user, "refresh_tokens", side_effect=refused),
        pytest.raises(anthropic_wif.WifAuthError, match="strix auth login entra"),
    ):
        anthropic_wif.read_identity_token()


def test_cached_token_reused_until_advisory_window() -> None:
    with (
        mock.patch.object(anthropic_wif.time, "time", return_value=1000.0),
        mock.patch.object(anthropic_wif.requests, "post", return_value=_ok(expires_in=600)) as post,
    ):
        assert anthropic_wif.get_valid_token() == "sk-ant-oat01-a"
        assert anthropic_wif.get_valid_token() == "sk-ant-oat01-a"
    assert post.call_count == 1


def test_refreshes_inside_advisory_window() -> None:
    with (
        mock.patch.object(anthropic_wif.requests, "post", return_value=_ok("sk-ant-oat01-a")),
        mock.patch.object(anthropic_wif.time, "time", return_value=1000.0),
    ):
        anthropic_wif.get_valid_token()
    # expires at 1600; 1500 is inside the 120s advisory window.
    with (
        mock.patch.object(anthropic_wif.time, "time", return_value=1500.0),
        mock.patch.object(anthropic_wif.requests, "post", return_value=_ok("sk-ant-oat01-b")),
    ):
        assert anthropic_wif.get_valid_token() == "sk-ant-oat01-b"


def test_advisory_refresh_failure_keeps_cached_token() -> None:
    with (
        mock.patch.object(anthropic_wif.time, "time", return_value=1000.0),
        mock.patch.object(anthropic_wif.requests, "post", return_value=_ok()),
    ):
        anthropic_wif.get_valid_token()
    with (
        mock.patch.object(anthropic_wif.time, "time", return_value=1500.0),
        mock.patch.object(
            anthropic_wif.requests, "post", side_effect=requests.ConnectionError("down")
        ),
    ):
        assert anthropic_wif.get_valid_token() == "sk-ant-oat01-a"


def test_mandatory_refresh_failure_raises() -> None:
    with (
        mock.patch.object(anthropic_wif.time, "time", return_value=1000.0),
        mock.patch.object(anthropic_wif.requests, "post", return_value=_ok()),
    ):
        anthropic_wif.get_valid_token()
    with (
        mock.patch.object(anthropic_wif.time, "time", return_value=1580.0),
        mock.patch.object(
            anthropic_wif.requests, "post", side_effect=requests.ConnectionError("down")
        ),
        pytest.raises(anthropic_wif.WifAuthError),
    ):
        anthropic_wif.get_valid_token()


def test_slow_failed_refresh_does_not_serve_an_expired_token() -> None:
    with (
        mock.patch.object(anthropic_wif.time, "time", return_value=1000.0),
        mock.patch.object(anthropic_wif.requests, "post", return_value=_ok()),
    ):
        anthropic_wif.get_valid_token()
    # Expires at 1600. The refresh starts at 1555, inside the advisory window but
    # outside the mandatory one, and fails only after the token has expired.
    clock = iter([1555.0, 1555.0, 1610.0, 1610.0])

    def _slow_failure(*_args: Any, **_kwargs: Any) -> Any:
        raise requests.ConnectionError("down")

    with (
        mock.patch.object(anthropic_wif.time, "time", side_effect=lambda: next(clock)),
        mock.patch.object(anthropic_wif.requests, "post", side_effect=_slow_failure),
        pytest.raises(anthropic_wif.WifAuthError),
    ):
        anthropic_wif.get_valid_token()


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("anthropic/claude-sonnet-5-5", True),
        ("litellm/anthropic/claude-sonnet-5-5", True),
        ("claude-sonnet-5-5", False),
        ("bedrock/anthropic.claude-sonnet-5-5", False),
        ("vertex_ai/claude-sonnet-5-5", False),
        ("openrouter/anthropic/claude-sonnet-5-5", False),
        ("openai/gpt-5", False),
    ],
)
def test_applies_only_to_anthropic_direct(model: str, *, expected: bool) -> None:
    assert anthropic_wif.applies(model) is expected


def test_explicit_api_key_wins() -> None:
    assert not anthropic_wif.applies("anthropic/claude-sonnet-5-5", "sk-ant-api03-x")


def test_auth_mode_reports_workload_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    assert codex.auth_mode("anthropic/claude-sonnet-5-5") == "workload_identity"
    assert codex.auth_mode("openai/gpt-5") == "api_key"
    monkeypatch.setenv("LLM_API_KEY", "sk-ant-api03-x")
    monkeypatch.setattr(loader, "_cached", None)
    assert codex.auth_mode("anthropic/claude-sonnet-5-5") == "api_key"


def _unwrap(model: object) -> object:
    while hasattr(model, "_inner"):
        model = model._inner
    return model


def test_provider_federates_anthropic_requests() -> None:
    model = _unwrap(StrixProvider().get_model("anthropic/claude-sonnet-5-5"))
    sent: dict[str, Any] = {}

    async def fake_fetch(self: Any, *_args: Any, **_kwargs: Any) -> str:
        sent["api_key"] = self.api_key
        return "response"

    with (
        mock.patch.object(LitellmModel, "_fetch_response", fake_fetch),
        mock.patch.object(anthropic_wif, "get_valid_token", return_value="sk-ant-oat01-z"),
    ):
        result = asyncio.run(model._fetch_response())  # type: ignore[attr-defined]
    assert result == "response"
    assert sent["api_key"] == "sk-ant-oat01-z"


def test_provider_leaves_other_litellm_models_alone() -> None:
    model = _unwrap(StrixProvider().get_model("deepseek/deepseek-chat"))
    assert type(model).__name__ == "LitellmModel"


def test_provider_uses_api_key_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_API_KEY", "sk-ant-api03-x")
    monkeypatch.setattr(loader, "_cached", None)
    model = _unwrap(StrixProvider().get_model("anthropic/claude-sonnet-5-5"))
    assert type(model).__name__ == "LitellmModel"
