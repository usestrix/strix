import json
from pathlib import Path

import pytest

from strix.llm.codex_oauth import (
    CodexOAuthCredentials,
    CodexOAuthError,
    _post_codex_responses,
    build_codex_responses_payload,
    load_codex_oauth_credentials,
    parse_responses_sse_events,
    refresh_codex_oauth_credentials,
)
from strix.llm.config import LLMConfig
from strix.llm.llm import LLM


def test_llm_config_detects_codex_oauth_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "codex/gpt-5.5")

    config = LLMConfig()

    assert config.uses_codex_oauth is True
    assert config.codex_model == "gpt-5.5"


def test_llm_does_not_retry_codex_oauth_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "codex/gpt-5.5")

    llm = LLM(LLMConfig())

    assert llm._should_retry(CodexOAuthError("Run `codex login` first.")) is False


@pytest.mark.asyncio
async def test_codex_oauth_stream_yields_single_processed_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LLM", "codex/gpt-5.5")

    def fake_complete_codex_oauth(*args, **kwargs):
        return (
            "<thinking>hidden</thinking><function=finish><parameter=summary>done</parameter></function>",
            {"input_tokens": 1, "output_tokens": 2},
        )

    monkeypatch.setattr("strix.llm.llm.complete_codex_oauth", fake_complete_codex_oauth)

    llm = LLM(LLMConfig())
    responses = [
        response
        async for response in llm._stream_codex_oauth([{"role": "user", "content": "Hi"}])
    ]

    assert len(responses) == 1
    assert "<thinking>" not in responses[0].content
    assert responses[0].tool_invocations
    assert llm._total_stats.input_tokens == 1
    assert llm._total_stats.output_tokens == 2


def test_load_codex_oauth_credentials_reads_codex_auth_json(tmp_path: Path) -> None:
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(
        json.dumps(
            {
                "auth_mode": "chatgpt",
                "tokens": {
                    "access_token": "access-token",
                    "account_id": "account-id",
                },
            }
        ),
        encoding="utf-8",
    )

    credentials = load_codex_oauth_credentials(tmp_path)

    assert credentials.access_token == "access-token"  # noqa: S105
    assert credentials.account_id == "account-id"


def test_load_codex_oauth_credentials_errors_when_not_logged_in(tmp_path: Path) -> None:
    with pytest.raises(CodexOAuthError, match="Codex auth file not found"):
        load_codex_oauth_credentials(tmp_path)


def test_refresh_codex_oauth_credentials_persists_new_tokens(tmp_path: Path) -> None:
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(
        json.dumps(
            {
                "auth_mode": "chatgpt",
                "tokens": {
                    "id_token": "old-id",
                    "access_token": "old-access",
                    "refresh_token": "old-refresh",
                    "account_id": "account-id",
                },
            }
        ),
        encoding="utf-8",
    )

    class FakeResponse:
        status_code = 200
        ok = True
        text = ""

        def json(self) -> dict[str, str]:
            return {
                "id_token": "new-id",
                "access_token": "new-access",
                "refresh_token": "new-refresh",
            }

    calls = []

    def fake_post(url: str, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse()

    credentials = refresh_codex_oauth_credentials(tmp_path, post=fake_post)

    updated = json.loads(auth_file.read_text(encoding="utf-8"))
    assert credentials.access_token == "new-access"  # noqa: S105
    assert updated["tokens"]["id_token"] == "new-id"  # noqa: S105
    assert updated["tokens"]["access_token"] == "new-access"  # noqa: S105
    assert updated["tokens"]["refresh_token"] == "new-refresh"  # noqa: S105
    assert updated["tokens"]["account_id"] == "account-id"
    assert calls[0][0] == "https://auth.openai.com/oauth/token"
    assert calls[0][1]["json"]["grant_type"] == "refresh_token"


def test_post_codex_responses_uses_user_agent_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    class FakeResponse:
        pass

    def fake_post(url: str, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse()

    monkeypatch.setattr("strix.llm.codex_oauth.requests.post", fake_post)

    response = _post_codex_responses(
        "https://example.test/codex",
        CodexOAuthCredentials(access_token="access-token", account_id="account-id"),
        {"model": "gpt-5.5"},
        60,
    )

    assert isinstance(response, FakeResponse)
    headers = calls[0][1]["headers"]
    assert headers["User-Agent"] == "strix-codex-oauth"
    assert "version" not in headers


def test_build_codex_responses_payload_converts_chat_messages() -> None:
    payload = build_codex_responses_payload(
        model="gpt-5.5",
        messages=[
            {"role": "system", "content": "System prompt."},
            {"role": "user", "content": "Find bugs."},
            {"role": "assistant", "content": "I will inspect the code."},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Tool Results:"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,abc"}},
                ],
            },
        ],
        reasoning_effort="high",
    )

    assert payload["model"] == "gpt-5.5"
    assert payload["instructions"] == "System prompt."
    assert payload["stream"] is True
    assert payload["reasoning"] == {"effort": "high"}
    assert payload["input"] == [
        {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "Find bugs."}],
        },
        {
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "I will inspect the code."}],
        },
        {
            "type": "message",
            "role": "user",
            "content": [
                {"type": "input_text", "text": "Tool Results:"},
                {"type": "input_image", "image_url": "data:image/png;base64,abc"},
            ],
        },
    ]


def test_parse_responses_sse_events_extracts_text_deltas_and_usage() -> None:
    content, usage = parse_responses_sse_events(
        [
            'data: {"type":"response.output_text.delta","delta":"hel"}',
            'data: {"type":"response.output_text.delta","delta":"lo"}',
            (
                'data: {"type":"response.completed","response":'
                '{"usage":{"input_tokens":3,"output_tokens":2}}}'
            ),
            "data: [DONE]",
        ]
    )

    assert content == "hello"
    assert usage == {"input_tokens": 3, "output_tokens": 2}
