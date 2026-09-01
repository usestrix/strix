"""Tests for OpenCode (Zen/Go) subscription auth: prefix parsing and key store."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest import mock

import pytest
import requests

from strix.config import codex, opencode


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home" / ".strix" / "subscription-auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", path)
    return path


@pytest.mark.parametrize(
    ("model", "slug", "base_url", "protocol"),
    [
        (
            "opencode/claude-sonnet-5",
            "claude-sonnet-5",
            opencode.ZEN_BASE_URL,
            opencode.PROTOCOL_MESSAGES,
        ),
        ("opencode/gpt-5.4", "gpt-5.4", opencode.ZEN_BASE_URL, opencode.PROTOCOL_RESPONSES),
        ("opencode/grok-4.5", "grok-4.5", opencode.ZEN_BASE_URL, opencode.PROTOCOL_RESPONSES),
        ("OpenCode/Kimi-K3", "Kimi-K3", opencode.ZEN_BASE_URL, opencode.PROTOCOL_CHAT),
        (
            "OpenCode/Claude-Opus-5",
            "Claude-Opus-5",
            opencode.ZEN_BASE_URL,
            opencode.PROTOCOL_MESSAGES,
        ),
        ("opencode-go/kimi-k3", "kimi-k3", opencode.GO_BASE_URL, opencode.PROTOCOL_CHAT),
        (
            "opencode-go/gpt-5.6-luna",
            "gpt-5.6-luna",
            opencode.GO_BASE_URL,
            opencode.PROTOCOL_RESPONSES,
        ),
        ("opencode-go/grok-4.5", "grok-4.5", opencode.GO_BASE_URL, opencode.PROTOCOL_CHAT),
        # Probed per family against both gateways; a wrong protocol 500s.
        (
            "opencode/muse-spark-1.2",
            "muse-spark-1.2",
            opencode.ZEN_BASE_URL,
            opencode.PROTOCOL_RESPONSES,
        ),
        (
            "opencode/deepseek-v4-pro",
            "deepseek-v4-pro",
            opencode.ZEN_BASE_URL,
            opencode.PROTOCOL_CHAT,
        ),
        ("opencode/minimax-m3", "minimax-m3", opencode.ZEN_BASE_URL, opencode.PROTOCOL_CHAT),
        ("opencode/qwen3.6-plus", "qwen3.6-plus", opencode.ZEN_BASE_URL, opencode.PROTOCOL_CHAT),
        ("opencode/glm-5.2", "glm-5.2", opencode.ZEN_BASE_URL, opencode.PROTOCOL_CHAT),
        ("opencode/grok-4.6", "grok-4.6", opencode.ZEN_BASE_URL, opencode.PROTOCOL_RESPONSES),
        (
            "opencode/gpt-5.6-luna",
            "gpt-5.6-luna",
            opencode.ZEN_BASE_URL,
            opencode.PROTOCOL_RESPONSES,
        ),
        (
            "opencode/claude-opus-5",
            "claude-opus-5",
            opencode.ZEN_BASE_URL,
            opencode.PROTOCOL_MESSAGES,
        ),
    ],
)
def test_subscription_model_parses_prefixes(
    model: str, slug: str, base_url: str, protocol: str
) -> None:
    parsed = opencode.subscription_model(model)
    assert parsed is not None
    assert parsed.slug == slug
    assert parsed.base_url == base_url
    assert parsed.protocol == protocol
    assert parsed.uses_responses is (protocol == opencode.PROTOCOL_RESPONSES)


def test_claude_route_targets_the_anthropic_endpoint() -> None:
    parsed = opencode.subscription_model("opencode/claude-sonnet-5")
    assert parsed is not None
    assert parsed.messages_url == "https://opencode.ai/zen/v1/messages"


@pytest.mark.parametrize(
    ("model", "plan", "label", "metered"),
    [
        ("opencode/claude-sonnet-5", opencode.PLAN_ZEN, "OpenCode Zen", True),
        ("opencode/kimi-k3", opencode.PLAN_ZEN, "OpenCode Zen", True),
        ("opencode-go/kimi-k3", opencode.PLAN_GO, "OpenCode Go", False),
        ("OpenCode-Go/GPT-5.6-Luna", opencode.PLAN_GO, "OpenCode Go", False),
    ],
)
def test_plan_is_labelled_and_metered_per_prefix(
    model: str, plan: str, label: str, metered: bool
) -> None:
    parsed = opencode.subscription_model(model)
    assert parsed is not None
    assert parsed.plan == plan
    assert parsed.label == label
    # Zen bills prepaid credits per request; Go is a flat monthly plan.
    assert parsed.metered is metered
    assert opencode.subscription_plan(model) == plan


def test_subscription_plan_is_none_off_opencode() -> None:
    assert opencode.subscription_plan("chatgpt/gpt-5.4") is None
    assert opencode.subscription_plan("anthropic/claude-sonnet-5") is None
    assert opencode.subscription_plan(None) is None


@pytest.mark.parametrize(
    "model",
    ["openai/gpt-5.4", "chatgpt/gpt-5.4", "opencode/", "opencode-go/", "opencode", "", None],
)
def test_subscription_model_rejects_non_opencode(model: str | None) -> None:
    assert opencode.subscription_model(model) is None


def test_store_roundtrip_and_logout() -> None:
    assert opencode.read_record() is None
    assert opencode.is_authenticated() is False

    opencode.save_api_key("sk-oc-test")
    record = opencode.read_record()
    assert record is not None
    assert record["key"] == "sk-oc-test"
    assert opencode.is_authenticated() is True
    assert opencode.get_api_key() == "sk-oc-test"

    opencode.logout()
    assert opencode.read_record() is None
    opencode.logout()  # no-op when already gone


def test_store_coexists_with_chatgpt_record() -> None:
    codex.save_record({"type": "oauth", "access": "a", "refresh": "r", "account_id": "acct"})
    opencode.save_api_key("sk-oc-test")

    assert codex.read_record() is not None
    assert opencode.get_api_key() == "sk-oc-test"

    opencode.logout()
    assert codex.read_record() is not None
    assert opencode.read_record() is None


def test_get_api_key_raises_when_not_signed_in() -> None:
    with pytest.raises(opencode.OpencodeAuthError) as exc:
        opencode.get_api_key()
    assert exc.value.code == "not_authenticated"


def test_auth_mode_covers_both_subscriptions() -> None:
    assert opencode.auth_mode("opencode/claude-sonnet-5") == "subscription"
    assert opencode.auth_mode("opencode-go/kimi-k3") == "subscription"
    assert opencode.auth_mode("chatgpt/gpt-5.4") == "subscription"
    assert opencode.auth_mode("openai/gpt-5.4") == "api_key"
    assert opencode.auth_mode(None) == "api_key"


def test_subscription_provider() -> None:
    assert opencode.subscription_provider("opencode/claude-sonnet-5") == "opencode"
    assert opencode.subscription_provider("opencode-go/kimi-k3") == "opencode"
    assert opencode.subscription_provider("chatgpt/gpt-5.4") == "chatgpt"
    assert opencode.subscription_provider("openai/gpt-5.4") is None
    assert opencode.subscription_provider(None) is None


def _response(status_code: int, text: str = "") -> mock.MagicMock:
    response = mock.MagicMock()
    response.status_code = status_code
    response.text = text
    return response


def test_validate_api_key_accepts_ok() -> None:
    with mock.patch.object(requests, "get", return_value=_response(200)) as get:
        opencode.validate_api_key("sk-oc-test")
    assert get.call_args.kwargs["headers"]["Authorization"] == "Bearer sk-oc-test"


def test_validate_api_key_rejects_unauthorized() -> None:
    with (
        mock.patch.object(requests, "get", return_value=_response(401)),
        pytest.raises(opencode.OpencodeAuthError) as exc,
    ):
        opencode.validate_api_key("bad-key")
    assert exc.value.code == "invalid_key"


def test_validate_api_key_maps_network_errors() -> None:
    with (
        mock.patch.object(requests, "get", side_effect=requests.ConnectionError("boom")),
        pytest.raises(opencode.OpencodeAuthError) as exc,
    ):
        opencode.validate_api_key("sk-oc-test")
    assert exc.value.code == "unavailable"
