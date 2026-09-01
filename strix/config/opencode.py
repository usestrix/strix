"""OpenCode subscription auth: API-key sign-in and the clients that route
inference through the OpenCode gateway.

Covers both OpenCode offerings, Zen (pay-as-you-go credits) and Go (the
monthly subscription), which share one account and API key but live behind
different gateway base URLs. Unlike the ChatGPT subscription there is no
OAuth: the user copies a plain API key from https://opencode.ai/auth, and
using the gateway from other agents is officially supported.

The gateway speaks three protocols and serves each model family on exactly
one of them (see https://opencode.ai/docs/zen/), answering a request sent to
the wrong one with an unhandled 500 rather than a 404. ``_protocol()`` holds
the mapping; ``SubscriptionModel.protocol`` carries the result. Claude runs on
Anthropic's ``/messages``, which the OpenAI SDK cannot speak, so that route
goes through LiteLLM instead of the clients built here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import requests

from strix.config import codex


if TYPE_CHECKING:
    from openai import AsyncOpenAI


PROVIDER = "opencode"

ZEN_BASE_URL = "https://opencode.ai/zen/v1"
GO_BASE_URL = "https://opencode.ai/zen/go/v1"

# ``opencode/<model>`` runs on Zen credits; ``opencode-go/<model>`` on the Go
# subscription (matching OpenCode's own ``opencode-go/`` model ids).
ZEN_PREFIX = "opencode/"
GO_PREFIX = "opencode-go/"

AUTH_CONSOLE_URL = "https://opencode.ai/auth"

_KEY_CHECK_TIMEOUT = 30


class OpencodeAuthError(Exception):
    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


PROTOCOL_CHAT = "chat"
PROTOCOL_RESPONSES = "responses"
PROTOCOL_MESSAGES = "messages"

PLAN_ZEN = "zen"
PLAN_GO = "go"

_PLAN_LABELS = {PLAN_ZEN: "OpenCode Zen", PLAN_GO: "OpenCode Go"}


@dataclass(frozen=True)
class SubscriptionModel:
    slug: str
    base_url: str
    protocol: str
    plan: str

    @property
    def uses_responses(self) -> bool:
        return self.protocol == PROTOCOL_RESPONSES

    @property
    def messages_url(self) -> str:
        """Anthropic-protocol endpoint for this gateway, e.g. ``.../zen/v1/messages``."""
        return f"{self.base_url}/messages"

    @property
    def label(self) -> str:
        return _PLAN_LABELS[self.plan]

    @property
    def metered(self) -> bool:
        """Whether a run spends money per request.

        Zen bills prepaid credits per request, so its runs cost real money and
        must not be reported as free. Go is a flat monthly fee, where a run's
        marginal cost genuinely is zero.
        """
        return self.plan == PLAN_ZEN


def _protocol(slug: str, base_url: str) -> str:
    """Which wire protocol the gateway serves *slug* on.

    The gateway routes by model family and answers a request sent to the wrong
    protocol with an unhandled 500 rather than a 404, so the mapping has to be
    right. Probed against both gateways per family:

    * Claude on Anthropic's ``/messages``
    * GPT, Grok (Zen) and Muse on OpenAI's ``/responses``
    * DeepSeek, MiniMax, Kimi, GLM and Qwen on Chat Completions

    Grok is absent from the Go catalog, so its Zen-only Responses route costs
    nothing there. Kimi and Qwen also answer on ``/messages``, but Chat
    Completions works for them on both plans and stays the single mapping.
    """
    lowered = slug.lower()
    if lowered.startswith("claude-"):
        return PROTOCOL_MESSAGES
    if lowered.startswith(("gpt-", "muse-")):
        return PROTOCOL_RESPONSES
    if lowered.startswith("grok") and base_url == ZEN_BASE_URL:
        return PROTOCOL_RESPONSES
    return PROTOCOL_CHAT


def subscription_model(model_name: str | None) -> SubscriptionModel | None:
    """The gateway model behind an ``opencode/`` or ``opencode-go/`` STRIX_LLM."""
    name = (model_name or "").strip()
    lowered = name.lower()
    for prefix, base_url, plan in (
        (GO_PREFIX, GO_BASE_URL, PLAN_GO),
        (ZEN_PREFIX, ZEN_BASE_URL, PLAN_ZEN),
    ):
        if lowered.startswith(prefix):
            slug = name[len(prefix) :]
            if not slug:
                return None
            return SubscriptionModel(slug, base_url, _protocol(slug, base_url), plan)
    return None


def read_record() -> dict[str, Any] | None:
    record = codex.read_provider_record(PROVIDER)
    if not isinstance(record, dict) or record.get("type") != "api_key":
        return None
    key = record.get("key")
    if not isinstance(key, str) or not key:
        return None
    return record


def is_authenticated() -> bool:
    return read_record() is not None


def save_api_key(key: str) -> None:
    codex.save_provider_record(PROVIDER, {"type": "api_key", "provider": PROVIDER, "key": key})


def logout() -> None:
    codex.remove_provider_record(PROVIDER)


def get_api_key() -> str:
    record = read_record()
    if record is None:
        raise OpencodeAuthError(
            "not_authenticated", "not signed in; run: strix auth login opencode"
        )
    return str(record["key"])


def validate_api_key(key: str) -> None:
    """Check the key against the gateway's models endpoint; raise if rejected."""
    try:
        response = requests.get(
            f"{ZEN_BASE_URL}/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=_KEY_CHECK_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise OpencodeAuthError("unavailable", str(exc)) from exc
    if response.status_code in (401, 403):
        raise OpencodeAuthError(
            "invalid_key", f"OpenCode rejected the API key (HTTP {response.status_code})"
        )
    if response.status_code >= 400:
        raise OpencodeAuthError("http_error", f"HTTP {response.status_code}: {response.text[:300]}")


def build_openai_client(base_url: str) -> AsyncOpenAI:
    import httpx
    from openai import AsyncOpenAI

    return AsyncOpenAI(
        api_key=get_api_key(),
        base_url=base_url,
        http_client=httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=30.0)),
    )


_subscription_clients: dict[str, AsyncOpenAI] = {}


def get_subscription_client(base_url: str) -> AsyncOpenAI:
    client = _subscription_clients.get(base_url)
    if client is None:
        client = build_openai_client(base_url)
        _subscription_clients[base_url] = client
    return client


def auth_mode(model_name: str | None) -> str:
    """Return "subscription" when STRIX_LLM runs on any subscription
    (OpenCode or ChatGPT), else "api_key"."""
    if subscription_model(model_name) or codex.subscription_model(model_name):
        return "subscription"
    return "api_key"


def subscription_plan(model_name: str | None) -> str | None:
    """Which OpenCode plan STRIX_LLM runs on: "zen", "go", or None.

    Recorded alongside ``subscription_provider`` rather than folded into it, so
    consumers that compare the provider against "opencode" keep working.
    """
    oc = subscription_model(model_name)
    return oc.plan if oc else None


def subscription_provider(model_name: str | None) -> str | None:
    """The subscription behind STRIX_LLM: "opencode", "chatgpt", or None."""
    if subscription_model(model_name):
        return PROVIDER
    if codex.subscription_model(model_name):
        return "chatgpt"
    return None
