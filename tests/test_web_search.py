"""Tests for web_search provider selection and the Exa backend."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import requests

from strix.config.settings import IntegrationSettings
from strix.tools.web_search import tool


if TYPE_CHECKING:
    from typing import Self

    import pytest


class _FakeResponse:
    def __init__(self, body: dict[str, Any]) -> None:
        self._body = body
        self.headers: dict[str, str] = {}

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._body


def test_auto_prefers_exa_when_both_keys_set() -> None:
    integrations = IntegrationSettings(PERPLEXITY_API_KEY="pk", EXA_API_KEY="ek")
    assert tool._resolve_provider(integrations) == ("exa", "ek")


def test_auto_falls_back_to_perplexity_when_only_perplexity_is_set() -> None:
    integrations = IntegrationSettings(PERPLEXITY_API_KEY="pk")
    assert tool._resolve_provider(integrations) == ("perplexity", "pk")


def test_explicit_exa_ignores_a_configured_perplexity_key() -> None:
    integrations = IntegrationSettings(
        PERPLEXITY_API_KEY="pk",
        EXA_API_KEY="ek",
        STRIX_WEB_SEARCH_PROVIDER="exa",
    )
    assert tool._resolve_provider(integrations) == ("exa", "ek")


def test_explicit_perplexity_ignores_a_configured_exa_key() -> None:
    integrations = IntegrationSettings(
        PERPLEXITY_API_KEY="pk",
        EXA_API_KEY="ek",
        STRIX_WEB_SEARCH_PROVIDER="perplexity",
    )
    assert tool._resolve_provider(integrations) == ("perplexity", "pk")


def test_explicit_exa_without_a_key_names_only_exa() -> None:
    integrations = IntegrationSettings(
        PERPLEXITY_API_KEY="pk",
        STRIX_WEB_SEARCH_PROVIDER="exa",
    )
    resolved = tool._resolve_provider(integrations)
    assert isinstance(resolved, dict)
    assert resolved["success"] is False
    assert "EXA_API_KEY" in resolved["error"]
    assert "PERPLEXITY_API_KEY" not in resolved["error"]


def test_no_keys_names_both_providers() -> None:
    resolved = tool._resolve_provider(IntegrationSettings())
    assert isinstance(resolved, dict)
    assert "EXA_API_KEY or PERPLEXITY_API_KEY" in resolved["error"]


def test_exa_content_appends_citation_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_post(url: str, **kwargs: Any) -> _FakeResponse:
        captured["url"] = url
        captured["headers"] = kwargs["headers"]
        captured["json"] = kwargs["json"]
        return _FakeResponse(
            {
                "answer": "CVE-2024-0001 affects it.",
                "citations": [
                    {"url": "https://nvd.example/cve", "title": "NVD entry"},
                    {"id": "https://blog.example/post"},
                    "not-a-dict",
                    {"title": "no url"},
                ],
            }
        )

    monkeypatch.setattr(requests, "post", fake_post)

    content = tool._exa_content("ek", "OpenSSH 7.4 RCE?")

    assert captured["url"] == "https://api.exa.ai/answer"
    assert captured["headers"]["x-api-key"] == "ek"
    assert "OpenSSH 7.4 RCE?" in captured["json"]["query"]
    assert content == (
        "CVE-2024-0001 affects it.\n\nSources:\n"
        "- NVD entry: https://nvd.example/cve\n"
        "- https://blog.example/post: https://blog.example/post"
    )


def test_exa_content_without_citations_returns_the_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        requests,
        "post",
        lambda *_a, **_kw: _FakeResponse({"answer": "  Nothing found.  "}),
    )
    assert tool._exa_content("ek", "q") == "Nothing found."


def test_do_search_reports_the_provider_it_used(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Settings:
        integrations = IntegrationSettings(EXA_API_KEY="ek")

    monkeypatch.setattr(tool, "load_settings", _Settings)
    monkeypatch.setattr(tool, "_exa_content", lambda *_a: "answer")

    result = tool._do_search("OpenSSH 7.4 RCE?")

    assert result == {
        "success": True,
        "query": "OpenSSH 7.4 RCE?",
        "provider": "exa",
        "content": "answer",
    }
