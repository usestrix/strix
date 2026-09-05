"""Tests for web_search/web_get_contents provider selection and the Exa backend."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
import requests

from strix.config.settings import IntegrationSettings
from strix.interface.environment import _missing_web_search_vars
from strix.tools.web_search import tool


if TYPE_CHECKING:
    from typing import Self


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


def test_exa_content_requests_summaries_and_renders_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_post(url: str, **kwargs: Any) -> _FakeResponse:
        captured["url"] = url
        captured["headers"] = kwargs["headers"]
        captured["json"] = kwargs["json"]
        return _FakeResponse(
            {
                "results": [
                    {
                        "url": "https://nvd.example/cve",
                        "title": "NVD entry",
                        "summary": "  CVE-2024-0001 is a heap overflow.  ",
                    },
                    {"id": "https://blog.example/post"},
                    "not-a-dict",
                    {"title": "no url"},
                ],
            }
        )

    monkeypatch.setattr(requests, "post", fake_post)

    content = tool._exa_content("ek", "OpenSSH 7.4 RCE?", "auto", 5)

    assert captured["url"] == "https://api.exa.ai/search"
    assert captured["headers"]["x-api-key"] == "ek"
    assert "OpenSSH 7.4 RCE?" in captured["json"]["query"]
    assert captured["json"]["type"] == "auto"
    assert captured["json"]["numResults"] == 5
    assert captured["json"]["contents"] == {"summary": {"query": tool._EXA_SUMMARY_PROMPT}}
    assert content == (
        "### NVD entry\nhttps://nvd.example/cve\nCVE-2024-0001 is a heap overflow.\n\n"
        "### https://blog.example/post\nhttps://blog.example/post"
    )


def test_exa_content_renders_a_result_without_contents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        requests,
        "post",
        lambda *_a, **_kw: _FakeResponse(
            {"results": [{"url": "https://ex.example", "title": "Ex"}]}
        ),
    )
    assert tool._exa_content("ek", "q", "auto", 5) == "### Ex\nhttps://ex.example"


@pytest.mark.parametrize("body", [{}, {"results": None}, {"results": []}, {"results": ["x"]}])
def test_exa_content_rejects_empty_results(
    monkeypatch: pytest.MonkeyPatch, body: dict[str, Any]
) -> None:
    monkeypatch.setattr(requests, "post", lambda *_a, **_kw: _FakeResponse(body))
    with pytest.raises(ValueError, match="no results"):
        tool._exa_content("ek", "q", "auto", 5)


def test_do_search_reports_empty_exa_results_as_unexpected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Settings:
        integrations = IntegrationSettings(EXA_API_KEY="ek")

    monkeypatch.setattr(tool, "load_settings", _Settings)
    monkeypatch.setattr(requests, "post", lambda *_a, **_kw: _FakeResponse({}))

    result = tool._do_search("q")

    assert result["success"] is False
    assert "unexpected response" in result["error"]


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({}, ["EXA_API_KEY", "PERPLEXITY_API_KEY"]),
        ({"EXA_API_KEY": "ek"}, []),
        ({"PERPLEXITY_API_KEY": "pk"}, []),
        ({"STRIX_WEB_SEARCH_PROVIDER": "exa", "PERPLEXITY_API_KEY": "pk"}, ["EXA_API_KEY"]),
        ({"STRIX_WEB_SEARCH_PROVIDER": "exa", "EXA_API_KEY": "ek"}, []),
        ({"STRIX_WEB_SEARCH_PROVIDER": "perplexity", "EXA_API_KEY": "ek"}, ["PERPLEXITY_API_KEY"]),
        ({"STRIX_WEB_SEARCH_PROVIDER": "perplexity", "PERPLEXITY_API_KEY": "pk"}, []),
    ],
)
def test_environment_validation_follows_provider_rules(
    env: dict[str, str], expected: list[str]
) -> None:
    integrations = IntegrationSettings.model_validate(env)
    assert _missing_web_search_vars(integrations) == expected


def test_exa_search_type_and_num_results_are_configurable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class _Settings:
        integrations = IntegrationSettings(
            EXA_API_KEY="ek",
            STRIX_EXA_SEARCH_TYPE="deep-reasoning",
            STRIX_EXA_NUM_RESULTS=3,
        )

    def fake_post(_url: str, **kwargs: Any) -> _FakeResponse:
        captured["json"] = kwargs["json"]
        return _FakeResponse({"results": [{"url": "https://ex.example", "title": "Ex"}]})

    monkeypatch.setattr(tool, "load_settings", _Settings)
    monkeypatch.setattr(requests, "post", fake_post)

    assert tool._do_search("q")["success"] is True
    assert captured["json"]["type"] == "deep-reasoning"
    assert captured["json"]["numResults"] == 3


def test_exa_page_text_requests_full_text_and_renders_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_post(url: str, **kwargs: Any) -> _FakeResponse:
        captured["url"] = url
        captured["headers"] = kwargs["headers"]
        captured["json"] = kwargs["json"]
        return _FakeResponse(
            {
                "results": [
                    {
                        "url": "https://nvd.example/cve",
                        "title": "NVD entry",
                        "text": "  Full advisory body.  ",
                    },
                    {"url": "https://empty.example", "text": "   "},
                    "not-a-dict",
                    {"text": "no url"},
                ],
            }
        )

    monkeypatch.setattr(requests, "post", fake_post)

    content, fetched = tool._exa_page_text("ek", ["https://nvd.example/cve"])

    assert captured["url"] == "https://api.exa.ai/contents"
    assert captured["headers"]["x-api-key"] == "ek"
    assert captured["json"] == {"urls": ["https://nvd.example/cve"], "text": True}
    assert content == "### NVD entry\nhttps://nvd.example/cve\n\nFull advisory body."
    assert fetched == {"https://nvd.example/cve"}


def test_exa_page_text_truncates_a_long_page(monkeypatch: pytest.MonkeyPatch) -> None:
    body = "A" * (tool._EXA_PAGE_MAX_CHARS + 500)
    monkeypatch.setattr(
        requests,
        "post",
        lambda *_a, **_kw: _FakeResponse(
            {"results": [{"url": "https://ex.example", "text": body}]}
        ),
    )
    content, _fetched = tool._exa_page_text("ek", ["https://ex.example"])
    assert "truncated at" in content
    assert content.count("A") == tool._EXA_PAGE_MAX_CHARS


@pytest.mark.parametrize("body", [{}, {"results": []}, {"results": [{"url": "u"}]}])
def test_exa_page_text_rejects_pages_without_text(
    monkeypatch: pytest.MonkeyPatch, body: dict[str, Any]
) -> None:
    monkeypatch.setattr(requests, "post", lambda *_a, **_kw: _FakeResponse(body))
    with pytest.raises(ValueError, match="no page contents"):
        tool._exa_page_text("ek", ["https://ex.example"])


@pytest.mark.parametrize("urls", [[], ["", "   "]])
def test_do_get_contents_requires_a_url(urls: list[str]) -> None:
    result = tool._do_get_contents(urls)
    assert result["success"] is False
    assert "at least one URL" in result["error"]


def test_do_get_contents_caps_the_url_count() -> None:
    urls = [f"https://ex{index}.example" for index in range(tool._EXA_MAX_CONTENT_URLS + 1)]
    result = tool._do_get_contents(urls)
    assert result["success"] is False
    assert "Too many URLs" in result["error"]


def test_do_get_contents_needs_an_exa_key(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Settings:
        integrations = IntegrationSettings(PERPLEXITY_API_KEY="pk")

    monkeypatch.setattr(tool, "load_settings", _Settings)

    result = tool._do_get_contents(["https://ex.example"])

    assert result["success"] is False
    assert "EXA_API_KEY" in result["error"]


def test_do_get_contents_refuses_a_perplexity_pinned_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Settings:
        integrations = IntegrationSettings(
            EXA_API_KEY="ek",
            PERPLEXITY_API_KEY="pk",
            STRIX_WEB_SEARCH_PROVIDER="perplexity",
        )

    monkeypatch.setattr(tool, "load_settings", _Settings)

    result = tool._do_get_contents(["https://ex.example"])

    assert result["success"] is False
    assert "web_search" in result["error"]


def test_do_get_contents_returns_page_text(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Settings:
        integrations = IntegrationSettings(EXA_API_KEY="ek")

    monkeypatch.setattr(tool, "load_settings", _Settings)
    monkeypatch.setattr(tool, "_exa_page_text", lambda *_a: ("page", {"https://ex.example"}))

    result = tool._do_get_contents([" https://ex.example "])

    assert result == {
        "success": True,
        "urls": ["https://ex.example"],
        "provider": "exa",
        "content": "page",
    }


def test_do_get_contents_reports_urls_exa_did_not_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Settings:
        integrations = IntegrationSettings(EXA_API_KEY="ek")

    monkeypatch.setattr(tool, "load_settings", _Settings)
    monkeypatch.setattr(
        requests,
        "post",
        lambda *_a, **_kw: _FakeResponse(
            {"results": [{"url": "https://ok.example/", "text": "Body."}]}
        ),
    )

    result = tool._do_get_contents(["https://ok.example", "https://blocked.example"])

    assert result["success"] is True
    assert result["urls"] == ["https://ok.example"]
    assert result["failed_urls"] == ["https://blocked.example"]
    assert "1 of 2" in result["warning"]
    assert "blocked.example" not in result["content"]


def test_normalize_url_folds_only_scheme_and_host() -> None:
    assert tool._normalize_url("HTTPS://Ex.Example/Path/") == tool._normalize_url(
        "https://ex.example/Path"
    )
    assert tool._normalize_url("https://ex.example/Path") != tool._normalize_url(
        "https://ex.example/path"
    )
    assert tool._normalize_url("https://ex.example/p?Q=A") != tool._normalize_url(
        "https://ex.example/p?q=a"
    )


def test_do_get_contents_omits_the_warning_when_every_page_returns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Settings:
        integrations = IntegrationSettings(EXA_API_KEY="ek")

    monkeypatch.setattr(tool, "load_settings", _Settings)
    monkeypatch.setattr(
        requests,
        "post",
        lambda *_a, **_kw: _FakeResponse(
            {
                "results": [
                    {"url": "https://a.example", "text": "A."},
                    {"url": "https://b.example", "text": "B."},
                ]
            }
        ),
    )

    result = tool._do_get_contents(["https://a.example", "https://b.example"])

    assert result["urls"] == ["https://a.example", "https://b.example"]
    assert "failed_urls" not in result
    assert "warning" not in result


def test_do_get_contents_sanitizes_a_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Settings:
        integrations = IntegrationSettings(EXA_API_KEY="ek")

    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise requests.exceptions.ConnectionError

    monkeypatch.setattr(tool, "load_settings", _Settings)
    monkeypatch.setattr(requests, "post", boom)

    result = tool._do_get_contents(["https://ex.example"])

    assert result["success"] is False
    assert "network error" in result["error"]
    assert "ek" not in result["error"]


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
