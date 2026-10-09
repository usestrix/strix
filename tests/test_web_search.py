"""Tests for web_search/web_get_contents provider selection and backends."""

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


@pytest.fixture(autouse=True)
def _isolate_search_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "PERPLEXITY_API_KEY",
        "EXA_API_KEY",
        "PARALLEL_API_KEY",
        "STRIX_WEB_SEARCH_PROVIDER",
        "STRIX_EXA_SEARCH_TYPE",
        "STRIX_EXA_NUM_RESULTS",
    ):
        monkeypatch.delenv(key, raising=False)


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
    assert captured["json"]["query"] == "OpenSSH 7.4 RCE?"
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
        ({"STRIX_WEB_SEARCH_PROVIDER": "parallel", "EXA_API_KEY": "ek"}, ["PARALLEL_API_KEY"]),
        ({"STRIX_WEB_SEARCH_PROVIDER": "parallel", "PARALLEL_API_KEY": "key"}, []),
        ({"PARALLEL_API_KEY": "key"}, ["EXA_API_KEY", "PERPLEXITY_API_KEY"]),
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


@pytest.mark.parametrize(
    ("provider", "keys", "expected"),
    [
        ("parallel", {"PARALLEL_API_KEY": "key", "EXA_API_KEY": "ek"}, ("parallel", "key")),
        ("parallel", {"EXA_API_KEY": "ek"}, "PARALLEL_API_KEY"),
        ("auto", {"PARALLEL_API_KEY": "key", "EXA_API_KEY": "ek"}, ("exa", "ek")),
        ("auto", {"PARALLEL_API_KEY": "key", "PERPLEXITY_API_KEY": "pk"}, ("perplexity", "pk")),
        ("auto", {"PARALLEL_API_KEY": "key"}, "EXA_API_KEY or PERPLEXITY_API_KEY"),
    ],
)
def test_parallel_selection_is_opt_in(
    provider: str,
    keys: dict[str, str],
    expected: tuple[str, str] | str,
) -> None:
    integrations = IntegrationSettings.model_validate(
        {"STRIX_WEB_SEARCH_PROVIDER": provider, **keys}
    )
    result = tool._resolve_provider(integrations)
    if isinstance(expected, str):
        assert isinstance(result, dict)
        assert result["success"] is False
        assert expected in result["error"]
    else:
        assert result == expected


@pytest.fixture
def _parallel_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Settings:
        integrations = IntegrationSettings(
            STRIX_WEB_SEARCH_PROVIDER="parallel",
            PARALLEL_API_KEY="test-parallel-secret",
        )

    monkeypatch.setattr(tool, "load_settings", _Settings)


@pytest.mark.usefixtures("_parallel_settings")
def test_parallel_request_and_tool_response(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_post(url: str, **kwargs: Any) -> _FakeResponse:
        captured.update(url=url, **kwargs)
        return _FakeResponse(
            {
                "results": [
                    {
                        "title": "Vendor advisory",
                        "url": "https://vendor.example/advisory",
                        "excerpts": [" Affected versions. ", "Fixed versions."],
                    },
                    {"title": None, "url": "https://vendor.example/docs", "excerpts": []},
                    {"title": "Missing URL"},
                    "malformed entry",
                ]
            }
        )

    monkeypatch.setattr(requests, "post", fake_post)
    query = "Find affected versions and mitigations in the vendor advisory. " * 4
    result = tool._do_search(query)
    assert captured["url"] == "https://api.parallel.ai/v1/search"
    assert captured["headers"] == {
        "x-api-key": "test-parallel-secret",
        "Content-Type": "application/json",
    }
    assert captured["json"] == {
        "objective": query,
        "search_queries": [query[:200]],
        "mode": "fast",
        "max_chars_total": 12000,
        "advanced_settings": {"max_results": 5},
    }
    assert captured["timeout"] == 300
    assert result == {
        "success": True,
        "query": query,
        "provider": "parallel",
        "content": "### Vendor advisory\nhttps://vendor.example/advisory\n\n"
        "Affected versions.\n\nFixed versions.\n\n"
        "### https://vendor.example/docs\nhttps://vendor.example/docs",
    }


@pytest.mark.usefixtures("_parallel_settings")
@pytest.mark.parametrize(
    ("body", "success", "text"),
    [
        ({"results": []}, True, "No web search results found."),
        ({}, False, "unexpected response"),
        ({"results": "invalid"}, False, "unexpected response"),
        ({"results": [{"title": "No URL"}]}, False, "unexpected response"),
    ],
)
def test_parallel_empty_or_malformed_results(
    monkeypatch: pytest.MonkeyPatch,
    body: dict[str, Any],
    success: bool,
    text: str,
) -> None:
    monkeypatch.setattr(requests, "post", lambda *_a, **_kw: _FakeResponse(body))
    result = tool._do_search("vendor advisory")
    assert result["success"] is success
    assert text in result["content" if success else "error"]


def test_parallel_caps_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        requests,
        "post",
        lambda *_a, **_kw: _FakeResponse(
            {
                "results": [{"url": "https://vendor.example", "excerpts": ["x" * 20000]}],
            }
        ),
    )
    result = tool._parallel_content("key", "vendor advisory")
    assert result.startswith("### https://vendor.example\nhttps://vendor.example")
    notice = "\n[excerpts truncated to preserve source links]"
    assert result.endswith(notice)
    assert len(result) == 12000 + len(notice)


@pytest.mark.parametrize("first_excerpt_size", [11920, 20000])
def test_parallel_truncation_keeps_all_source_headers(
    monkeypatch: pytest.MonkeyPatch,
    first_excerpt_size: int,
) -> None:
    results = [
        {
            "title": f"Vendor advisory {index}",
            "url": f"https://vendor.example/advisory/{index}/" + "a" * 100,
            "excerpts": ["x" * (first_excerpt_size if index == 0 else 2000)],
        }
        for index in range(5)
    ]
    monkeypatch.setattr(
        requests,
        "post",
        lambda *_a, **_kw: _FakeResponse({"results": results}),
    )
    content = tool._parallel_content("key", "vendor advisories")
    for result in results:
        assert f"### {result['title']}\n{result['url']}" in content
    notice = "\n[excerpts truncated to preserve source links]"
    assert content.endswith(notice)
    assert len(content) <= 12000 + len(notice)


@pytest.mark.parametrize("spare_chars", [-1, 0, 1, 2, 3])
def test_parallel_keeps_headers_when_no_excerpt_fits(
    monkeypatch: pytest.MonkeyPatch,
    spare_chars: int,
) -> None:
    headers = ["### First\nhttps://first.example", "### Second\nhttps://second.example"]
    header_text = "\n\n".join(headers)
    monkeypatch.setattr(tool, "_PARALLEL_MAX_CHARS", len(header_text) + spare_chars)
    content = tool._parallel_result_content([(header, "excerpt") for header in headers])
    assert all(header in content for header in headers)
    notice = "\n[excerpts truncated to preserve source links]"
    assert content.endswith(notice)
    assert len(content) <= max(len(header_text), tool._PARALLEL_MAX_CHARS) + len(notice)


@pytest.mark.usefixtures("_parallel_settings")
@pytest.mark.parametrize("status", [401, 402, 422, 429, 503])
def test_parallel_http_failures_are_sanitized(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    def fail(*_args: Any, **_kwargs: Any) -> _FakeResponse:
        response = requests.Response()
        response.status_code = status
        raise requests.HTTPError("test-parallel-secret: upstream body", response=response)

    monkeypatch.setattr(requests, "post", fail)
    result = tool._do_search("vendor advisory")
    assert result["success"] is False
    assert "test-parallel-secret" not in result["error"]
    assert "upstream body" not in result["error"]
    assert ("PARALLEL_API_KEY" if status < 500 else "unavailable") in result["error"]


@pytest.mark.usefixtures("_parallel_settings")
@pytest.mark.parametrize(
    ("exception", "message"),
    [(requests.Timeout, "timed out"), (requests.ConnectionError, "network error")],
)
def test_parallel_network_failures(
    monkeypatch: pytest.MonkeyPatch,
    exception: type[requests.RequestException],
    message: str,
) -> None:
    def fail(*_args: Any, **_kwargs: Any) -> _FakeResponse:
        raise exception("upstream error")

    monkeypatch.setattr(requests, "post", fail)
    result = tool._do_search("vendor advisory")
    assert result["success"] is False
    assert message in result["error"]


@pytest.mark.usefixtures("_parallel_settings")
def test_parallel_rejects_oversized_objective_before_http(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_call(*_args: Any, **_kwargs: Any) -> _FakeResponse:
        pytest.fail("Invalid input must not make a request")

    monkeypatch.setattr(requests, "post", unexpected_call)
    result = tool._do_search("x" * 5001)
    assert result["success"] is False
    assert "5000" in result["error"]
