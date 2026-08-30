"""Tests for strix.tools.web_search: Perplexity + DuckDuckGo opt-in backend."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests as _requests
from agents.tool import FunctionTool

from strix.tools.web_search import tool


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_DDG_RESULTS = [
    {
        "title": "CVE-2024-1234",
        "body": "Critical RCE in Example 1.0",
        "href": "https://example.com/1",
    },
    {
        "title": "Example Exploit",
        "body": "PoC for Example 1.0 RCE",
        "href": "https://example.com/2",
    },
]


def _perplexity_response(content: str = "Perplexity answer") -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"choices": [{"message": {"content": content}}]}
    resp.raise_for_status = MagicMock()
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _mock_settings(
    *,
    perplexity_api_key: str | None = None,
    web_search_backend: str | None = None,
) -> MagicMock:
    settings = MagicMock()
    settings.integrations.perplexity_api_key = perplexity_api_key
    settings.integrations.web_search_backend = web_search_backend
    return settings


# --------------------------------------------------------------------------- #
# _do_search — orchestration
# --------------------------------------------------------------------------- #


class TestDoSearch:
    def test_empty_query_returns_error(self) -> None:
        result = tool._do_search("")
        assert result["success"] is False
        assert "empty" in result["error"].lower()

    def test_whitespace_only_query_returns_error(self) -> None:
        result = tool._do_search("   ")
        assert result["success"] is False
        assert "empty" in result["error"].lower()

    @patch.object(tool, "load_settings")
    def test_default_no_key_returns_error(self, mock_settings: MagicMock) -> None:
        mock_settings.return_value = _mock_settings(
            perplexity_api_key=None,
            web_search_backend=None,
        )
        result = tool._do_search("test query")

        assert result["success"] is False
        assert "PERPLEXITY_API_KEY" in result["error"]

    @patch.object(tool, "load_settings")
    def test_default_with_key_uses_perplexity(self, mock_settings: MagicMock) -> None:
        mock_settings.return_value = _mock_settings(
            perplexity_api_key="pplx-test",
            web_search_backend=None,
        )
        with patch.object(tool, "_perplexity_search") as mock_pplx:
            mock_pplx.return_value = {"success": True, "provider": "perplexity"}
            result = tool._do_search("test query")

        mock_pplx.assert_called_once_with("test query")
        assert result["provider"] == "perplexity"

    @patch.object(tool, "load_settings")
    def test_backend_perplexity_uses_perplexity(self, mock_settings: MagicMock) -> None:
        mock_settings.return_value = _mock_settings(
            perplexity_api_key="pplx-test",
            web_search_backend="perplexity",
        )
        with patch.object(tool, "_perplexity_search") as mock_pplx:
            mock_pplx.return_value = {"success": True, "provider": "perplexity"}
            result = tool._do_search("test query")

        mock_pplx.assert_called_once_with("test query")
        assert result["provider"] == "perplexity"

    @patch.object(tool, "load_settings")
    def test_backend_perplexity_no_key_returns_error(self, mock_settings: MagicMock) -> None:
        mock_settings.return_value = _mock_settings(
            perplexity_api_key=None,
            web_search_backend="perplexity",
        )
        result = tool._do_search("test query")

        assert result["success"] is False
        assert "PERPLEXITY_API_KEY" in result["error"]

    @patch.object(tool, "load_settings")
    def test_backend_duckduckgo_uses_ddg(self, mock_settings: MagicMock) -> None:
        mock_settings.return_value = _mock_settings(
            web_search_backend="duckduckgo",
        )
        with patch.object(tool, "_ddg_search") as mock_ddg:
            mock_ddg.return_value = {"success": True, "provider": "duckduckgo"}
            result = tool._do_search("test query")

        mock_ddg.assert_called_once_with("test query")
        assert result["provider"] == "duckduckgo"

    @patch.object(tool, "load_settings")
    def test_backend_duckduckgo_ignores_perplexity_key(self, mock_settings: MagicMock) -> None:
        mock_settings.return_value = _mock_settings(
            perplexity_api_key="pplx-test",
            web_search_backend="duckduckgo",
        )
        with (
            patch.object(tool, "_perplexity_search") as mock_pplx,
            patch.object(tool, "_ddg_search") as mock_ddg,
        ):
            mock_ddg.return_value = {"success": True, "provider": "duckduckgo"}
            tool._do_search("test query")

        mock_pplx.assert_not_called()
        mock_ddg.assert_called_once_with("test query")

    @patch.object(tool, "load_settings")
    def test_unknown_backend_returns_error(self, mock_settings: MagicMock) -> None:
        mock_settings.return_value = _mock_settings(
            web_search_backend="firecrawl",
        )
        result = tool._do_search("test query")

        assert result["success"] is False
        assert "Unknown STRIX_WEB_SEARCH_BACKEND" in result["error"]
        assert "firecrawl" in result["error"]


# --------------------------------------------------------------------------- #
# _perplexity_search
# --------------------------------------------------------------------------- #


class TestPerplexitySearch:
    def test_no_api_key_returns_error(self) -> None:
        with patch.object(tool, "load_settings") as mock_settings:
            mock_settings.return_value = _mock_settings()
            result = tool._perplexity_search("query")

        assert result["success"] is False
        assert "PERPLEXITY_API_KEY" in result["error"]

    @patch.object(tool, "load_settings")
    @patch("requests.post")
    def test_success(self, mock_post: MagicMock, mock_settings: MagicMock) -> None:
        mock_settings.return_value = _mock_settings(perplexity_api_key="pplx-test")
        mock_post.return_value = _perplexity_response("Pplx answer")

        result = tool._perplexity_search("test CVE query")

        assert result["success"] is True
        assert result["content"] == "Pplx answer"
        assert result["provider"] == "perplexity"

    @patch.object(tool, "load_settings")
    @patch("requests.post")
    def test_timeout_returns_error(self, mock_post: MagicMock, mock_settings: MagicMock) -> None:
        mock_settings.return_value = _mock_settings(perplexity_api_key="pplx-test")
        mock_post.side_effect = _requests.exceptions.Timeout("timed out")

        result = tool._perplexity_search("query")

        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    @patch.object(tool, "load_settings")
    @patch("requests.post")
    def test_http_4xx_returns_rejection(
        self, mock_post: MagicMock, mock_settings: MagicMock
    ) -> None:
        mock_settings.return_value = _mock_settings(perplexity_api_key="pplx-test")
        resp = MagicMock()
        resp.status_code = 400
        mock_post.side_effect = _requests.exceptions.HTTPError(response=resp)

        result = tool._perplexity_search("query")

        assert result["success"] is False
        assert "rejected" in result["error"].lower()

    @patch.object(tool, "load_settings")
    @patch("requests.post")
    def test_http_5xx_returns_unavailable(
        self, mock_post: MagicMock, mock_settings: MagicMock
    ) -> None:
        mock_settings.return_value = _mock_settings(perplexity_api_key="pplx-test")
        resp = MagicMock()
        resp.status_code = 503
        mock_post.side_effect = _requests.exceptions.HTTPError(response=resp)

        result = tool._perplexity_search("query")

        assert result["success"] is False
        assert "unavailable" in result["error"].lower()

    @patch.object(tool, "load_settings")
    @patch("requests.post")
    def test_unexpected_response_shape(
        self, mock_post: MagicMock, mock_settings: MagicMock
    ) -> None:
        mock_settings.return_value = _mock_settings(perplexity_api_key="pplx-test")
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {"unexpected": "shape"}
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        mock_post.return_value = resp

        result = tool._perplexity_search("query")

        assert result["success"] is False
        assert "unexpected" in result["error"].lower()


# --------------------------------------------------------------------------- #
# _ddg_search
# --------------------------------------------------------------------------- #


class TestDDGSearch:
    @patch("ddgs.DDGS")
    def test_success(self, mock_ddgs_cls: MagicMock) -> None:
        mock_ddgs_cls.return_value.text.return_value = _DDG_RESULTS

        result = tool._ddg_search("CVE-2024-1234 Example RCE")

        assert result["success"] is True
        assert result["provider"] == "duckduckgo"
        assert "CVE-2024-1234" in result["content"]
        assert "https://example.com/1" in result["content"]

    @patch("ddgs.DDGS")
    def test_empty_results(self, mock_ddgs_cls: MagicMock) -> None:
        mock_ddgs_cls.return_value.text.return_value = []

        result = tool._ddg_search("nonexistent gibberish xyz123")

        assert result["success"] is False
        assert "no results" in result["error"].lower()

    @patch("ddgs.DDGS")
    def test_ddg_exception_returns_error(self, mock_ddgs_cls: MagicMock) -> None:
        mock_ddgs_cls.return_value.text.side_effect = Exception("rate limited")

        result = tool._ddg_search("query")

        assert result["success"] is False
        assert "failed" in result["error"].lower()

    @patch.dict("sys.modules", {"ddgs": None})
    def test_import_error_returns_error(self) -> None:
        result = tool._ddg_search("query")

        assert result["success"] is False
        assert "not installed" in result["error"].lower()


# --------------------------------------------------------------------------- #
# web_search (async tool entry point)
# --------------------------------------------------------------------------- #


class TestWebSearchTool:
    def test_tool_is_registered(self) -> None:
        assert isinstance(tool.web_search, FunctionTool)
        assert tool.web_search.name == "web_search"
        assert "web search" in tool.web_search.description.lower()
