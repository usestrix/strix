"""Tests for query-param handling in strix.tools.proxy.caido_api."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlparse

from strix.tools.proxy.caido_api import apply_modifications


def _components() -> dict[str, Any]:
    return {
        "method": "GET",
        "url_path": "/",
        "headers": {"Host": "victim.com"},
        "body": "",
    }


def _query_pairs(url: str) -> list[tuple[str, str]]:
    return parse_qsl(urlparse(url).query, keep_blank_values=True)


def test_params_add_preserves_blank_valued_param() -> None:
    result = apply_modifications(
        _components(),
        {"params": {"debug": "1"}},
        "http://victim.com/callback?code=abc&state=",
    )
    pairs = _query_pairs(result["url"])
    assert ("state", "") in pairs
    assert ("code", "abc") in pairs
    assert ("debug", "1") in pairs


def test_params_update_keeps_other_params() -> None:
    result = apply_modifications(
        _components(),
        {"params": {"code": "xyz"}},
        "http://victim.com/api?code=abc&state=",
    )
    pairs = _query_pairs(result["url"])
    assert ("code", "xyz") in pairs
    assert ("code", "abc") not in pairs
    assert ("state", "") in pairs


def test_params_preserve_repeated_keys() -> None:
    result = apply_modifications(
        _components(),
        {"params": {"q": "y"}},
        "http://victim.com/search?tag=a&tag=b&q=x",
    )
    pairs = _query_pairs(result["url"])
    assert ("tag", "a") in pairs
    assert ("tag", "b") in pairs
    assert ("q", "y") in pairs
    assert ("q", "x") not in pairs


def test_params_add_new_param() -> None:
    result = apply_modifications(
        _components(),
        {"params": {"new": "1"}},
        "http://victim.com/path?a=1",
    )
    pairs = _query_pairs(result["url"])
    assert ("a", "1") in pairs
    assert ("new", "1") in pairs
