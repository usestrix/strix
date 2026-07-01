"""Tests for request modification in the Caido proxy integration."""

from __future__ import annotations

from strix.tools.proxy.caido_api import apply_modifications, build_raw_request


def _components(body: str = "old", headers: dict[str, str] | None = None) -> dict:
    return {
        "method": "POST",
        "url_path": "/submit",
        "headers": headers or {"Content-Length": str(len(body))},
        "body": body,
    }


def test_apply_modifications_drops_stale_content_length_on_body_replace() -> None:
    components = _components(body="old")
    result = apply_modifications(
        components,
        {"body": "a much longer replacement body than the original"},
        "http://example.com/submit",
    )
    assert "Content-Length" not in {k.title() for k in result["headers"]}


def test_apply_modifications_keeps_explicit_content_length_on_body_replace() -> None:
    components = _components(body="old")
    result = apply_modifications(
        components,
        {"body": "new-body", "headers": {"Content-Length": "8"}},
        "http://example.com/submit",
    )
    assert result["headers"]["Content-Length"] == "8"


def test_apply_modifications_without_body_change_keeps_headers() -> None:
    components = _components(body="old")
    result = apply_modifications(
        components,
        {"headers": {"X-Test": "1"}},
        "http://example.com/submit",
    )
    assert result["headers"]["Content-Length"] == "3"


def test_build_raw_request_recomputes_content_length_after_replacement() -> None:
    components = _components(body="old")
    new_body = "a much longer replacement body than the original"
    modified = apply_modifications(
        components,
        {"body": new_body},
        "http://example.com/submit",
    )
    _, raw = build_raw_request(
        method=modified["method"],
        url=modified["url"],
        headers=modified["headers"],
        body=modified["body"],
    )
    head = raw.decode("utf-8").split("\r\n\r\n", 1)[0]
    assert f"Content-Length: {len(new_body.encode('utf-8'))}" in head


def test_build_raw_request_sets_content_length_zero_for_empty_body() -> None:
    components = _components(body="old")
    modified = apply_modifications(
        components,
        {"body": ""},
        "http://example.com/submit",
    )
    _, raw = build_raw_request(
        method=modified["method"],
        url=modified["url"],
        headers=modified["headers"],
        body=modified["body"],
    )
    head = raw.decode("utf-8").split("\r\n\r\n", 1)[0]
    assert "Content-Length: 0" in head
