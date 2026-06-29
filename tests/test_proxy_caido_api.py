"""Tests for raw-request building in the Caido proxy helper."""

from __future__ import annotations

from strix.tools.proxy.caido_api import apply_modifications, build_raw_request


def _content_length(raw: bytes) -> str | None:
    for line in raw.decode("utf-8").split("\r\n"):
        if line.lower().startswith("content-length:"):
            return line.split(":", 1)[1].strip()
    return None


def test_body_replacement_recomputes_content_length() -> None:
    components = {
        "method": "POST",
        "headers": {"Host": "x.test", "Content-Length": "3"},
        "body": "old",
    }
    new_body = "this is the new and much longer body!"
    result = apply_modifications(components, {"body": new_body}, "http://x.test/submit")
    _conn, raw = build_raw_request(
        method=result["method"],
        url=result["url"],
        headers=result["headers"],
        body=result["body"],
    )
    assert _content_length(raw) == str(len(new_body.encode("utf-8")))


def test_explicit_content_length_override_is_preserved() -> None:
    components = {
        "method": "POST",
        "headers": {"Host": "x.test", "Content-Length": "3"},
        "body": "old",
    }
    result = apply_modifications(
        components,
        {"body": "new body", "headers": {"Content-Length": "999"}},
        "http://x.test/",
    )
    _conn, raw = build_raw_request(
        method=result["method"],
        url=result["url"],
        headers=result["headers"],
        body=result["body"],
    )
    assert _content_length(raw) == "999"


def test_no_body_modification_keeps_content_length() -> None:
    components = {
        "method": "POST",
        "headers": {"Host": "x.test", "Content-Length": "3"},
        "body": "old",
    }
    result = apply_modifications(components, {"headers": {"X-Test": "1"}}, "http://x.test/")
    assert result["headers"].get("Content-Length") == "3"
