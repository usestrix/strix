"""Tests for the Strix 2 persistent-rate-limit detection + clean-stop wrapping."""

from __future__ import annotations

import httpx
from openai import RateLimitError

from strix.core.execution import _as_rate_limit_error, _is_rate_limit_error


# The 9Router shape: an upstream 429 wrapped in a 503 whose message carries the text.
_NINE_ROUTER_503 = (
    "Error code: 503 - {'error': {'message': \"[claude/claude-sonnet-5] [429]: "
    '{"type":"error","error":{"type":"rate_limit_error","message":"This request would '
    "exceed your account's rate limit. Please try again later.\"}} (reset after 5m)\"}}"
)


class _StatusError(Exception):
    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


# --- _is_rate_limit_error ----------------------------------------------------


def test_detects_ninerouter_wrapped_429_by_text() -> None:
    assert _is_rate_limit_error(Exception(_NINE_ROUTER_503)) is True


def test_detects_by_429_status_code() -> None:
    assert _is_rate_limit_error(_StatusError("slow down", 429)) is True


def test_plain_503_without_rate_text_is_not_rate_limit() -> None:
    assert _is_rate_limit_error(_StatusError("bad gateway", 503)) is False


def test_unrelated_error_is_not_rate_limit() -> None:
    assert _is_rate_limit_error(Exception("connection reset by peer")) is False


# --- _as_rate_limit_error ----------------------------------------------------


def test_wraps_non_ratelimit_into_ratelimit() -> None:
    wrapped = _as_rate_limit_error(Exception(_NINE_ROUTER_503))
    assert isinstance(wrapped, RateLimitError)


def test_passes_through_an_existing_ratelimit_error() -> None:
    request = httpx.Request("POST", "http://localhost/strix")
    original = RateLimitError("rl", response=httpx.Response(429, request=request), body=None)
    assert _as_rate_limit_error(original) is original
