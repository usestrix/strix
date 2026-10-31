"""Classify MCP connection failures without retaining sensitive request data."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Literal, cast

import httpx
from agents.exceptions import UserError
from mcp.shared.exceptions import McpError


FailureKind = Literal[
    "auth", "permission", "rate_limit", "server", "transport", "timeout", "protocol", "unknown"
]

_PRIORITY: dict[FailureKind, int] = {
    "auth": 0,
    "permission": 1,
    "rate_limit": 2,
    "server": 3,
    "protocol": 4,
    "timeout": 5,
    "transport": 6,
    "unknown": 7,
}
_HTTP_ERROR_RE = re.compile(r"\bHTTP error\s+(\d{3})\b", re.IGNORECASE)


@dataclass(frozen=True)
class FailureInfo:
    """A non-sensitive description of one connection failure."""

    kind: FailureKind
    status: int | None = None
    reason: str | None = None
    retry_after: float | None = None
    request_method: str | None = None
    request_path: str | None = None

    @property
    def retryable(self) -> bool:
        return self.kind not in {"auth", "permission"}


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        date = parsedate_to_datetime(value)
        if date.tzinfo is None:
            date = date.replace(tzinfo=UTC)
        return max(0.0, (date - datetime.now(UTC)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


def _from_status(
    status: int,
    reason: str | None = None,
    retry_after: float | None = None,
    *,
    request_method: str | None = None,
    request_path: str | None = None,
) -> FailureInfo:
    if status == 401:
        kind: FailureKind = "auth"
    elif status == 403:
        kind = "permission"
    elif status == 429:
        kind = "rate_limit"
    elif 500 <= status <= 599:
        kind = "server"
    elif 400 <= status <= 499:
        kind = "protocol"
    else:
        kind = "unknown"
    return FailureInfo(
        kind,
        status,
        reason,
        retry_after,
        request_method,
        request_path,
    )


def _direct(exc: BaseException) -> FailureInfo | None:
    if isinstance(exc, httpx.HTTPStatusError):
        response = exc.response
        request = response.request
        return _from_status(
            response.status_code,
            response.reason_phrase,
            _retry_after(response.headers.get("Retry-After")),
            request_method=request.method,
            request_path=request.url.path,
        )
    if isinstance(exc, httpx.TimeoutException):
        return FailureInfo("timeout", reason="request timed out")
    if isinstance(exc, httpx.TransportError):
        return FailureInfo("transport", reason="transport error")
    if isinstance(exc, McpError):
        return FailureInfo("protocol", reason="MCP protocol error")
    if isinstance(exc, UserError):
        match = _HTTP_ERROR_RE.search(str(exc))
        if match:
            return _from_status(int(match.group(1)))
    return None


def classify(exc: BaseException) -> FailureInfo:
    """Return the most specific non-sensitive classification in an exception tree."""
    direct = _direct(exc)
    matches: list[FailureInfo] = [direct] if direct is not None else []
    if isinstance(exc, BaseExceptionGroup):
        group = cast("BaseExceptionGroup[BaseException]", exc)
        matches.extend(classify(child) for child in group.exceptions)
    if matches:
        return min(matches, key=lambda info: _PRIORITY[info.kind])
    return FailureInfo("unknown", reason="unknown failure")


class HttpStatusRecorder:
    """Capture the last non-success response from one HTTP connection."""

    def __init__(self) -> None:
        self._failure: FailureInfo | None = None

    async def __call__(self, response: httpx.Response) -> None:
        if not 200 <= response.status_code < 300:
            request = response.request
            self._failure = _from_status(
                response.status_code,
                response.reason_phrase,
                _retry_after(response.headers.get("Retry-After")),
                request_method=request.method,
                request_path=request.url.path,
            )

    def take(self) -> FailureInfo | None:
        failure, self._failure = self._failure, None
        return failure
