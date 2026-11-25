"""Tell an exhausted LLM provider account apart from every other model failure.

A provider that has run out of quota, credits or billing headroom rejects every
call until a person fixes the account, so retrying burns time and failing the
agent throws away its work. The engine pauses the scan on these instead.

Throttles and account caps share HTTP 429 and much of their wording, so the
verdict rests on evidence a throttle does not carry: HTTP 402, an error code the
provider reserves for the account, or account wording on a 429 or on an error
that arrived without a status (mid-stream). Anything else is left to the retry
policy. The rules follow the classifier in opencode (MIT).
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal, cast


ProviderFailure = Literal["provider_quota"]

_QUOTA_CODES = frozenset(
    {
        "insufficient_quota",
        "insufficient_credits",
        "insufficient_balance",
        "usage_not_included",
        "billing_error",
        "billing_hard_limit_reached",
        "billing_not_active",
        "credit_balance_too_low",
        "creditlimitexceeded",
        "payment_required",
    }
)
# Only consulted on a 429 or a statusless error. Gemini words its per-minute
# throttle as "exceeded your current quota" and Cerebras names its token
# throttle ``token_quota_exceeded``; neither may match.
_QUOTA_TEXT = re.compile(
    r"insufficient[-_\s]?(?:quota|balance|credits?|funds)"
    r"|(?<!token_)quota[-_\s]?exceeded"
    r"|budget exceeded"
    r"|usage limit"
    r"|(?<!rate)(?<!rate[-_\s])limit exhausted"
    r"|out of credits"
    r"|package has expired"
    r"|plan does not yet include",
    re.IGNORECASE,
)
# Anthropic reports an empty balance as a plain HTTP 400 ``invalid_request_error``.
_QUOTA_TEXT_ANY_4XX = re.compile(r"credit balance is too low", re.IGNORECASE)


def _strings(*values: Any) -> list[str]:
    return [value for value in values if isinstance(value, str)]


def _record(value: Any) -> dict[str, Any]:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _body_codes(raw: Any) -> list[str]:
    """Error codes a provider error body carries, wherever the provider puts them."""
    if isinstance(raw, str):
        start = raw.find("{")
        if start < 0:
            return []
        try:
            raw = json.loads(raw[start:])
        except ValueError:
            return []
    body = _record(raw)
    if not body:
        return []
    error = _record(body.get("error"))
    response = _record(body.get("response"))
    details = error.get("details")
    return _strings(
        body.get("code"),
        body.get("type"),
        body.get("error_type"),
        error.get("code"),
        error.get("type"),
        error.get("status"),
        error.get("error_type"),
        # Google ``google.rpc.ErrorInfo`` details carry the specific reason.
        *(_record(detail).get("reason") for detail in details or [] if isinstance(details, list)),
        _record(error.get("innererror")).get("code"),
        _record(error.get("metadata")).get("error_type"),
        _record(response.get("error")).get("code"),
        response.get("error_type"),
    )


def classify_provider_failure(exc: BaseException) -> ProviderFailure | None:
    """Return ``"provider_quota"`` when ``exc`` says the provider account is out of budget."""
    status: int | None = None
    codes: set[str] = set()
    texts: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        found = getattr(current, "status_code", None)
        if status is None and isinstance(found, int):
            status = found
        text = str(current)
        texts.append(text)
        for code in (
            *_strings(getattr(current, "code", None), getattr(current, "type", None)),
            *_body_codes(getattr(current, "body", None)),
            *_body_codes(text),
        ):
            codes.add(code.lower())
        current = current.__cause__ or current.__context__

    if status == 402 or codes & _QUOTA_CODES:
        return "provider_quota"
    text = "\n".join(texts)
    if status in (None, 429) and _QUOTA_TEXT.search(text):
        return "provider_quota"
    if status is not None and 400 <= status < 500 and _QUOTA_TEXT_ANY_4XX.search(text):
        return "provider_quota"
    return None
