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
        "credit_balance_exhausted",
        "organization_spend_limit_exceeded",
        "project_spend_limit_exceeded",
        "organization_usage_limit_exceeded",
        # Anthropic's monthly tier spend cap, sent as a ``rate_limit_error``.
        "enforced_spend_limit_reached",
        # Moonshot sends an empty balance as a 429 with this type.
        "exceeded_current_quota_error",
        # Z.ai balance and plan-limit codes; its throttle (1302) and overload (1305) are not here.
        "1113",
        *(str(code) for code in (1308, 1309, 1310, 1311, *range(1313, 1322))),
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
    r"|\bspend(?:ing)? cap\b"
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


def _parsed(raw: Any) -> dict[str, Any]:
    if isinstance(raw, str):
        start = raw.find("{")
        if start < 0:
            return {}
        try:
            raw = json.loads(raw[start:])
        except ValueError:
            return {}
    return _record(raw)


def _daily_quota(raw: Any) -> bool:
    """Whether a Google error body names a per-day quota, which no wait within the scan restores.

    Gemini sends ``RESOURCE_EXHAUSTED`` with the same message for per-minute and
    per-day limits; only the ``google.rpc.QuotaFailure`` violations tell them apart.
    """
    details = _record(_parsed(raw).get("error")).get("details")
    for detail in details if isinstance(details, list) else []:
        violations = _record(detail).get("violations")
        for violation in violations if isinstance(violations, list) else []:
            quota_id = _record(violation).get("quotaId")
            if isinstance(quota_id, str) and ("PerDay" in quota_id or "Daily" in quota_id):
                return True
    return False


def _body_codes(raw: Any) -> list[str]:
    """Error codes a provider error body carries, wherever the provider puts them."""
    body = _parsed(raw)
    if not body:
        return []
    error = _record(body.get("error"))
    response = _record(body.get("response"))
    details = error.get("details")
    return _strings(
        *(str(code) for code in (body.get("code"), error.get("code")) if isinstance(code, int)),
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
    daily_quota = False
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
        daily_quota = daily_quota or _daily_quota(getattr(current, "body", None))
        daily_quota = daily_quota or _daily_quota(text)
        for code in (
            *_strings(getattr(current, "code", None), getattr(current, "type", None)),
            *_body_codes(getattr(current, "body", None)),
            *_body_codes(text),
        ):
            codes.add(code.lower())
        current = current.__cause__ or current.__context__

    if status == 402 or daily_quota or codes & _QUOTA_CODES:
        return "provider_quota"
    text = "\n".join(texts)
    if status in (None, 429) and _QUOTA_TEXT.search(text):
        return "provider_quota"
    if status is not None and 400 <= status < 500 and _QUOTA_TEXT_ANY_4XX.search(text):
        return "provider_quota"
    return None
