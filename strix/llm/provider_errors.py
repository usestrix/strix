"""Tell an exhausted LLM provider account apart from every other model failure.

A provider that has run out of quota, credits or billing headroom rejects every
call until a person fixes the account, so retrying burns time and failing the
agent throws away its work. The engine pauses the scan on these instead.
"""

from __future__ import annotations

import re
from typing import Any, Literal, cast


ProviderFailure = Literal["provider_quota"]

_QUOTA_CODES = frozenset(
    {
        "insufficient_quota",
        "insufficient_credits",
        "insufficient_balance",
        "billing_hard_limit_reached",
        "billing_not_active",
        "account_deactivated",
        "credit_balance_too_low",
        "payment_required",
    }
)
_QUOTA_TEXT = re.compile(
    r"exceeded your current quota"
    r"|insufficient[_ ](?:quota|credits?|balance|funds)"
    r"|credit balance is too low"
    r"|billing[_ ]hard[_ ]limit"
    r"|billing (?:is )?not active"
    r"|(?:spend(?:ing)?|usage|budget) limit (?:has been )?(?:reached|exceeded)"
    r"|exceeded (?:your|the) (?:monthly |daily )?(?:spend(?:ing)?|usage|budget) limit"
    r"|out of credits"
    r"|payment required",
    re.IGNORECASE,
)


def _error_fields(exc: BaseException) -> tuple[str, ...]:
    fields: list[str] = []
    for name in ("code", "type"):
        value = getattr(exc, name, None)
        if isinstance(value, str):
            fields.append(value)
    raw: Any = getattr(exc, "body", None)
    if isinstance(raw, dict):
        body = cast("dict[str, Any]", raw)
        error = body.get("error")
        inner = cast("dict[str, Any]", error) if isinstance(error, dict) else body
        for name in ("code", "type"):
            value = inner.get(name)
            if isinstance(value, str):
                fields.append(value)
    return tuple(field.lower() for field in fields)


def classify_provider_failure(exc: BaseException) -> ProviderFailure | None:
    """Return ``"provider_quota"`` when ``exc`` says the provider account is out of budget."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if getattr(current, "status_code", None) == 402:
            return "provider_quota"
        if any(field in _QUOTA_CODES for field in _error_fields(current)):
            return "provider_quota"
        if _QUOTA_TEXT.search(str(current)):
            return "provider_quota"
        current = current.__cause__ or current.__context__
    return None
