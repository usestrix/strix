"""Agent-baseline parameter classification with deterministic evidence recording."""

from __future__ import annotations

from typing import cast

from strix.core.inventory.models import Endpoint, Param, ParamClassEvidence, ParamClassName


_CLASS_RULES: list[tuple[ParamClassName, set[str]]] = [
    ("object-id", {"id", "user_id", "item_id", "order_id", "account_id", "uuid"}),
    ("url", {"url", "link", "redirect", "callback", "return_url"}),
    ("html", {"content", "body", "message", "description", "comment"}),
    ("file", {"file", "filename", "upload", "attachment"}),
    ("amount", {"amount", "price", "total", "quantity", "balance"}),
    ("role", {"role", "permission", "group", "admin", "scope"}),
    ("state", {"status", "state", "enabled", "active", "visible"}),
]


def classify_param(param: Param) -> ParamClassEvidence:
    """Return a deterministic baseline class hypothesis with recorded evidence."""
    name_lower = param.name.lower()
    for class_name, keywords in _CLASS_RULES:
        if name_lower in keywords or any(name_lower.endswith(f"_{kw}") for kw in keywords):
            return ParamClassEvidence(
                class_name=class_name,
                evidence=f"param name '{param.name}' matches {class_name} keyword set",
            )

    if param.location == "path":
        return ParamClassEvidence(
            class_name="object-id",
            evidence=f"param '{param.name}' is in path, treated as object-id by default",
        )

    return ParamClassEvidence(
        class_name="unknown",
        evidence=f"param '{param.name}' matched no rule",
    )


def classify_endpoint(endpoint: Endpoint) -> Endpoint:
    """Attach baseline class evidence to every parameter on the endpoint."""
    for param in endpoint.params.values():
        if param.class_evidence is None:
            param.class_evidence = classify_param(param)
    return endpoint


def agent_classify_param(
    param: Param,
    class_name: str,
    evidence: str,
) -> Param:
    """Agent override: record a proposed class with explicit evidence."""
    param.class_evidence = ParamClassEvidence(
        class_name=cast("ParamClassName", class_name),
        evidence=evidence,
    )
    return param
