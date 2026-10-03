"""Load a Bugcrowd program into a :class:`BountyProgram`.

:func:`parse_program` accepts two shapes: a simplified ``{"program": {...},
"targets": [...]}`` object (what this tool exports and what the fixtures use) and a
JSON:API ``{"data": [{"type": "target", "attributes": {...}}]}`` list, which is
closer to Bugcrowd's live API. The parser is defensive so a minor shape difference
degrades gracefully instead of crashing. :func:`fetch_program` performs the
authenticated call; its exact endpoint/field mapping should be confirmed against a
live response the first time a real Bugcrowd token is available.
"""

from __future__ import annotations

from typing import Any

from strix.bounty.loaders.errors import BountyLoadError
from strix.bounty.schema import AssetType, BountyProgram, ScopeAsset


BUGCROWD_API_BASE = "https://api.bugcrowd.com"

# Bugcrowd target category -> our AssetType.
_BC_CATEGORY: dict[str, AssetType] = {
    "website": "url",
    "api": "api",
    "android": "android",
    "ios": "ios",
    "source": "source",
    "executable": "executable",
    "hardware": "other",
    "other": "other",
}


def _target_to_asset(name: str, category: str, *, eligible: bool) -> ScopeAsset:
    asset_type = _BC_CATEGORY.get(category.lower(), "other")
    if asset_type == "url" and "*" in name:
        asset_type = "wildcard"
    return ScopeAsset(identifier=name.strip(), asset_type=asset_type, eligible_for_bounty=eligible)


def _iter_targets(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize either supported shape into a flat list of target dicts."""
    if isinstance(payload.get("targets"), list):
        return [t for t in payload["targets"] if isinstance(t, dict)]
    out: list[dict[str, Any]] = []
    for item in payload.get("data") or []:
        if not isinstance(item, dict):
            continue
        attrs = item.get("attributes") or {}
        in_scope = attrs.get("in_scope", True)
        out.append(
            {
                "name": attrs.get("name") or attrs.get("uri"),
                "category": attrs.get("category") or "other",
                "in_scope": in_scope,
                "eligible_for_bounty": attrs.get("eligible_for_bounty", in_scope),
            }
        )
    return out


def parse_program(payload: dict[str, Any]) -> BountyProgram:
    """Parse a Bugcrowd program/targets payload into a :class:`BountyProgram`."""
    program = payload.get("program") or {}
    code = (program.get("code") or payload.get("code") or "").strip()
    if not code:
        raise BountyLoadError("Bugcrowd payload has no program code")

    in_scope: list[ScopeAsset] = []
    out_of_scope: list[ScopeAsset] = []
    for target in _iter_targets(payload):
        name = target.get("name")
        if not name:
            continue
        in_scope_flag = bool(target.get("in_scope", True))
        asset = _target_to_asset(
            str(name),
            str(target.get("category") or "other"),
            eligible=bool(target.get("eligible_for_bounty", in_scope_flag)),
        )
        (in_scope if in_scope_flag else out_of_scope).append(asset)

    return BountyProgram(
        platform="bugcrowd",
        handle=code,
        name=program.get("name") or None,
        url=f"https://bugcrowd.com/{code}",
        managed_by="Bugcrowd",
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    )


def fetch_program(code: str, *, api_token: str, timeout: float = 30.0) -> BountyProgram:
    """Fetch a program live from the Bugcrowd API (token auth).

    Network/auth failures raise :class:`BountyLoadError`.
    """
    import httpx

    url = f"{BUGCROWD_API_BASE}/programs/{code}/targets"
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(
                url,
                headers={
                    "Authorization": f"Token {api_token}",
                    "Accept": "application/vnd.bugcrowd+json",
                },
            )
            resp.raise_for_status()
            payload = resp.json()
    except httpx.HTTPError as exc:
        raise BountyLoadError(f"Bugcrowd API request for {code!r} failed: {exc}") from exc
    if "program" not in payload and "code" not in payload:
        payload = {"program": {"code": code}, **payload}
    return parse_program(payload)
