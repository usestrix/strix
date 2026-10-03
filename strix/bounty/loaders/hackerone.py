"""Load a HackerOne program into a :class:`BountyProgram`.

:func:`parse_program` turns a HackerOne Hacker-API program response (the JSON:API
``/hackers/programs/{handle}`` shape, with inline ``structured_scopes``) into the
platform-neutral model; it is pure and fully tested against a fixture.
:func:`fetch_program` performs the authenticated HTTP call and hands the JSON to the
parser — its field mapping follows HackerOne's documented API and should be
confirmed against a live response the first time a real token is available.

HackerOne does not expose a machine-readable "automated testing allowed" flag or a
numeric rate limit; those live in the free-text policy, which is preserved in
``roe.notes``. Encode them as real ROE constraints with a companion file via
:func:`strix.bounty.loaders.apply_roe_overrides`.
"""

from __future__ import annotations

from typing import Any

from strix.bounty.loaders.errors import BountyLoadError
from strix.bounty.schema import AssetType, BountyProgram, RulesOfEngagement, ScopeAsset


H1_API_BASE = "https://api.hackerone.com/v1"

# HackerOne structured-scope asset_type -> our AssetType.
_H1_ASSET_TYPE: dict[str, AssetType] = {
    "URL": "url",
    "WILDCARD": "wildcard",
    "CIDR": "cidr",
    "IP_ADDRESS": "ip",
    "GOOGLE_PLAY_APP_ID": "android",
    "OTHER_APK": "android",
    "APPLE_STORE_APP_ID": "ios",
    "TESTFLIGHT": "ios",
    "SOURCE_CODE": "source",
    "DOWNLOADABLE_EXECUTABLES": "executable",
}


def _asset_from_scope(attrs: dict[str, Any]) -> ScopeAsset | None:
    identifier = (attrs.get("asset_identifier") or "").strip()
    if not identifier:
        return None
    asset_type = _H1_ASSET_TYPE.get(str(attrs.get("asset_type", "")).upper(), "other")
    return ScopeAsset(
        identifier=identifier,
        asset_type=asset_type,
        eligible_for_bounty=bool(attrs.get("eligible_for_bounty", False)),
        instruction=attrs.get("instruction") or None,
    )


def parse_program(payload: dict[str, Any]) -> BountyProgram:
    """Parse a HackerOne program API payload into a :class:`BountyProgram`.

    Accepts both the single-program Hacker-API shape (the program object at the top
    level: ``{id, type, attributes, relationships}``) and a ``{"data": {...}}``
    wrapper (the collection/JSON:API style used by saved exports and fixtures).
    """
    data = payload.get("data")
    if not isinstance(data, dict):
        data = payload
    attrs = data.get("attributes") or {}
    handle = (attrs.get("handle") or "").strip()
    if not handle:
        raise BountyLoadError("HackerOne payload has no program handle")

    scopes = (
        ((data.get("relationships") or {}).get("structured_scopes") or {}).get("data")
    ) or []

    in_scope: list[ScopeAsset] = []
    out_of_scope: list[ScopeAsset] = []
    for item in scopes:
        asset = _asset_from_scope(item.get("attributes") or {})
        if asset is None:
            continue
        # eligible_for_submission defaults True when absent (an in-scope entry).
        if (item.get("attributes") or {}).get("eligible_for_submission", True):
            in_scope.append(asset)
        else:
            out_of_scope.append(asset)

    return BountyProgram(
        platform="hackerone",
        handle=handle,
        name=attrs.get("name") or None,
        url=f"https://hackerone.com/{handle}",
        managed_by="HackerOne",
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        roe=RulesOfEngagement(notes=attrs.get("policy") or None),
    )


_MAX_SCOPE_PAGES = 50


def fetch_program(
    handle: str,
    *,
    api_username: str,
    api_token: str,
    timeout: float = 30.0,
) -> BountyProgram:
    """Fetch a program live from the HackerOne Hacker API (HTTP Basic auth).

    Two calls: the program object (handle / name / policy) and its full, paginated
    ``structured_scopes`` list — the inline relationship on the program object can be
    truncated, so the dedicated endpoint is the authoritative scope source. The two
    are merged into one payload and handed to :func:`parse_program`. Requires a
    HackerOne API identifier (``api_username``) and token; failures raise
    :class:`BountyLoadError`.
    """
    import httpx

    auth = (api_username, api_token)
    headers = {"Accept": "application/json"}
    base = f"{H1_API_BASE}/hackers/programs/{handle}"
    try:
        with httpx.Client(timeout=timeout, auth=auth, headers=headers) as client:
            resp = client.get(base)
            resp.raise_for_status()
            program_obj = resp.json()

            scopes: list[dict[str, Any]] = []
            url: str | None = f"{base}/structured_scopes?page[size]=100"
            pages = 0
            while url and pages < _MAX_SCOPE_PAGES:
                sresp = client.get(url)
                sresp.raise_for_status()
                body = sresp.json()
                page_data = body.get("data")
                if isinstance(page_data, list):
                    scopes.extend(x for x in page_data if isinstance(x, dict))
                url = (body.get("links") or {}).get("next")
                pages += 1
    except httpx.HTTPError as exc:
        raise BountyLoadError(f"HackerOne API request for {handle!r} failed: {exc}") from exc

    # Normalize to the shape parse_program reads: the program object with the full
    # scope list injected as its structured_scopes relationship.
    obj = program_obj.get("data") if isinstance(program_obj.get("data"), dict) else program_obj
    if scopes:
        obj.setdefault("relationships", {})["structured_scopes"] = {"data": scopes}
    return parse_program(obj)
