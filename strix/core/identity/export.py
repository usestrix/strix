"""Import/export of per-target identity sets as portable artifacts."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from strix.core.identity.models import Freshness, FreshnessStatus, Identity, Provenance


if TYPE_CHECKING:
    from pathlib import Path

_FRESHNESS_STATUS = frozenset({"fresh", "stale", "expired"})


def _identity_to_record(identity: Identity) -> dict[str, Any]:
    """Serialize an identity for export, preserving credentials."""
    return {
        "target_key": identity.target_key,
        "role": identity.role,
        "cookies": dict(identity.cookies),
        "tokens": dict(identity.tokens),
        "headers": dict(identity.headers),
        "provenance": identity.provenance,
        "freshness": identity.freshness.model_dump(),
        "is_reserved_expired": identity.is_reserved_expired,
    }


def _record_to_identity(record: dict[str, Any]) -> Identity:
    """Deserialize a record back into an ``Identity``."""
    freshness_record: dict[str, Any] = record.get("freshness") or {}
    captured_at: str = freshness_record.get("captured_at", datetime.now(UTC).isoformat())
    expires_hint: str | None = freshness_record.get("expires_hint")
    status_raw: str = freshness_record.get("status", "fresh")
    status: str = status_raw if status_raw in _FRESHNESS_STATUS else "fresh"
    provenance_raw: str = record.get("provenance", "imported")
    provenance: str = (
        provenance_raw
        if provenance_raw in {"proxy_capture", "login_flow", "imported", "reserved"}
        else "imported"
    )
    return Identity(
        target_key=str(record.get("target_key", "")),
        role=str(record.get("role", "")),
        cookies=dict(record.get("cookies", {}) or {}),
        tokens=dict(record.get("tokens", {}) or {}),
        headers=dict(record.get("headers", {}) or {}),
        provenance=cast("Provenance", provenance),
        freshness=Freshness(
            captured_at=captured_at,
            expires_hint=expires_hint,
            status=cast("FreshnessStatus", status),
        ),
        is_reserved_expired=bool(record.get("is_reserved_expired", False)),
    )


def export_identities(target_key: str, identities: list[Identity]) -> dict[str, Any]:
    """Export a target's identity set to a portable artifact.

    Credentials are preserved in the artifact but must be handled as a secret
    by the caller (encrypted storage, no logging).
    """
    return {
        "version": 1,
        "exported_at": datetime.now(UTC).isoformat(),
        "target_key": target_key,
        "identities": [_identity_to_record(i) for i in identities],
    }


def import_identities(
    artifact: dict[str, Any],
    expected_target_key: str | None = None,
) -> list[Identity]:
    """Import identities from an artifact.

    Args:
        artifact: The exported artifact dict.
        expected_target_key: If provided, reject identities for any other
            target key to enforce per-target scoping.

    Returns:
        A list of ``Identity`` objects ready to be upserted into a store.

    Raises:
        ValueError: If the artifact is for a foreign target.
    """
    target_key: str | None = artifact.get("target_key")
    if expected_target_key is not None and target_key != expected_target_key:
        raise ValueError(
            f"Artifact target_key {target_key!r} does not match expected {expected_target_key!r}"
        )
    if not isinstance(target_key, str) or not target_key:
        raise ValueError("Artifact missing target_key")

    records: list[Any] = artifact.get("identities", [])
    if not isinstance(records, list):
        raise TypeError("Artifact identities must be a list")

    identities: list[Identity] = []
    for record in records:
        if not isinstance(record, dict):
            raise TypeError("Each identity record must be an object")
        identity = _record_to_identity(record)
        if identity.target_key != target_key:
            raise ValueError(
                f"Identity target_key {identity.target_key!r} differs from "
                f"artifact target_key {target_key!r}"
            )
        if identity.provenance != "reserved":
            identity.provenance = "imported"
        identities.append(identity)
    return identities


def export_identities_to_file(
    target_key: str,
    identities: list[Identity],
    path: Path,
) -> None:
    """Write a target's identity set to a JSON file."""
    payload = export_identities(target_key, identities)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def import_identities_from_file(
    path: Path,
    expected_target_key: str | None = None,
) -> list[Identity]:
    """Read an identity artifact from a JSON file."""
    text = path.read_text(encoding="utf-8")
    artifact = json.loads(text)
    if not isinstance(artifact, dict):
        raise TypeError("Artifact file must contain a JSON object")
    return import_identities(artifact, expected_target_key=expected_target_key)
