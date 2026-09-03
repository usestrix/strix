"""Stable, privacy-safe identity for this Strix CLI installation."""

from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from strix.utils.secret_files import write_secret_text


IDENTITY_PATH = Path.home() / ".strix" / "cli-identity.json"


def _default_device_name(instance_id: str) -> str:
    system = {"Darwin": "macOS", "Windows": "Windows", "Linux": "Linux"}.get(
        platform.system(), "Computer"
    )
    return f"{system} CLI · {instance_id[:8]}"


def read_or_create_identity(*, device_name: str | None = None) -> dict[str, str]:
    """Return one installation ID, optionally updating its user-facing label."""
    record: dict[str, Any] = {}
    try:
        raw = json.loads(IDENTITY_PATH.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            record = cast("dict[str, Any]", raw)
    except (OSError, json.JSONDecodeError):
        pass

    instance_id = record.get("client_instance_id")
    if not isinstance(instance_id, str) or len(instance_id) < 8:
        instance_id = str(uuid4())
    label = device_name.strip() if device_name is not None else record.get("device_name")
    if not isinstance(label, str) or not label.strip():
        label = _default_device_name(instance_id)
    label = " ".join(label.split())
    if not 1 <= len(label) <= 80:
        raise ValueError("device name must be 1-80 printable characters")

    identity = {"client_instance_id": instance_id, "device_name": label}
    write_secret_text(IDENTITY_PATH, json.dumps(identity, indent=2))
    return identity
