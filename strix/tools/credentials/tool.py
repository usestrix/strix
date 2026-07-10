"""Credential placeholder substitution utilities for Strix agents."""

from __future__ import annotations

import re


_PLACEHOLDER_RE = re.compile(r"\{\{([A-Za-z0-9_]+)\}\}")


def substitute_credentials(text: str, credentials: dict[str, str]) -> str:
    """Replace ``{{NAME}}`` tokens in *text* with matching credential values.

    Tokens whose names are not in *credentials* are left unchanged.
    Empty-string credential values substitute to an empty string.
    """
    if not credentials:
        return text

    def _replace(m: re.Match[str]) -> str:
        name = m.group(1)
        return credentials[name] if name in credentials else m.group(0)

    return _PLACEHOLDER_RE.sub(_replace, text)


def scrub_credentials(text: str, credentials: dict[str, str]) -> str:
    """Replace literal credential values in *text* with ``[CREDENTIAL:NAME]``.

    Values shorter than 4 characters are not scrubbed to avoid false-positive
    replacement of common substrings.  Longer values are replaced first so that
    a longer secret that contains a shorter one is handled correctly.
    """
    pairs = sorted(
        ((v, k) for k, v in credentials.items() if len(v) >= 4),
        key=lambda x: -len(x[0]),
    )
    for value, name in pairs:
        text = re.sub(re.escape(value), f"[CREDENTIAL:{name}]", text)
    return text
