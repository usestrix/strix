"""Stable cross-run identity for a Strix finding.

Strix's own ``strix/report/dedupe.py`` is LLM-based and only dedupes *within*
a single run, so correlating the same issue across scans needs a deterministic
key of our own. Endpoint + method + weakness class is what stays stable when
the agent rewords a title between runs; the title is only a fallback for
findings with no endpoint (dependency/code findings).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlsplit


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]{12,}$", re.I)
_NUM_RE = re.compile(r"^\d+$")
_NON_WORD_RE = re.compile(r"[^a-z0-9]+")


def normalize_endpoint(endpoint: str | None) -> str:
    """Path only, with volatile identifier segments collapsed to ``{id}``."""
    if not endpoint:
        return ""
    path = urlsplit(endpoint.strip()).path or endpoint.strip()
    segments = []
    for segment in path.split("/"):
        if not segment:
            continue
        if _NUM_RE.match(segment) or _UUID_RE.match(segment) or _HEX_RE.match(segment):
            segments.append("{id}")
        else:
            segments.append(segment.lower())
    return "/" + "/".join(segments)


def _title_slug(title: str | None) -> str:
    return _NON_WORD_RE.sub("-", (title or "").lower()).strip("-")


def finding_fingerprint(vuln: dict[str, Any]) -> str:
    weakness = str(vuln.get("cwe") or vuln.get("finding_class") or "").upper().strip()
    endpoint = normalize_endpoint(vuln.get("endpoint"))
    method = str(vuln.get("method") or "").upper().strip()

    if endpoint:
        parts = (weakness, method, endpoint)
    else:
        parts = (weakness, "", _title_slug(vuln.get("title")))

    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
