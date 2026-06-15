"""Inventory source collectors."""

from __future__ import annotations

from strix.core.inventory.collectors.code import collect_code
from strix.core.inventory.collectors.external import (
    collect_arjun,
    collect_ffuf,
    collect_httpx,
    collect_katana,
)
from strix.core.inventory.collectors.js import collect_js
from strix.core.inventory.collectors.sitemap import collect_sitemap


__all__ = [
    "collect_arjun",
    "collect_code",
    "collect_ffuf",
    "collect_httpx",
    "collect_js",
    "collect_katana",
    "collect_sitemap",
]
