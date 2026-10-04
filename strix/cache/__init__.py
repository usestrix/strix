"""Strix 2 — cross-run recon cache.

A shared, on-disk store of recon results (port scans, enumeration, cloud listings)
keyed by ``(tool, target, params)`` and living outside any single run directory, so a
later run can reuse an earlier run's recon instead of re-running the expensive scan.
It saves the most over an LLM gateway with no prompt caching (e.g. 9Router), where
recon the agent does not repeat is context it is not re-billed for.

Kept as a self-contained package (no edits to the upstream run loop): the agent
reaches it through the ``recon_cache_*`` tools, which scope-gate each target and are
registered additively via ``strix.strix2_ext``.
"""

from __future__ import annotations

from strix.cache.schema import DEFAULT_TTL_SECONDS, ReconCacheEntry, cache_key
from strix.cache.store import (
    MAX_RESULT_BYTES,
    ReconCache,
    ReconCacheTooLargeError,
    default_cache_root,
    get_recon_cache,
    recon_cache_enabled,
    reset_recon_cache,
    set_recon_cache,
)


__all__ = [
    "DEFAULT_TTL_SECONDS",
    "MAX_RESULT_BYTES",
    "ReconCache",
    "ReconCacheEntry",
    "ReconCacheTooLargeError",
    "cache_key",
    "default_cache_root",
    "get_recon_cache",
    "recon_cache_enabled",
    "reset_recon_cache",
    "set_recon_cache",
]
