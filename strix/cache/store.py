"""Cross-run recon cache: a shared, on-disk store of recon results.

Unlike the candidate / finding-annotation stores (bound to one run directory), this
cache lives **outside** any single run so results persist across runs — default
``~/.strix/recon_cache``, overridable with ``$STRIX2_RECON_CACHE_DIR``. One JSON file
per entry, named by the cache key, written atomically. Disable the whole mechanism
with ``STRIX2_RECON_CACHE=0`` (reads miss, writes are skipped).

The store is deliberately dependency-light and scope-agnostic: it is pure storage.
Scope gating (refusing an out-of-scope target) happens in the agent tools that call
it, reusing ``strix.scope`` — the same split the candidate store uses.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from strix.cache.schema import DEFAULT_TTL_SECONDS, ReconCacheEntry, cache_key, normalize_tool
from strix.candidates.schema import normalize_target


if TYPE_CHECKING:
    from datetime import datetime


logger = logging.getLogger(__name__)

_CACHE_DIR_ENV = "STRIX2_RECON_CACHE_DIR"
_ENABLE_ENV = "STRIX2_RECON_CACHE"

# Refuse to cache a result larger than this: a truncated recon result is misleading,
# and the cache is for reuse, not bulk artifact storage.
MAX_RESULT_BYTES = 1024 * 1024  # 1 MiB


class ReconCacheTooLargeError(ValueError):
    """Raised by :meth:`ReconCache.put` when a result exceeds ``MAX_RESULT_BYTES``."""


def recon_cache_enabled() -> bool:
    return os.environ.get(_ENABLE_ENV, "1").strip().lower() not in ("0", "false", "no", "off")


def default_cache_root() -> Path:
    override = os.environ.get(_CACHE_DIR_ENV)
    if override and override.strip():
        return Path(override).expanduser()
    return Path.home() / ".strix" / "recon_cache"


class ReconCache:
    """A shared on-disk recon cache rooted at ``root`` (cross-run)."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or default_cache_root()

    def _path(self, key: str) -> Path:
        return self.root / f"{key}.json"

    # ---- reads -----------------------------------------------------------

    def get(
        self,
        tool: str,
        target: str,
        params: str = "",
        *,
        max_age_seconds: int | None = None,
        now: datetime | None = None,
    ) -> ReconCacheEntry | None:
        """Return a fresh cached entry for the triple, or ``None`` (miss or stale)."""
        path = self._path(cache_key(tool, target, params))
        if not path.exists():
            return None
        try:
            entry = ReconCacheEntry.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            logger.warning("could not read recon cache entry %s", path, exc_info=True)
            return None
        if not entry.is_fresh(now=now, max_age_seconds=max_age_seconds):
            return None
        return entry

    # ---- writes ----------------------------------------------------------

    def put(
        self,
        tool: str,
        target: str,
        result: str,
        *,
        params: str = "",
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        run_id: str | None = None,
        agent_id: str | None = None,
        agent_name: str | None = None,
    ) -> ReconCacheEntry:
        """Store a recon result. Raises :class:`ReconCacheTooLargeError` if too big."""
        size = len((result or "").encode("utf-8"))
        if size > MAX_RESULT_BYTES:
            raise ReconCacheTooLargeError(
                f"recon result is {size} bytes (> {MAX_RESULT_BYTES}); not cached"
            )
        key = cache_key(tool, target, params)
        entry = ReconCacheEntry(
            key=key,
            tool=normalize_tool(tool),
            target=target,
            normalized_target=normalize_target(target),
            params=params,
            result=result,
            size_bytes=size,
            ttl_seconds=max(1, int(ttl_seconds)),
            run_id=run_id,
            agent_id=agent_id,
            agent_name=agent_name,
        )
        self._write(entry)
        return entry

    def _write(self, entry: ReconCacheEntry) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self._path(entry.key)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        try:
            tmp.write_text(entry.model_dump_json(indent=2), encoding="utf-8")
            tmp.replace(path)  # atomic on the same filesystem
        finally:
            tmp.unlink(missing_ok=True)

    # ---- maintenance -----------------------------------------------------

    def _entries(self) -> list[ReconCacheEntry]:
        if not self.root.exists():
            return []
        entries: list[ReconCacheEntry] = []
        for path in self.root.glob("*.json"):
            try:
                entries.append(ReconCacheEntry.model_validate_json(path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        return entries

    def purge_expired(self, *, now: datetime | None = None) -> int:
        """Delete every expired entry; return how many were removed."""
        removed = 0
        if not self.root.exists():
            return 0
        for path in self.root.glob("*.json"):
            try:
                entry = ReconCacheEntry.model_validate_json(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not entry.is_fresh(now=now):
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    logger.warning("could not purge recon cache entry %s", path, exc_info=True)
        return removed

    def clear(self) -> int:
        """Delete every entry; return how many were removed."""
        removed = 0
        if not self.root.exists():
            return 0
        for path in self.root.glob("*.json"):
            try:
                path.unlink()
                removed += 1
            except OSError:
                logger.warning("could not delete recon cache entry %s", path, exc_info=True)
        return removed

    def stats(self) -> dict[str, Any]:
        entries = self._entries()
        return {
            "root": str(self.root),
            "entries": len(entries),
            "total_bytes": sum(e.size_bytes for e in entries),
        }


_global_recon_cache: ReconCache | None = None


def get_recon_cache() -> ReconCache | None:
    return _global_recon_cache


def set_recon_cache(cache: ReconCache | None) -> None:
    global _global_recon_cache  # noqa: PLW0603
    _global_recon_cache = cache


def reset_recon_cache(root: Path | None = None) -> ReconCache:
    """Bind a cache handle for the run (a cross-run root; does NOT clear the disk).

    Called once at run start (by ``strix.strix2_ext``). Rebinds only when the root
    changes, so calling it again is safe. The on-disk cache persists across runs —
    that is the whole point — so this never deletes anything.
    """
    resolved = root or default_cache_root()
    existing = get_recon_cache()
    if existing is not None and existing.root == resolved:
        return existing
    cache = ReconCache(root=resolved)
    set_recon_cache(cache)
    return cache
