"""Tests for the Strix 2 cross-run recon cache (schema, store, tools, registration)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from strix.agents.factory import registered_agent_tools
from strix.cache.schema import DEFAULT_TTL_SECONDS, ReconCacheEntry, cache_key
from strix.cache.store import (
    MAX_RESULT_BYTES,
    ReconCache,
    ReconCacheTooLargeError,
    get_recon_cache,
    reset_recon_cache,
    set_recon_cache,
)
from strix.scope.enforcement import get_active_policy, set_active_policy
from strix.scope.schema import ScopePolicy
from strix.strix2_ext import install_strix2_extensions
from strix.tools.cache.tools import (
    _do_recon_cache_get,
    _do_recon_cache_put,
    _do_recon_cache_stats,
)


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReconCache]:
    """A temp cache root + clean scope + enabled cache, restored afterward."""
    saved_cache = get_recon_cache()
    saved_policy = get_active_policy()
    monkeypatch.delenv("STRIX2_RECON_CACHE", raising=False)
    monkeypatch.setenv("STRIX2_RECON_CACHE_DIR", str(tmp_path / "recon_cache"))
    set_active_policy(None)  # no policy -> scope checks allow
    cache = reset_recon_cache(tmp_path / "recon_cache")
    try:
        yield cache
    finally:
        set_recon_cache(saved_cache)
        set_active_policy(saved_policy)


# --- key derivation ----------------------------------------------------------

def test_key_normalizes_scheme_slash_and_case() -> None:
    assert cache_key("nmap", "http://example.com/") == cache_key("NMAP", "example.com")
    assert cache_key("httpx", "HTTPS://Example.com") == cache_key("httpx", "example.com")


def test_key_separates_params() -> None:
    assert cache_key("nmap", "10.0.0.5", "-p-") != cache_key("nmap", "10.0.0.5", "--top-ports 100")
    assert cache_key("nmap", "10.0.0.5", " -p-  ") == cache_key("nmap", "10.0.0.5", "-p-")


# --- entry freshness ---------------------------------------------------------

def test_entry_fresh_and_stale() -> None:
    created = datetime.now(UTC) - timedelta(hours=2)
    entry = ReconCacheEntry(
        key="k", tool="nmap", target="t", normalized_target="t",
        result="x", created_at=created.isoformat(), ttl_seconds=3600,
    )
    assert entry.is_fresh() is False  # 2h old, 1h ttl
    entry_long = entry.model_copy(update={"ttl_seconds": 24 * 3600})
    assert entry_long.is_fresh() is True
    # a stricter max_age overrides a generous ttl
    assert entry_long.is_fresh(max_age_seconds=1800) is False


# --- store round-trip --------------------------------------------------------

def test_store_put_get_roundtrip(_isolate: ReconCache) -> None:
    _isolate.put("nmap", "10.0.0.5", "PORT 22 open", params="-p-")
    entry = _isolate.get("nmap", "10.0.0.5", "-p-")
    assert entry is not None
    assert entry.result == "PORT 22 open"
    assert entry.normalized_target == "10.0.0.5"
    # scheme/case-insensitive match on target + tool
    assert _isolate.get("NMAP", "10.0.0.5", "-p-") is not None


def test_store_miss_returns_none(_isolate: ReconCache) -> None:
    assert _isolate.get("nmap", "10.0.0.99") is None


def test_store_respects_ttl(_isolate: ReconCache) -> None:
    _isolate.put("nmap", "10.0.0.5", "data", ttl_seconds=3600)
    future = datetime.now(UTC) + timedelta(hours=2)
    assert _isolate.get("nmap", "10.0.0.5", now=future) is None  # expired
    assert _isolate.get("nmap", "10.0.0.5") is not None  # fresh now


def test_store_max_age_override(_isolate: ReconCache) -> None:
    _isolate.put("nmap", "10.0.0.5", "data", ttl_seconds=24 * 3600)
    soon = datetime.now(UTC) + timedelta(hours=2)
    assert _isolate.get("nmap", "10.0.0.5", max_age_seconds=3600, now=soon) is None
    assert _isolate.get("nmap", "10.0.0.5", max_age_seconds=24 * 3600, now=soon) is not None


def test_store_rejects_too_large(_isolate: ReconCache) -> None:
    big = "x" * (MAX_RESULT_BYTES + 1)
    with pytest.raises(ReconCacheTooLargeError):
        _isolate.put("nmap", "10.0.0.5", big)


def test_store_purge_and_clear(_isolate: ReconCache) -> None:
    _isolate.put("nmap", "a", "1", ttl_seconds=3600)
    _isolate.put("nmap", "b", "2", ttl_seconds=24 * 3600)
    future = datetime.now(UTC) + timedelta(hours=2)
    assert _isolate.purge_expired(now=future) == 1  # only "a" expired
    assert _isolate.stats()["entries"] == 1
    assert _isolate.clear() == 1
    assert _isolate.stats()["entries"] == 0


def test_store_stats(_isolate: ReconCache) -> None:
    _isolate.put("nmap", "a", "hello")
    stats = _isolate.stats()
    assert stats["entries"] == 1
    assert stats["total_bytes"] == len(b"hello")
    assert stats["root"].endswith("recon_cache")


def test_reset_recon_cache_idempotent_and_rebind(tmp_path: Path) -> None:
    root = tmp_path / "c1"
    a = reset_recon_cache(root)
    b = reset_recon_cache(root)
    assert a is b  # same root -> same handle
    c = reset_recon_cache(tmp_path / "c2")
    assert c is not a  # new root -> rebind


# --- tool helpers ------------------------------------------------------------

def test_tool_get_miss_then_put_then_hit() -> None:
    miss = json.loads(_do_recon_cache_get("10.0.0.5", "nmap", "", 0.0))
    assert miss == {"success": True, "hit": False}

    stored = json.loads(_do_recon_cache_put("10.0.0.5", "nmap", "PORT 22 open", 24.0, ""))
    assert stored["success"] is True
    assert stored["stored"] is True
    assert stored["expires_in_hours"] == 24.0

    hit = json.loads(_do_recon_cache_get("10.0.0.5", "nmap", "", 0.0))
    assert hit["hit"] is True
    assert hit["result"] == "PORT 22 open"
    assert "age_hours" in hit
    assert "prior run" in hit["note"]


def test_tool_put_requires_fields() -> None:
    assert json.loads(_do_recon_cache_put("", "nmap", "x", 24.0, ""))["success"] is False
    assert json.loads(_do_recon_cache_put("t", "nmap", "", 24.0, ""))["success"] is False


def test_tool_put_too_large() -> None:
    body = json.loads(_do_recon_cache_put("t", "nmap", "x" * (MAX_RESULT_BYTES + 1), 24.0, ""))
    assert body["success"] is False
    assert "not cached" in body["error"]


def test_tool_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX2_RECON_CACHE", "0")
    put = json.loads(_do_recon_cache_put("t", "nmap", "x", 24.0, ""))
    assert put["stored"] is False
    assert put["disabled"] is True
    get = json.loads(_do_recon_cache_get("t", "nmap", "", 0.0))
    assert get["hit"] is False
    assert get["disabled"] is True


def test_tool_stats() -> None:
    _do_recon_cache_put("t", "nmap", "data", 24.0, "")
    stats = json.loads(_do_recon_cache_stats())
    assert stats["success"] is True
    assert stats["enabled"] is True
    assert stats["entries"] == 1


# --- scope gating ------------------------------------------------------------

def test_tool_refuses_out_of_scope_target() -> None:
    set_active_policy(ScopePolicy.model_validate({"web": {"domains": ["example.com"]}}))
    denied = json.loads(_do_recon_cache_get("http://evil.test/x", "httpx", "", 0.0))
    assert denied["success"] is False
    assert denied["refused"] == "out_of_scope"
    denied_put = json.loads(_do_recon_cache_put("http://evil.test/x", "httpx", "data", 24.0, ""))
    assert denied_put["refused"] == "out_of_scope"


def test_tool_allows_in_scope_target() -> None:
    set_active_policy(ScopePolicy.model_validate({"web": {"domains": ["example.com"]}}))
    stored = json.loads(_do_recon_cache_put("http://example.com/app", "httpx", "200 OK", 24.0, ""))
    assert stored["success"] is True
    hit = json.loads(_do_recon_cache_get("http://example.com/app", "httpx", "", 0.0))
    assert hit["hit"] is True


# --- registration ------------------------------------------------------------

def test_install_registers_recon_cache_tools(tmp_path: Path) -> None:
    install_strix2_extensions(tmp_path)
    names = {t.name for t in registered_agent_tools()}
    assert {"recon_cache_get", "recon_cache_put", "recon_cache_stats"} <= names
    assert get_recon_cache() is not None


def test_default_ttl_is_a_day() -> None:
    assert DEFAULT_TTL_SECONDS == 24 * 60 * 60
