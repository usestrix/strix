"""Tests for the scan recon ledger."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

import pytest

from strix.tools.recon_ledger.tools import (
    _list_impl,
    _record_impl,
    _update_impl,
    get_recon_ledger_entries,
    hydrate_recon_ledger_from_disk,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def recon_ledger_store(tmp_path: Path) -> Path:
    hydrate_recon_ledger_from_disk(tmp_path)
    return tmp_path


def _record(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "method": "GET",
        "path": "/api/orders/{id}",
        "params": "id (path)",
        "auth_required": None,
        "technology": "Express",
        "notes": "Found while crawling the SPA bundle.",
        "source": "JS bundle",
        "agent_id": "agent-1",
        "agent_name": "recon-bot",
    }
    kwargs.update(overrides)
    return _record_impl(**kwargs)


def test_record_persists_entry(recon_ledger_store: Path) -> None:
    result = _record()
    assert result["success"] is True

    entries = get_recon_ledger_entries()
    assert len(entries) == 1
    assert entries[0]["method"] == "GET"
    assert entries[0]["path"] == "/api/orders/{id}"
    assert entries[0]["agent_name"] == "recon-bot"
    assert (recon_ledger_store / "recon_ledger.json").exists()


def test_record_normalizes_method() -> None:
    assert _record(method="get")["success"] is True
    assert get_recon_ledger_entries()[0]["method"] == "GET"


def test_record_maps_unknown_method_to_other() -> None:
    result = _record(method="TRACE")
    assert result["success"] is True
    assert get_recon_ledger_entries()[0]["method"] == "OTHER"


def test_record_requires_method_and_path() -> None:
    result = _record(method="  ", path="")
    assert result["success"] is False
    joined = " ".join(result["errors"])
    assert "method" in joined
    assert "path" in joined


def test_record_omits_empty_optional_fields() -> None:
    result = _record(params="", technology="", notes="", source="", auth_required=None)
    assert result["success"] is True
    entry = get_recon_ledger_entries()[0]
    assert "params" not in entry
    assert "technology" not in entry
    assert "notes" not in entry
    assert "source" not in entry
    assert "auth_required" not in entry


def test_record_keeps_explicit_auth_required_false() -> None:
    result = _record(auth_required=False)
    assert result["success"] is True
    assert get_recon_ledger_entries()[0]["auth_required"] is False


def test_hydrate_reloads_from_disk(recon_ledger_store: Path) -> None:
    _record()
    hydrate_recon_ledger_from_disk(recon_ledger_store)
    entries = get_recon_ledger_entries()
    assert len(entries) == 1
    assert entries[0]["path"] == "/api/orders/{id}"


def _update(entry_id: str, **overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "entry_id": entry_id,
        "params": None,
        "auth_required": True,
        "technology": None,
        "notes": None,
        "source": None,
        "agent_id": "agent-2",
        "agent_name": "authz-tester",
    }
    kwargs.update(overrides)
    return _update_impl(**kwargs)


def test_update_changes_field_and_keeps_history() -> None:
    recorded = _record(auth_required=None)
    entry_id = str(recorded["entry_id"])

    result = _update(entry_id)

    assert result["success"] is True
    entries = get_recon_ledger_entries()
    assert len(entries) == 1, "update must not create a parallel entry"
    entry = entries[0]
    assert entry["auth_required"] is True
    assert entry["agent_name"] == "authz-tester"
    assert entry["history"] == [
        {
            "recorded_at": entry["created_at"],
            "params": "id (path)",
            "technology": "Express",
            "notes": "Found while crawling the SPA bundle.",
            "source": "JS bundle",
            "agent_name": "recon-bot",
        }
    ]


def test_update_can_clear_a_field_with_empty_string() -> None:
    entry_id = str(_record()["entry_id"])

    _update(entry_id, auth_required=None, notes="")

    entry = get_recon_ledger_entries()[0]
    assert "notes" not in entry


def test_update_requires_at_least_one_field() -> None:
    entry_id = str(_record()["entry_id"])

    result = _update_impl(
        entry_id=entry_id,
        params=None,
        auth_required=None,
        technology=None,
        notes=None,
        source=None,
        agent_id=None,
        agent_name=None,
    )

    assert result["success"] is False


def test_update_rejects_unknown_entry() -> None:
    result = _update("nope")
    assert result["success"] is False
    assert "list_endpoints" in str(result["error"])


def test_update_persists_to_disk(recon_ledger_store: Path) -> None:
    entry_id = str(_record()["entry_id"])
    _update(entry_id)

    hydrate_recon_ledger_from_disk(recon_ledger_store)

    entry = get_recon_ledger_entries()[0]
    assert entry["auth_required"] is True
    assert len(entry["history"]) == 1


def test_recording_a_duplicate_route_is_refused_with_the_existing_id() -> None:
    first = _record_impl(
        method="POST",
        path="/api/invoices",
        params="",
        auth_required=None,
        technology="",
        notes="",
        source="crawl",
        agent_id="a1",
        agent_name="Recon",
    )

    duplicate = _record_impl(
        method="post",
        path="  /API/Invoices ",
        params="",
        auth_required=True,
        technology="",
        notes="",
        source="manual probing",
        agent_id="a2",
        agent_name="Authz",
    )

    assert duplicate["success"] is False
    assert duplicate["existing_entry_id"] == first["entry_id"]
    assert "update_endpoint" in duplicate["error"]
    assert len(get_recon_ledger_entries()) == 1


def test_a_different_path_is_still_its_own_entry() -> None:
    _record_impl(
        method="GET",
        path="/api/invoices",
        params="",
        auth_required=None,
        technology="",
        notes="",
        source="",
        agent_id="a1",
        agent_name="Recon",
    )
    second = _record_impl(
        method="GET",
        path="/api/invoices/{id}",
        params="",
        auth_required=None,
        technology="",
        notes="",
        source="",
        agent_id="a1",
        agent_name="Recon",
    )

    assert second["success"] is True
    assert len(get_recon_ledger_entries()) == 2


def test_a_different_method_on_one_path_is_still_its_own_entry() -> None:
    _record_impl(
        method="GET",
        path="/api/invoices",
        params="",
        auth_required=None,
        technology="",
        notes="",
        source="",
        agent_id="a1",
        agent_name="Recon",
    )
    second = _record_impl(
        method="DELETE",
        path="/api/invoices",
        params="",
        auth_required=None,
        technology="",
        notes="",
        source="",
        agent_id="a1",
        agent_name="Recon",
    )

    assert second["success"] is True
    assert len(get_recon_ledger_entries()) == 2


def test_list_filters_by_method_path_and_auth() -> None:
    _record(method="GET", path="/login", auth_required=False)
    _record(method="POST", path="/login", auth_required=False)
    _record(method="GET", path="/admin/users", auth_required=True)

    by_method = _list_impl(
        method="POST", path_contains=None, auth_required=None, caller_agent_id=None
    )
    assert by_method["filtered_count"] == 1
    assert by_method["entries"][0]["path"] == "/login"

    by_path = _list_impl(
        method=None, path_contains="admin", auth_required=None, caller_agent_id=None
    )
    assert by_path["filtered_count"] == 1

    by_auth = _list_impl(
        method=None, path_contains=None, auth_required=True, caller_agent_id="agent-1"
    )
    assert by_auth["filtered_count"] == 1
    assert by_auth["entries"][0]["by_you"] is True


def test_list_rejects_unknown_method_filter() -> None:
    result = _list_impl(
        method="bogus", path_contains=None, auth_required=None, caller_agent_id=None
    )
    assert result["success"] is False


def test_concurrent_records_of_one_route_yield_a_single_row() -> None:
    """Duplicate detection and insertion must be one critical section.

    Two agents recording the same route at the same moment would otherwise
    both pass the "no duplicate" check, and the ledger would show a stale
    conclusion beside its replacement - the exact outcome the rejection
    exists to prevent.
    """
    barrier = threading.Barrier(8)

    def attempt(index: int) -> dict[str, Any]:
        barrier.wait()
        return _record(agent_id=f"agent-{index}", agent_name=f"tester-{index}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))

    assert sum(1 for result in results if result["success"]) == 1
    assert len(get_recon_ledger_entries()) == 1


def test_concurrent_records_all_survive_persistence(recon_ledger_store: Path) -> None:
    """A writer holding an older snapshot must not win the rename.

    If it did, the mirror would come back short on resume and endpoints
    recorded before a crash would silently disappear from the ledger.
    """
    barrier = threading.Barrier(8)

    def attempt(index: int) -> dict[str, Any]:
        barrier.wait()
        return _record(path=f"/api/resource/{index}", agent_id=f"agent-{index}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(attempt, range(8)))

    persisted = json.loads((recon_ledger_store / "recon_ledger.json").read_text(encoding="utf-8"))
    assert len(persisted) == 8
    hydrate_recon_ledger_from_disk(recon_ledger_store)
    assert len(get_recon_ledger_entries()) == 8
