"""Tests for the scan coverage ledger."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

import pytest

from strix.tools.coverage.tools import (
    _list_impl,
    _record_impl,
    _update_impl,
    get_coverage_entries,
    hydrate_coverage_from_disk,
    outcome_counts,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def coverage_store(tmp_path: Path) -> Path:
    hydrate_coverage_from_disk(tmp_path)
    return tmp_path


def _record(**overrides: str) -> dict[str, Any]:
    kwargs = {
        "surface": "POST /api/orders/{id}",
        "risk_area": "object-level authorization",
        "outcome": "no_issue_found",
        "evidence": "Tested with two tenants; both received 403.",
        "agent_id": "agent-1",
        "agent_name": "authz-tester",
    }
    kwargs.update(overrides)
    return _record_impl(**kwargs)


def test_record_persists_entry(coverage_store: Path) -> None:
    result = _record()
    assert result["success"] is True

    entries = get_coverage_entries()
    assert len(entries) == 1
    assert entries[0]["surface"] == "POST /api/orders/{id}"
    assert entries[0]["outcome"] == "no_issue_found"
    assert entries[0]["agent_name"] == "authz-tester"
    assert (coverage_store / "coverage.json").exists()


def test_record_normalizes_outcome() -> None:
    assert _record(outcome="Needs Follow-Up")["success"] is True
    assert get_coverage_entries()[0]["outcome"] == "needs_follow_up"


def test_record_rejects_unknown_outcome() -> None:
    result = _record(outcome="looks fine")
    assert result["success"] is False
    assert any("Invalid outcome" in e for e in result["errors"])
    assert not get_coverage_entries()


def test_record_requires_surface_and_risk_area() -> None:
    result = _record(surface="  ", risk_area="")
    assert result["success"] is False
    joined = " ".join(result["errors"])
    assert "surface" in joined
    assert "risk_area" in joined


@pytest.mark.parametrize("outcome", ["ruled_out", "not_applicable", "needs_follow_up"])
def test_evidence_required_for_asserted_outcomes(outcome: str) -> None:
    result = _record(outcome=outcome, evidence="   ")
    assert result["success"] is False
    assert any("evidence is required" in e for e in result["errors"])


def test_evidence_optional_for_reported() -> None:
    assert _record(outcome="reported", evidence="")["success"] is True


def test_outcome_counts_and_filtering() -> None:
    _record(surface="/login", outcome="reported", evidence="")
    _record(surface="/search", outcome="no_issue_found")
    _record(surface="/upload", outcome="needs_follow_up", evidence="No credentials to test.")

    assert outcome_counts() == {"reported": 1, "no_issue_found": 1, "needs_follow_up": 1}

    listed = _list_impl(outcome="needs_follow_up", surface=None, caller_agent_id="agent-1")
    assert listed["filtered_count"] == 1
    assert listed["entries"][0]["surface"] == "/upload"
    assert listed["entries"][0]["by_you"] is True

    by_surface = _list_impl(outcome=None, surface="sea", caller_agent_id=None)
    assert by_surface["filtered_count"] == 1
    assert by_surface["entries"][0]["surface"] == "/search"


def test_list_rejects_unknown_outcome_filter() -> None:
    result = _list_impl(outcome="bogus", surface=None, caller_agent_id=None)
    assert result["success"] is False


def test_hydrate_reloads_from_disk(coverage_store: Path) -> None:
    _record()
    hydrate_coverage_from_disk(coverage_store)
    entries = get_coverage_entries()
    assert len(entries) == 1
    assert entries[0]["risk_area"] == "object-level authorization"


def _update(entry_id: str, **overrides: str) -> dict[str, Any]:
    kwargs = {
        "entry_id": entry_id,
        "outcome": "reported",
        "evidence": "Got staging credentials and confirmed the IDOR.",
        "agent_id": "agent-2",
        "agent_name": "followup-tester",
    }
    kwargs.update(overrides)
    return _update_impl(**kwargs)


def test_update_moves_outcome_and_keeps_history() -> None:
    recorded = _record(outcome="needs_follow_up", evidence="No credentials to test.")
    entry_id = str(recorded["entry_id"])

    result = _update(entry_id)

    assert result["success"] is True
    assert result["previous_outcome"] == "needs_follow_up"
    assert result["outcome"] == "reported"

    entries = get_coverage_entries()
    assert len(entries) == 1, "update must not create a parallel entry"
    entry = entries[0]
    assert entry["outcome"] == "reported"
    assert entry["agent_name"] == "followup-tester"
    assert entry["history"] == [
        {
            "outcome": "needs_follow_up",
            "recorded_at": entry["created_at"],
            "evidence": "No credentials to test.",
            "agent_name": "authz-tester",
        }
    ]
    assert outcome_counts() == {"reported": 1}


def test_update_can_reopen_a_closed_entry() -> None:
    recorded = _record(outcome="ruled_out", evidence="Guard at auth.py:40 covers the path.")
    entry_id = str(recorded["entry_id"])

    _update(
        entry_id,
        outcome="needs_follow_up",
        evidence="The guard is skipped on the /v2 alias; reachability unproven.",
    )

    assert outcome_counts() == {"needs_follow_up": 1}
    listed = _list_impl(outcome=None, surface=None, caller_agent_id=None)
    assert listed["entries"][0]["previous_outcomes"] == ["ruled_out"]


def test_update_enforces_evidence_for_closing_outcomes() -> None:
    entry_id = str(_record(outcome="needs_follow_up", evidence="unknown")["entry_id"])

    result = _update(entry_id, outcome="ruled_out", evidence="  ")

    assert result["success"] is False
    assert get_coverage_entries()[0]["outcome"] == "needs_follow_up"


def test_update_rejects_unknown_entry() -> None:
    result = _update("nope")
    assert result["success"] is False
    assert "list_coverage" in str(result["error"])


def test_update_persists_to_disk(coverage_store: Path) -> None:
    entry_id = str(_record(outcome="needs_follow_up", evidence="No creds.")["entry_id"])
    _update(entry_id)

    hydrate_coverage_from_disk(coverage_store)

    entry = get_coverage_entries()[0]
    assert entry["outcome"] == "reported"
    assert len(entry["history"]) == 1


def test_recording_a_duplicate_surface_is_refused_with_the_existing_id() -> None:
    first = _record_impl(
        surface="/api/invoices",
        risk_area="IDOR",
        outcome="needs_follow_up",
        evidence="No second tenant account to test cross-tenant reads with.",
        agent_id="a1",
        agent_name="Recon",
    )

    duplicate = _record_impl(
        surface="  /API/Invoices ",
        risk_area="idor",
        outcome="reported",
        evidence="Cross-tenant read confirmed.",
        agent_id="a2",
        agent_name="Authz",
    )

    assert duplicate["success"] is False
    assert duplicate["existing_entry_id"] == first["entry_id"]
    assert duplicate["existing_outcome"] == "needs_follow_up"
    assert "update_coverage" in duplicate["error"]
    assert len(get_coverage_entries()) == 1


def test_a_different_risk_area_on_one_surface_is_still_its_own_entry() -> None:
    _record_impl(
        surface="/api/invoices",
        risk_area="IDOR",
        outcome="no_issue_found",
        evidence="Tenant id read from the session.",
        agent_id="a1",
        agent_name="Authz",
    )
    second = _record_impl(
        surface="/api/invoices",
        risk_area="SQL injection",
        outcome="no_issue_found",
        evidence="Parameterized throughout.",
        agent_id="a1",
        agent_name="Injection",
    )

    assert second["success"] is True
    assert len(get_coverage_entries()) == 2


def test_concurrent_records_of_one_surface_yield_a_single_row() -> None:
    """Duplicate detection and insertion must be one critical section.

    Two agents recording the same surface at the same moment would otherwise
    both pass the "no duplicate" check, and the report would show a stale
    conclusion beside its replacement — the exact outcome the rejection exists
    to prevent.
    """
    barrier = threading.Barrier(8)

    def attempt(index: int) -> dict[str, Any]:
        barrier.wait()
        return _record(agent_id=f"agent-{index}", agent_name=f"tester-{index}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))

    assert sum(1 for result in results if result["success"]) == 1
    assert len(get_coverage_entries()) == 1


def test_concurrent_records_all_survive_persistence(coverage_store: Path) -> None:
    """A writer holding an older snapshot must not win the rename.

    If it did, the mirror would come back short on resume and coverage
    recorded before a crash would silently disappear from the report.
    """
    barrier = threading.Barrier(8)

    def attempt(index: int) -> dict[str, Any]:
        barrier.wait()
        return _record(surface=f"GET /api/resource/{index}", agent_id=f"agent-{index}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(attempt, range(8)))

    persisted = json.loads((coverage_store / "coverage.json").read_text(encoding="utf-8"))
    assert len(persisted) == 8
    hydrate_coverage_from_disk(coverage_store)
    assert len(get_coverage_entries()) == 8
