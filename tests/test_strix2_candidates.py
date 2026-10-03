"""Tests for the Strix 2 two-tier finding model — candidate (lead) tier."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from strix.agents import factory
from strix.agents.factory import registered_agent_tools
from strix.candidates import CandidateStore, normalize_target
from strix.candidates.schema import Candidate, structural_match
from strix.candidates.store import get_candidate_store, reset_candidate_store, set_candidate_store
from strix.candidates.writer import render_leads_markdown, write_leads
from strix.report.writer import write_executive_report
from strix.scope.enforcement import get_active_policy, set_active_policy
from strix.strix2_ext import install_strix2_extensions


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture(autouse=True)
def _isolate_globals() -> Iterator[None]:
    """Keep shared globals (tool registry, candidate store, scope policy) from leaking.

    ``install_strix2_extensions`` loads ``scope.yaml`` from cwd, so it can set an
    active policy; reset it too, or a later test's ``call_mcp`` would enforce it.
    """
    saved_tools = list(factory._EXTRA_TOOLS)
    saved_store = get_candidate_store()
    saved_policy = get_active_policy()
    factory._EXTRA_TOOLS.clear()
    set_candidate_store(None)
    set_active_policy(None)
    try:
        yield
    finally:
        factory._EXTRA_TOOLS[:] = saved_tools
        set_candidate_store(saved_store)
        set_active_policy(saved_policy)


# --- schema ------------------------------------------------------------------

def test_normalize_target_strips_scheme_and_slash() -> None:
    assert normalize_target("HTTPS://Example.com/") == "example.com"
    assert normalize_target("http://10.0.0.5:8080/path/") == "10.0.0.5:8080/path"


def test_dedup_key_is_domain_target_title() -> None:
    c = Candidate(id="x", title="Open Port 3306", target="https://Host", domain="network",
                  source="nmap", rationale="r")
    assert c.dedup_key == "network|host|open port 3306"


def test_structural_match_ignores_case_and_scheme() -> None:
    assert structural_match("Open S3", "https://b.s3", "open s3", "b.s3")
    assert not structural_match("Open S3", "a", "Open S3", "b")


# --- store: filing + dedup ---------------------------------------------------

def test_add_assigns_sequential_ids_and_persists(tmp_path: Path) -> None:
    store = CandidateStore(run_dir=tmp_path)
    r1 = store.add(title="Port 3306 open", target="10.0.0.5", domain="network",
                   source="nmap", rationale="MySQL exposed; not exercised")
    r2 = store.add(title="Public bucket policy", target="s3://b", domain="cloud",
                   source="prowler", rationale="policy reads public; unproven")
    assert r1["status"] == "created"
    assert r1["candidate"]["id"] == "cand-0001"
    assert r2["candidate"]["id"] == "cand-0002"

    saved = json.loads((tmp_path / "candidates.json").read_text(encoding="utf-8"))
    assert [c["id"] for c in saved] == ["cand-0001", "cand-0002"]


def test_duplicate_candidate_is_refused() -> None:
    store = CandidateStore()
    store.add(title="Port 3306 open", target="10.0.0.5", domain="network",
              source="nmap", rationale="r")
    dup = store.add(title="port 3306 open", target="10.0.0.5", domain="network",
                    source="nmap", rationale="r again")
    assert dup["status"] == "duplicate_candidate"
    assert dup["duplicate_of"] == "cand-0001"
    assert len(store.all_candidates()) == 1


def test_candidate_matching_a_validated_finding_is_refused() -> None:
    store = CandidateStore()
    validated = [{"id": "vuln-0007", "title": "SQLi in login", "target": "https://app/login"}]
    res = store.add(title="SQLi in login", target="https://app/login", domain="web",
                    source="reasoning", rationale="looks injectable",
                    existing_validated=validated)
    assert res["status"] == "already_validated"
    assert res["duplicate_of"] == "vuln-0007"


def test_a_dismissed_leads_key_can_be_refiled() -> None:
    store = CandidateStore()
    store.add(title="Maybe open redirect", target="https://app/go", domain="web",
              source="reasoning", rationale="r")
    store.dismiss("cand-0001", "confirmed the redirect is allowlisted")
    again = store.add(title="Maybe open redirect", target="https://app/go", domain="web",
                      source="reasoning", rationale="new evidence")
    assert again["status"] == "created"
    assert again["candidate"]["id"] == "cand-0002"


# --- store: lifecycle --------------------------------------------------------

def test_promote_links_to_a_validated_report(tmp_path: Path) -> None:
    store = CandidateStore(run_dir=tmp_path)
    store.add(title="Public object", target="s3://b/obj", domain="cloud",
              source="prowler", rationale="r")
    promoted = store.promote("cand-0001", "vuln-0003", note="unauthenticated GetObject succeeded")
    assert promoted is not None
    assert promoted.status == "promoted"
    assert promoted.promoted_to == "vuln-0003"
    saved = json.loads((tmp_path / "candidates.json").read_text(encoding="utf-8"))
    assert saved[0]["status"] == "promoted"


def test_dismiss_records_reason() -> None:
    store = CandidateStore()
    store.add(title="Open port", target="10.0.0.9", domain="network", source="nmap", rationale="r")
    dismissed = store.dismiss("cand-0001", "port filtered, no service reachable")
    assert dismissed is not None
    assert dismissed.status == "dismissed"
    assert "filtered" in (dismissed.resolution or "")


def test_list_filters_by_status() -> None:
    store = CandidateStore()
    store.add(title="a", target="t1", domain="network", source="s", rationale="r")
    store.add(title="b", target="t2", domain="cloud", source="s", rationale="r")
    store.dismiss("cand-0002", "benign")
    assert len(store.all_candidates()) == 2
    assert [c.id for c in store.all_candidates("open")] == ["cand-0001"]
    assert [c.id for c in store.all_candidates("dismissed")] == ["cand-0002"]


def test_unknown_ids_return_none() -> None:
    store = CandidateStore()
    assert store.get("cand-9999") is None
    assert store.promote("cand-9999", "vuln-0001") is None
    assert store.dismiss("cand-9999", "reason") is None


# --- bootstrap / registration -----------------------------------------------

def test_install_registers_candidate_tools_and_is_idempotent(tmp_path: Path) -> None:
    install_strix2_extensions(tmp_path)
    install_strix2_extensions(tmp_path)  # idempotent

    names = {t.name for t in registered_agent_tools()}
    expected = {"create_candidate", "list_candidates", "promote_candidate", "dismiss_candidate"}
    assert expected <= names
    # store is bound to the run dir so leads persist beside vulnerabilities.json
    store = get_candidate_store()
    assert store is not None
    assert store.run_dir == tmp_path


def test_reset_candidate_store_rebinds_on_new_run(tmp_path: Path) -> None:
    a = reset_candidate_store(tmp_path / "runA")
    same = reset_candidate_store(tmp_path / "runA")
    other = reset_candidate_store(tmp_path / "runB")
    assert a is same  # same run dir keeps the store (resume-safe)
    assert other is not a  # a new run dir rebinds


# --- leads rendering (B) -----------------------------------------------------

def test_render_leads_groups_and_labels_status() -> None:
    store = CandidateStore()
    store.add(title="Port 3306 open", target="10.0.0.5", domain="network", source="nmap",
              rationale="mysql exposed")
    store.add(title="Public bucket", target="s3://b", domain="cloud", source="prowler",
              rationale="policy public")
    store.add(title="Stale lead", target="x", domain="web", source="reasoning", rationale="r")
    store.promote("cand-0001", "vuln-0009")
    store.dismiss("cand-0003", "benign redirect")

    md = render_leads_markdown(store.all_candidates())
    assert "# Leads (unvalidated)" in md
    assert "1 open" in md and "1 promoted" in md and "1 dismissed" in md
    assert "### cloud" in md  # open lead grouped by domain
    assert "vuln-0009" in md  # promoted link
    assert "benign redirect" in md  # dismissal reason


def test_render_leads_is_empty_without_candidates() -> None:
    assert render_leads_markdown([]) == ""


def test_write_leads_creates_and_removes_file(tmp_path: Path) -> None:
    store = CandidateStore(run_dir=tmp_path)
    store.add(title="Open port", target="10.0.0.5", domain="network", source="nmap", rationale="r")
    assert (tmp_path / "LEADS.md").exists()  # written on persist
    write_leads(tmp_path, [])  # no candidates -> file removed
    assert not (tmp_path / "LEADS.md").exists()


def test_executive_report_appends_open_leads(tmp_path: Path) -> None:
    reset_candidate_store(tmp_path)
    store = get_candidate_store()
    assert store is not None
    store.add(title="Port 8080 open", target="10.0.0.5", domain="network", source="nmap",
              rationale="service present, no demonstrated impact")

    write_executive_report(tmp_path, "Executive summary body.")
    report = (tmp_path / "penetration_test_report.md").read_text(encoding="utf-8")
    assert "Executive summary body." in report
    assert "Leads (unvalidated)" in report
    assert "Port 8080 open" in report


def test_executive_report_has_no_leads_section_when_none(tmp_path: Path) -> None:
    set_candidate_store(None)
    write_executive_report(tmp_path, "Body only.")
    report = (tmp_path / "penetration_test_report.md").read_text(encoding="utf-8")
    assert "Leads (unvalidated)" not in report
