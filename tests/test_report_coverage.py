"""Tests for the coverage artifact assembled in strix.report.coverage."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from strix.report.coverage import (
    _SKILL_PHRASINGS,
    VULN_CLASSES,
    build_coverage_document,
    cwe_for_skill,
    read_agent_graph,
    write_coverage,
)
from strix.skills import get_available_skills


if TYPE_CHECKING:
    from pathlib import Path


def _entry(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "surface": "POST /api/orders/{id}",
        "risk_area": "object-level authorization",
        "outcome": "no_issue_found",
        "evidence": "Two tenants tested; both received 403.",
        "agent_id": "agent-1",
        "agent_name": "authz-tester",
        "created_at": "2026-07-02 10:00:00 UTC",
    }
    base.update(overrides)
    return base


def _graph(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "statuses": {"agent-1": "completed"},
        "names": {"agent-1": "authz-tester"},
        "metadata": {"agent-1": {"skills": ["idor"], "task": "authz review"}},
    }
    base.update(overrides)
    return base


def _document(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "run_record": {"run_id": "r1", "run_name": "run-1", "status": "completed"},
        "entries": [_entry()],
        "agent_graph": _graph(),
        "vulnerability_reports": [],
    }
    kwargs.update(overrides)
    return build_coverage_document(**kwargs)


def test_document_reports_surfaces_and_outcomes() -> None:
    doc = _document()

    assert doc["summary"]["surfaces_reviewed"] == 1
    assert doc["summary"]["outcomes"] == {"no_issue_found": 1}
    assert doc["entries"][0]["outcome_label"] == "No issue identified"
    assert doc["entries"][0]["recorded_by"] == "authz-tester"


def test_ledger_entries_are_labelled_as_agent_reported() -> None:
    """A reader has to be able to tell a self-report from an observation."""
    doc = _document()

    assert doc["entries"][0]["source"] == "agent_reported"
    assert doc["machine_observed"]["source"] == "runtime"
    assert doc["machine_observed"]["skills_exercised"] == ["idor"]


def test_assigned_risk_skill_without_coverage_becomes_a_gap() -> None:
    """An agent carrying the sql_injection skill that records nothing about it
    leaves the class unexamined, not clean."""
    doc = _document(
        agent_graph=_graph(
            metadata={"agent-1": {"skills": ["idor", "sql_injection"], "task": "review"}}
        )
    )

    gaps = [gap for gap in doc["gaps"] if gap["kind"] == "unrecorded_risk_class"]
    assert [gap["risk_area"] for gap in gaps] == ["sql injection"]


def test_substring_match_does_not_hide_a_gap() -> None:
    """A short class token matches whole words, not substrings: 'brute force' is
    not RCE coverage, 'enforcement' is not 'rce', 'corridor' is not 'idor'."""
    cases = [
        ("rce", "POST /login", "brute force protection"),
        ("rce", "GET /api/resources/{id}", "object-level authorization"),
        ("rce", "Access control enforcement", "authorization"),
        ("idor", "GET /building/corridor/{id}", "information disclosure"),
    ]
    for skill, surface, risk in cases:
        doc = _document(
            entries=[_entry(surface=surface, risk_area=risk)],
            agent_graph=_graph(metadata={"agent-1": {"skills": [skill]}}),
        )
        classes = [g["risk_area"] for g in doc["gaps"] if g["kind"] == "unrecorded_risk_class"]
        assert skill.replace("_", " ") in classes, (skill, surface, risk, classes)


def test_joined_camelcase_name_counts_as_coverage() -> None:
    """A row recorded as a joined/CamelCase class name ('DirectoryTraversal')
    still counts, via the joined-token fallback — no substring matching."""
    doc = _document(
        entries=[_entry(risk_area="DirectoryTraversal reviewed", surface="/download")],
        agent_graph=_graph(metadata={"agent-1": {"skills": ["path_traversal_lfi_rfi"]}}),
    )

    assert not [g for g in doc["gaps"] if g["kind"] == "unrecorded_risk_class"]


def test_simple_plural_still_counts_as_coverage() -> None:
    """Whole-word matching tolerates a trivial plural, so 'passwords' /
    'credentials' still cover weak_password_detection."""
    doc = _document(
        entries=[_entry(risk_area="weak passwords and credentials reviewed", surface="/login")],
        agent_graph=_graph(metadata={"agent-1": {"skills": ["weak_password_detection"]}}),
    )

    assert not [g for g in doc["gaps"] if g["kind"] == "unrecorded_risk_class"]


def test_recorded_risk_class_is_not_reported_as_a_gap() -> None:
    doc = _document(
        entries=[_entry(risk_area="SQL injection", surface="GET /search?q=")],
        agent_graph=_graph(metadata={"agent-1": {"skills": ["sql_injection"]}}),
    )

    assert not [gap for gap in doc["gaps"] if gap["kind"] == "unrecorded_risk_class"]


def test_synonym_phrasing_counts_as_recorded_coverage() -> None:
    """The ledger says "object-level authorization"; the skill is called idor."""
    doc = _document(agent_graph=_graph(metadata={"agent-1": {"skills": ["idor"]}}))

    assert not [gap for gap in doc["gaps"] if gap["kind"] == "unrecorded_risk_class"]


def test_cspt_acronym_phrasing_counts_as_recorded_coverage() -> None:
    """The ledger spells out "Client-Side Path Traversal (CSPT)"; the skill is
    called client_side_path_traversal."""
    doc = _document(
        entries=[
            _entry(risk_area="Client-Side Path Traversal (CSPT)", surface="GET /app#/profile")
        ],
        agent_graph=_graph(metadata={"agent-1": {"skills": ["client_side_path_traversal"]}}),
    )

    assert not [gap for gap in doc["gaps"] if gap["kind"] == "unrecorded_risk_class"]


def test_bundled_skill_partially_tested_flags_untested_subtopics() -> None:
    """browser_security bundles many surfaces; proving postMessage must not
    mark client-side path traversal covered."""
    doc = _document(
        entries=[_entry(risk_area="postMessage origin validation", surface="window listener")],
        agent_graph=_graph(metadata={"agent-1": {"skills": ["browser_security"]}}),
    )

    flagged = {g["risk_area"] for g in doc["gaps"] if g["kind"] == "unrecorded_sub_topic"}
    assert "client-side path traversal" in flagged
    assert "postMessage" not in flagged  # the surface that was tested is not re-flagged
    # a partially-tested bundled skill is not also reported as a wholesale gap
    assert not [
        g
        for g in doc["gaps"]
        if g["kind"] == "unrecorded_risk_class" and g["risk_area"] == "browser security"
    ]


def test_bundled_skill_wholly_untested_is_a_single_gap() -> None:
    """A bundled skill nobody touched collapses to one class-level gap, not one
    per surface — the honest short statement is "not examined"."""
    doc = _document(
        entries=[_entry(risk_area="SQL injection", surface="GET /search")],
        agent_graph=_graph(metadata={"agent-1": {"skills": ["browser_security"]}}),
    )

    class_gaps = [
        g
        for g in doc["gaps"]
        if g["kind"] == "unrecorded_risk_class" and g["risk_area"] == "browser security"
    ]
    assert len(class_gaps) == 1
    assert "surfaces" in class_gaps[0]["detail"]
    assert not [g for g in doc["gaps"] if g["kind"] == "unrecorded_sub_topic"]


def test_bundled_skill_with_every_surface_covered_is_clean() -> None:
    """Covering every surface of a bundled skill leaves no coverage gap."""
    entries = [
        _entry(risk_area=sub.phrasings[0], surface=sub.label)
        for sub in VULN_CLASSES["browser_security"].sub_topics
    ]
    doc = _document(
        entries=entries,
        agent_graph=_graph(metadata={"agent-1": {"skills": ["browser_security"]}}),
    )

    assert not [
        g for g in doc["gaps"] if g["kind"] in {"unrecorded_risk_class", "unrecorded_sub_topic"}
    ]


def test_unrelated_agents_row_does_not_cover_a_browser_subtopic() -> None:
    """An open_redirect agent's 'meta refresh' row must not mark browser_security's
    navigation surface covered — only a browser_security carrier's row counts."""
    doc = _document(
        entries=[
            _entry(
                risk_area="postMessage origin validation",
                surface="listener",
                agent_id="agent-1",
                agent_name="browser-tester",
            ),
            _entry(
                risk_area="open redirect via meta refresh",
                surface="/login?next=",
                agent_id="agent-2",
                agent_name="redirect-tester",
            ),
        ],
        agent_graph=_graph(
            statuses={"agent-1": "completed", "agent-2": "completed"},
            names={"agent-1": "browser-tester", "agent-2": "redirect-tester"},
            metadata={
                "agent-1": {"skills": ["browser_security"]},
                "agent-2": {"skills": ["open_redirect"]},
            },
        ),
    )

    sub = {g["risk_area"] for g in doc["gaps"] if g["kind"] == "unrecorded_sub_topic"}
    assert "navigation and redirect control" in sub  # not masked by the open_redirect row
    assert "postMessage" not in sub  # the browser agent's own row still counts


def test_updated_browser_row_keeps_its_carrier_authorship() -> None:
    """update_coverage overwrites agent_id with the updater's; a browser surface a
    carrier assessed must still count via the author preserved in history."""
    doc = _document(
        entries=[
            _entry(
                risk_area="client-side path traversal",
                surface="fetch from route param",
                agent_id="agent-2",  # current author after an unrelated update
                agent_name="redirect-tester",
                history=[
                    {
                        "outcome": "no_issue_found",
                        "agent_id": "agent-1",  # the carrier who first assessed it
                        "agent_name": "browser-tester",
                    }
                ],
            ),
        ],
        agent_graph=_graph(
            statuses={"agent-1": "completed", "agent-2": "completed"},
            names={"agent-1": "browser-tester", "agent-2": "redirect-tester"},
            metadata={
                "agent-1": {"skills": ["browser_security"]},
                "agent-2": {"skills": ["open_redirect"]},
            },
        ),
    )

    sub = {g["risk_area"] for g in doc["gaps"] if g["kind"] == "unrecorded_sub_topic"}
    assert "client-side path traversal" not in sub  # preserved carrier authorship counts


def test_registry_backs_skill_phrasings_and_cwe() -> None:
    """_SKILL_PHRASINGS is derived from the registry, so they cannot drift."""
    assert {name: v.aliases for name, v in VULN_CLASSES.items()} == _SKILL_PHRASINGS
    assert cwe_for_skill("sql_injection") == ("CWE-89",)
    assert cwe_for_skill("vulnerabilities/ssrf") == ("CWE-918",)
    assert cwe_for_skill("subdomain_takeover") == ()


def test_non_risk_skills_carry_no_coverage_obligation() -> None:
    """Tooling skills describe how an agent works, not what it hunts."""
    doc = _document(agent_graph=_graph(metadata={"agent-1": {"skills": ["idor", "caido"]}}))

    assert not [gap for gap in doc["gaps"] if gap.get("risk_area") == "caido"]


def test_agent_that_recorded_nothing_is_a_gap() -> None:
    doc = _document(
        agent_graph=_graph(
            statuses={"agent-1": "completed", "agent-2": "completed"},
            names={"agent-1": "authz-tester", "agent-2": "recon"},
            metadata={},
        )
    )

    silent = [gap for gap in doc["gaps"] if gap["kind"] == "agent_recorded_no_coverage"]
    assert [gap["agent_name"] for gap in silent] == ["recon"]


def test_needs_follow_up_is_carried_as_an_open_gap() -> None:
    doc = _document(
        entries=[_entry(outcome="needs_follow_up", evidence="Auth wall blocked testing.")]
    )

    assert doc["gaps"][0]["kind"] == "needs_follow_up"
    assert doc["gaps"][0]["detail"] == "Auth wall blocked testing."


def test_completed_run_with_finished_agents_is_complete() -> None:
    doc = _document(exit_reason="finished_by_tool")

    assert doc["completeness"]["complete"] is True
    assert doc["completeness"]["caveats"] == []


def test_budget_exhausted_run_is_not_a_complete_record() -> None:
    """A truncated scan must not read like a clean one."""
    doc = _document(exit_reason="budget_exhausted")

    assert doc["completeness"]["complete"] is False
    assert "budget_exhausted" in doc["completeness"]["caveats"][0]


def test_unfinished_agent_makes_the_record_partial() -> None:
    doc = _document(
        agent_graph=_graph(statuses={"agent-1": "crashed"}),
        exit_reason="finished_by_tool",
    )

    assert doc["completeness"]["complete"] is False
    assert "authz-tester" in doc["completeness"]["caveats"][0]


def test_failed_run_status_makes_the_record_partial() -> None:
    doc = _document(
        run_record={"run_id": "r1", "status": "failed"},
        exit_reason="finished_by_tool",
    )

    assert doc["completeness"]["complete"] is False


def test_write_coverage_emits_a_top_level_artifact(tmp_path: Path) -> None:
    path = write_coverage(tmp_path, _document())

    assert path == tmp_path / "coverage.json"
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 1


def test_read_agent_graph_tolerates_a_missing_or_corrupt_snapshot(tmp_path: Path) -> None:
    assert read_agent_graph(tmp_path) == {}

    (tmp_path / "agents.json").write_text("{not json", encoding="utf-8")
    assert read_agent_graph(tmp_path) == {}


def test_read_agent_graph_loads_a_snapshot(tmp_path: Path) -> None:
    (tmp_path / "agents.json").write_text(json.dumps(_graph()), encoding="utf-8")

    assert read_agent_graph(tmp_path)["names"] == {"agent-1": "authz-tester"}


def test_multi_token_skill_matches_how_a_pentester_writes_it() -> None:
    """An agent carrying path_traversal_lfi_rfi records "Path Traversal".

    Requiring the skill's filename verbatim published a false gap for a class
    that had been tested and even had a finding filed against it.
    """
    doc = _document(
        entries=[_entry(risk_area="Path Traversal / Directory Traversal", surface="/download")],
        agent_graph=_graph(metadata={"agent-1": {"skills": ["path_traversal_lfi_rfi"]}}),
    )

    assert not [gap for gap in doc["gaps"] if gap["kind"] == "unrecorded_risk_class"]


def _vulnerability_skill_names() -> set[str]:
    return {skill["name"] for skill in get_available_skills()["vulnerabilities"]}


def test_every_vulnerability_skill_declares_its_phrasings() -> None:
    """A new skill without phrasings would be matched by its filename alone,
    which is how the false gap above got published."""
    missing = _vulnerability_skill_names() - set(_SKILL_PHRASINGS)

    assert not missing, f"add ledger phrasings for: {sorted(missing)}"


def test_declared_phrasings_name_real_skills() -> None:
    stale = set(_SKILL_PHRASINGS) - _vulnerability_skill_names()

    assert not stale, f"phrasings for skills that no longer exist: {sorted(stale)}"


def _delegating_graph(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "statuses": {"root": "completed", "agent-1": "completed"},
        "names": {"root": "Root Agent", "agent-1": "authz-tester"},
        "parent_of": {"agent-1": "root"},
        "metadata": {"agent-1": {"skills": ["idor"]}},
    }
    base.update(overrides)
    return base


def test_delegating_root_agent_is_not_a_coverage_gap() -> None:
    """The root delegates and reconciles; it is not a tester that went quiet.
    Flagging it would put the same false line in every clean report."""
    doc = _document(agent_graph=_delegating_graph())

    silent = [gap for gap in doc["gaps"] if gap["kind"] == "agent_recorded_no_coverage"]
    assert silent == []


def test_a_subagent_that_records_nothing_is_still_a_gap() -> None:
    doc = _document(
        agent_graph=_delegating_graph(
            statuses={"root": "completed", "agent-1": "completed", "agent-2": "completed"},
            names={"root": "Root Agent", "agent-1": "authz-tester", "agent-2": "recon"},
            parent_of={"agent-1": "root", "agent-2": "root"},
        )
    )

    silent = [gap for gap in doc["gaps"] if gap["kind"] == "agent_recorded_no_coverage"]
    assert [gap["agent_name"] for gap in silent] == ["recon"]


def test_a_root_that_worked_alone_is_held_to_the_rule() -> None:
    """With no subagents there is nobody else the testing could have come
    from, so silence is a real gap."""
    doc = _document(
        entries=[],
        agent_graph={
            "statuses": {"root": "completed"},
            "names": {"root": "Root Agent"},
            "parent_of": {},
        },
    )

    silent = [gap for gap in doc["gaps"] if gap["kind"] == "agent_recorded_no_coverage"]
    assert [gap["agent_name"] for gap in silent] == ["Root Agent"]
