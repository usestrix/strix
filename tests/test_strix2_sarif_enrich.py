"""Tests for folding finding-annotation tags into the written SARIF (Phase 4)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from strix.findings2.sarif_enrich import (
    enrich_run_sarif,
    enrich_sarif_document,
    enrich_sarif_file,
)
from strix.findings2.schema import FindingAnnotation
from strix.findings2.store import reset_annotation_store, set_annotation_store
from strix.report.sarif import build_sarif_report, write_sarif


if TYPE_CHECKING:
    from pathlib import Path


def _annotation(vuln_id: str, **kwargs: Any) -> FindingAnnotation:
    return FindingAnnotation(vuln_report_id=vuln_id, **kwargs)


def _finding(fid: str, cwe: str = "CWE-284") -> dict[str, Any]:
    return {
        "id": fid,
        "title": "Public S3 object readable",
        "description": "An object in a private bucket is world-readable.",
        "severity": "high",
        "cwe": cwe,
        "target": "s3://bucket/secret.txt",
    }


def _rule_tags(sarif: dict[str, Any]) -> list[str]:
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    return [tag for rule in rules for tag in rule.get("properties", {}).get("tags", [])]


# --- pure document enrichment ------------------------------------------------

def test_enrich_adds_tags_and_frameworks_block() -> None:
    sarif = build_sarif_report([_finding("vuln-0001")])
    ann = {"vuln-0001": _annotation("vuln-0001", mitre_attack=["T1530"], domain="cloud")}
    assert enrich_sarif_document(sarif, ann) is True

    tags = _rule_tags(sarif)
    assert "mitre:T1530" in tags
    assert "domain:cloud" in tags
    frameworks = sarif["runs"][0]["results"][0]["properties"]["strix"]["frameworks"]
    assert frameworks["mitre_attack"] == ["T1530"]
    assert frameworks["domain"] == "cloud"


def test_enrich_no_annotations_is_noop() -> None:
    sarif = build_sarif_report([_finding("vuln-0001")])
    before = json.dumps(sarif, sort_keys=True)
    assert enrich_sarif_document(sarif, {}) is False
    assert json.dumps(sarif, sort_keys=True) == before


def test_enrich_unmatched_finding_untouched() -> None:
    sarif = build_sarif_report([_finding("vuln-0001")])
    ann = {"vuln-9999": _annotation("vuln-9999", mitre_attack=["T1078"])}
    assert enrich_sarif_document(sarif, ann) is False
    assert "mitre:T1078" not in _rule_tags(sarif)


def test_enrich_adds_cis_tags() -> None:
    sarif = build_sarif_report([_finding("vuln-0001")])
    ann = {"vuln-0001": _annotation("vuln-0001", cis_benchmark=["CIS AWS 2.1.5"])}
    assert enrich_sarif_document(sarif, ann) is True
    assert "cis:CIS AWS 2.1.5" in _rule_tags(sarif)


# --- file round-trip ---------------------------------------------------------

def test_enrich_file_roundtrip_and_idempotent(tmp_path: Path) -> None:
    out = write_sarif(tmp_path, [_finding("vuln-0001")])
    ann = {"vuln-0001": _annotation("vuln-0001", mitre_attack=["T1530"])}

    assert enrich_sarif_file(out, ann) is True
    reloaded = json.loads(out.read_text(encoding="utf-8"))
    assert "mitre:T1530" in _rule_tags(reloaded)

    # Second pass makes no change (already enriched) and leaves no temp files.
    assert enrich_sarif_file(out, ann) is False
    assert list(tmp_path.glob("*.tmp")) == []


def test_enrich_file_missing_is_noop(tmp_path: Path) -> None:
    ann = {"vuln-0001": _annotation("vuln-0001", mitre_attack=["T1530"])}
    assert enrich_sarif_file(tmp_path / "nope.sarif", ann) is False


# --- end-to-end through the run store ----------------------------------------

def test_enrich_run_sarif_from_store(tmp_path: Path) -> None:
    write_sarif(tmp_path, [_finding("vuln-0001")])
    store = reset_annotation_store(tmp_path)
    store.upsert(vuln_report_id="vuln-0001", domain="cloud", mitre_attack=["T1530"])
    try:
        assert enrich_run_sarif(tmp_path) is True
        reloaded = json.loads((tmp_path / "findings.sarif").read_text(encoding="utf-8"))
        assert "mitre:T1530" in _rule_tags(reloaded)
        assert "domain:cloud" in _rule_tags(reloaded)
    finally:
        set_annotation_store(None)


def test_enrich_run_sarif_no_store_is_noop(tmp_path: Path) -> None:
    write_sarif(tmp_path, [_finding("vuln-0001")])
    set_annotation_store(None)
    assert enrich_run_sarif(tmp_path) is False
