"""Tests for the Strix 2 finding-annotation sidecar (schema, store, registration, writer)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from strix.agents.factory import registered_agent_tools
from strix.findings2.schema import FindingAnnotation, invalid_mitre_ids, parse_ids
from strix.findings2.store import (
    FindingAnnotationStore,
    get_annotation_store,
    reset_annotation_store,
    set_annotation_store,
)
from strix.findings2.writer import render_framework_map
from strix.strix2_ext import install_strix2_extensions


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture(autouse=True)
def _reset() -> Iterator[None]:
    saved = get_annotation_store()
    set_annotation_store(None)
    try:
        yield
    finally:
        set_annotation_store(saved)


# --- schema ------------------------------------------------------------------

def test_parse_ids_splits_and_dedupes() -> None:
    assert parse_ids("T1530, T1078  T1530") == ["T1530", "T1078"]
    assert parse_ids("") == []


def test_invalid_mitre_ids() -> None:
    assert invalid_mitre_ids(["T1530", "T1078.001"]) == []
    assert invalid_mitre_ids(["T1530", "nope", "1234"]) == ["nope", "1234"]


def test_annotation_rejects_malformed_mitre() -> None:
    with pytest.raises(ValueError):  # pydantic raises a ValueError subclass
        FindingAnnotation(vuln_report_id="vuln-0001", mitre_attack=["bad"])


# --- store -------------------------------------------------------------------

def test_upsert_creates_and_persists(tmp_path: Path) -> None:
    store = FindingAnnotationStore(run_dir=tmp_path)
    ann = store.upsert(
        vuln_report_id="vuln-0001", domain="cloud", mitre_attack=["T1530"], notes="public s3 read"
    )
    assert ann.domain == "cloud"
    assert ann.mitre_attack == ["T1530"]
    data = json.loads((tmp_path / "finding_annotations.json").read_text(encoding="utf-8"))
    assert data[0]["vuln_report_id"] == "vuln-0001"
    assert (tmp_path / "FRAMEWORK_MAP.md").exists()


def test_upsert_merges_tags_and_keys_by_report(tmp_path: Path) -> None:
    store = FindingAnnotationStore(run_dir=tmp_path)
    store.upsert(vuln_report_id="vuln-0001", mitre_attack=["T1530"], cis_benchmark=["CIS 2.1.5"])
    merged = store.upsert(
        vuln_report_id="vuln-0001", domain="cloud", mitre_attack=["T1078"], notes="x"
    )
    assert merged.mitre_attack == ["T1530", "T1078"]  # accumulated
    assert merged.cis_benchmark == ["CIS 2.1.5"]  # preserved
    assert merged.domain == "cloud"  # filled in
    assert merged.notes == "x"
    assert len(store.all_annotations()) == 1  # one per report id


def test_reset_rebinds_on_new_run(tmp_path: Path) -> None:
    a = reset_annotation_store(tmp_path / "A")
    same = reset_annotation_store(tmp_path / "A")
    other = reset_annotation_store(tmp_path / "B")
    assert a is same
    assert other is not a


# --- registration ------------------------------------------------------------

def test_install_registers_annotation_tools(tmp_path: Path) -> None:
    install_strix2_extensions(tmp_path)
    names = {t.name for t in registered_agent_tools()}
    assert {"annotate_finding", "list_finding_annotations"} <= names
    store = get_annotation_store()
    assert store is not None
    assert store.run_dir == tmp_path


# --- writer ------------------------------------------------------------------

def test_render_framework_map() -> None:
    assert "No finding annotations" in render_framework_map([])
    ann = FindingAnnotation(vuln_report_id="vuln-0001", domain="network", mitre_attack=["T1046"])
    out = render_framework_map([ann])
    assert "vuln-0001" in out
    assert "T1046" in out
    assert "network" in out
