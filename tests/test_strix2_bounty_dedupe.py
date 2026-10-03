"""Tests for bug-bounty dedupe: similarity scoring, the store, and report parsing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.bounty.dedupe import (
    KnownReport,
    KnownReportsStore,
    known_reports_from_mapping,
    load_known_reports_file,
    parse_bugcrowd_disclosures,
    parse_hackerone_hacktivity,
    render_dedupe_md,
    similarity,
)
from strix.bounty.loaders.errors import BountyLoadError


_FIXTURES = Path(__file__).parent / "fixtures" / "bounty"


def _reports() -> list[KnownReport]:
    return [
        KnownReport(
            title="SQL injection in the product search endpoint",
            vuln_type="SQL Injection",
            asset="https://shop.acme.com/search",
            state="Resolved",
        ),
        KnownReport(title="Stored XSS via user profile display name", state="Resolved"),
    ]


# --- similarity --------------------------------------------------------------


def test_similar_title_and_asset_scores_as_likely_duplicate() -> None:
    store = KnownReportsStore(_reports())
    result = store.check(
        title="SQLi in product search endpoint",
        asset="https://shop.acme.com/search",
        vuln_type="SQL injection",
    )
    assert result["verdict"] == "likely_duplicate"
    assert result["matches"][0]["title"].startswith("SQL injection")


def test_unrelated_finding_is_novel() -> None:
    store = KnownReportsStore(_reports())
    result = store.check(
        title="Server-side request forgery in the webhook importer",
        asset="https://api.acme.com/webhooks",
        vuln_type="SSRF",
    )
    assert result["verdict"] == "novel"
    assert result["best_score"] < 0.35


def test_empty_store_is_always_novel() -> None:
    result = KnownReportsStore([]).check(title="anything at all")
    assert result["verdict"] == "novel"
    assert result["known_report_count"] == 0


def test_similarity_is_bounded() -> None:
    r = _reports()[0]
    score = similarity(
        r, title=r.title, asset=r.asset, vuln_type=r.vuln_type
    )
    assert 0.0 <= score <= 1.0


# --- parsers / loaders -------------------------------------------------------


def test_parse_hackerone_hacktivity_fixture() -> None:
    payload = json.loads((_FIXTURES / "hackerone_hacktivity.json").read_text(encoding="utf-8"))
    reports = parse_hackerone_hacktivity(payload)
    assert len(reports) == 2
    assert reports[0].title.startswith("SQL injection")
    assert reports[0].source == "hackerone"
    assert reports[0].url == "https://hackerone.com/reports/111111"


def test_parse_bugcrowd_disclosures_both_shapes() -> None:
    flat = parse_bugcrowd_disclosures(
        {
            "disclosures": [
                {"title": "IDOR on invoice download", "target": "acme.com", "vrt": "idor"},
            ]
        }
    )
    assert flat[0].vuln_type == "idor"
    jsonapi = parse_bugcrowd_disclosures(
        {"data": [{"attributes": {"title": "Open redirect in login flow", "severity": "p4"}}]}
    )
    assert jsonapi[0].title == "Open redirect in login flow"
    assert jsonapi[0].severity == "p4"


def test_known_reports_from_mapping_accepts_list_or_wrapper() -> None:
    as_list = known_reports_from_mapping([{"title": "x"}])
    as_wrapped = known_reports_from_mapping({"reports": [{"title": "x"}]})
    assert len(as_list) == len(as_wrapped) == 1


def test_known_reports_bad_shape_raises() -> None:
    with pytest.raises(BountyLoadError):
        known_reports_from_mapping({"nope": 1})


def test_load_known_reports_file_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "known.json"
    path.write_text(json.dumps([{"title": "SSRF in importer"}]), encoding="utf-8")
    reports = load_known_reports_file(path)
    assert reports[0].title == "SSRF in importer"


def test_render_dedupe_md_empty_and_populated() -> None:
    assert "No disclosed reports" in render_dedupe_md([])
    md = render_dedupe_md(_reports())
    assert "SQL injection" in md and "avoid duplicates" in md.lower()
