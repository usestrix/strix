"""Tests for opt-in fleet-scale target scoring/dedup (strix.interface.target_triage)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from strix.interface.target_triage import triage_network_targets


if TYPE_CHECKING:
    from collections.abc import Mapping


_FetchResult = tuple[int, dict[str, str], str] | None


def _web(url: str) -> dict[str, Any]:
    return {"type": "web_application", "details": {"target_url": url}, "original": url}


def _local(path: str) -> dict[str, Any]:
    return {"type": "local_code", "details": {"target_path": path}, "original": path}


def _fetcher(responses: Mapping[str, _FetchResult]) -> Any:
    def fetch(url: str, *, timeout: float) -> tuple[int, dict[str, str], str] | None:
        del timeout
        return responses.get(url)

    return fetch


def test_noop_with_fewer_than_two_network_targets() -> None:
    targets = [_web("https://a.tld"), _local("/repo")]
    result = triage_network_targets(targets, fetcher=_fetcher({}))
    assert result == targets
    assert "triage" not in targets[0]["details"]


def test_scores_and_orders_distinct_targets() -> None:
    responses: dict[str, _FetchResult] = {
        "https://weak.tld": (200, {}, "generic default nginx welcome page placeholder text"),
        "https://strong.tld": (
            200,
            {},
            "a distinctive application dashboard with unique inventory management widgets",
        ),
        "https://broken.tld": (500, {}, "internal server error"),
    }
    targets = [_web(u) for u in responses]
    result = triage_network_targets(targets, fetcher=_fetcher(responses))

    scores = [t["details"]["triage"]["score"] for t in result]
    assert scores == sorted(scores, reverse=True)
    assert all(t["details"]["triage"]["near_duplicate_of"] is None for t in result)


def test_waf_detected_lowers_score_relative_to_clean_target() -> None:
    body = "identical marketing landing page content shared across both hosts here"
    responses: dict[str, _FetchResult] = {
        "https://clean.tld": (200, {}, body + " unique-a"),
        "https://waf.tld": (200, {"server": "cloudflare"}, body + " unique-b"),
    }
    targets = [_web("https://waf.tld"), _web("https://clean.tld")]
    result = triage_network_targets(targets, fetcher=_fetcher(responses))

    by_url = {t["original"]: t["details"]["triage"] for t in result}
    assert by_url["https://waf.tld"]["waf_detected"] is not None
    assert by_url["https://clean.tld"]["waf_detected"] is None
    assert by_url["https://clean.tld"]["score"] > by_url["https://waf.tld"]["score"]


def test_near_identical_bodies_flagged_as_duplicate() -> None:
    shared_body = " ".join(f"word{i}" for i in range(500))
    responses: dict[str, _FetchResult] = {
        "https://mirror1.tld": (200, {}, shared_body),
        "https://mirror2.tld": (200, {}, shared_body + " word500"),
        "https://different.tld": (200, {}, "completely unrelated distinctive content only here"),
    }
    targets = [_web(u) for u in responses]
    result = triage_network_targets(targets, fetcher=_fetcher(responses))

    by_url = {t["original"]: t["details"]["triage"] for t in result}
    flagged = [u for u, t in by_url.items() if t["near_duplicate_of"] is not None]
    assert len(flagged) == 1
    assert flagged[0] in ("https://mirror1.tld", "https://mirror2.tld")
    assert by_url["https://different.tld"]["near_duplicate_of"] is None


def test_fetch_failure_scored_last_not_fatal() -> None:
    responses: dict[str, _FetchResult] = {
        "https://up.tld": (200, {}, "a healthy reachable page with real content on it"),
        "https://down.tld": None,
    }
    targets = [_web("https://down.tld"), _web("https://up.tld")]
    result = triage_network_targets(targets, fetcher=_fetcher(responses))

    assert [t["original"] for t in result] == ["https://up.tld", "https://down.tld"]
    assert result[-1]["details"]["triage"]["status"] is None


def test_drop_near_duplicates_removes_lower_scored_twin() -> None:
    shared_body = " ".join(f"tok{i}" for i in range(500))
    responses: dict[str, _FetchResult] = {
        "https://a.tld": (200, {}, shared_body),
        "https://b.tld": (200, {"server": "cloudflare"}, shared_body + " extra"),
    }
    targets = [_web(u) for u in responses]
    result = triage_network_targets(
        targets, fetcher=_fetcher(responses), drop_near_duplicates=True
    )

    assert len(result) == 1
    assert result[0]["original"] == "https://a.tld"


def test_non_network_targets_pass_through_unaffected() -> None:
    responses: dict[str, _FetchResult] = {
        "https://a.tld": (200, {}, "content a is distinct from content b here"),
        "https://b.tld": (200, {}, "content b is distinct from content a there"),
    }
    targets = [_local("/repo"), _web("https://a.tld"), _web("https://b.tld")]
    result = triage_network_targets(targets, fetcher=_fetcher(responses))

    local_entries = [t for t in result if t["type"] == "local_code"]
    assert local_entries == [_local("/repo")]
    assert "triage" not in local_entries[0]["details"]
