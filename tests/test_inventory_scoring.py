"""Tier-1 + PBT tests for Phase 3 scoring and ranked map."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from hypothesis import given
from hypothesis import strategies as st

from strix.core.inventory.models import Endpoint, Param, ReachabilityAnnotation
from strix.core.inventory.scoring import (
    build_ranked_map,
    extract_signals,
    score_endpoint,
    score_signals,
)
from strix.core.inventory.store import load_ranked_map, save_ranked_map


_ALL_SIGNALS = {
    "auth-required",
    "object-ref",
    "state-changing-verb",
    "upload",
    "source-multiplicity",
    "reachable-sink",
}


class TestScoringSignals(unittest.TestCase):
    """Signal extraction covers the fixed attack-surface signal set."""

    def test_auth_required_from_path(self) -> None:
        endpoint = Endpoint(key="k", method="GET", url="https://api.example.com/login")
        signals = extract_signals(endpoint)
        self.assertIn("auth-required", signals)

    def test_object_ref_from_templated_path(self) -> None:
        endpoint = Endpoint(key="k", method="GET", url="https://api.example.com/users/{id}")
        signals = extract_signals(endpoint)
        self.assertIn("object-ref", signals)

    def test_state_changing_verb(self) -> None:
        endpoint = Endpoint(key="k", method="POST", url="https://api.example.com/users")
        signals = extract_signals(endpoint)
        self.assertIn("state-changing-verb", signals)

    def test_upload_signal(self) -> None:
        endpoint = Endpoint(
            key="k",
            method="POST",
            url="https://api.example.com/upload",
            params={"file": Param(name="file", location="body")},
        )
        signals = extract_signals(endpoint)
        self.assertIn("upload", signals)

    def test_source_multiplicity(self) -> None:
        endpoint = Endpoint(key="k", method="GET", url="https://api.example.com/users")
        endpoint.sources = {"sitemap", "js"}
        signals = extract_signals(endpoint)
        self.assertIn("source-multiplicity", signals)

    def test_reachable_sink(self) -> None:
        endpoint = Endpoint(key="k", method="GET", url="https://api.example.com/users")
        endpoint.reachability = ReachabilityAnnotation(
            status="reachable", path=["route", "handler"]
        )
        signals = extract_signals(endpoint)
        self.assertIn("reachable-sink", signals)


class TestScoringMonotonicity(unittest.TestCase):
    """Adding signals never lowers the score."""

    def test_strict_superset_scores_at_or_above(self) -> None:
        base_signals = {"auth-required"}
        extra_signals = {"auth-required", "state-changing-verb", "object-ref"}
        self.assertGreaterEqual(
            score_signals(extra_signals),
            score_signals(base_signals),
        )

    def test_score_endpoint_records_signals_and_score(self) -> None:
        endpoint = Endpoint(
            key="k",
            method="POST",
            url="https://api.example.com/users/{id}",
        )
        score = score_endpoint(endpoint)
        self.assertGreater(score, 0)
        self.assertIn("state-changing-verb", endpoint.signals)
        self.assertIn("object-ref", endpoint.signals)
        self.assertEqual(endpoint.score, score)

    def test_ranked_map_orders_by_score(self) -> None:
        low = Endpoint(key="low", method="GET", url="https://api.example.com/static")
        high = Endpoint(
            key="high",
            method="POST",
            url="https://api.example.com/users/{id}",
            sources={"sitemap", "js"},
        )
        ranked = build_ranked_map("target-1", {"low": low, "high": high})
        ordered = ranked.sorted_endpoints()
        self.assertEqual(ordered[0].key, "high")
        self.assertGreater(ordered[0].score, ordered[1].score)


class TestStore(unittest.TestCase):
    """Ranked map persists and reloads."""

    def test_save_and_load_roundtrip(self) -> None:
        with TemporaryDirectory() as run_dir:
            run_dir_path = Path(run_dir)
            endpoint = Endpoint(key="k", method="GET", url="https://api.example.com/users")
            score_endpoint(endpoint)
            ranked = build_ranked_map("target-1", {"k": endpoint})

            path = save_ranked_map(run_dir_path, ranked)
            loaded = load_ranked_map(run_dir_path, "target-1")

            self.assertEqual(loaded.target_id, "target-1")
            self.assertEqual(set(loaded.endpoints), {"k"})
            self.assertEqual(loaded.endpoints["k"].score, endpoint.score)
            self.assertTrue(path.exists())

    def test_load_missing_returns_empty_map(self) -> None:
        with TemporaryDirectory() as run_dir:
            loaded = load_ranked_map(Path(run_dir), "target-x")
            self.assertEqual(loaded.target_id, "target-x")
            self.assertEqual(loaded.endpoints, {})


class TestScoringPBT(unittest.TestCase):
    """Property-based scoring monotonicity."""

    @given(
        st.sets(st.sampled_from(list(_ALL_SIGNALS))),
        st.sets(st.sampled_from(list(_ALL_SIGNALS))),
    )
    def test_monotonicity(self, signals_a: set[str], signals_b: set[str]) -> None:
        if signals_a > signals_b:
            self.assertGreaterEqual(
                score_signals(signals_a),
                score_signals(signals_b),
            )
        elif signals_b > signals_a:
            self.assertGreaterEqual(
                score_signals(signals_b),
                score_signals(signals_a),
            )
