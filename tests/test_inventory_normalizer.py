"""Tier-1 + PBT tests for Phase 3 normalizer and dedup."""

from __future__ import annotations

import unittest

from hypothesis import given
from hypothesis import strategies as st

from strix.core.inventory.models import EndpointObservation, ParamObservation
from strix.core.inventory.normalizer import (
    dedup_endpoints,
    dedup_observations,
    endpoint_key,
    normalize_observation,
)


def _observation_from_tuple(data: tuple[str, str, str]) -> EndpointObservation:
    method, raw_url, source = data
    return EndpointObservation(
        method=method,
        raw_url=raw_url,
        source=source,  # type: ignore[arg-type]
    )


class TestNormalizer(unittest.TestCase):
    """Canonicalization rules are applied and recorded."""

    def test_noise_equivalent_urls_share_key(self) -> None:
        observations = [
            EndpointObservation(
                method="GET",
                raw_url="HTTPS://Api.Example.COM:443/users/123/?foo=1&bar=2",
                source="sitemap",
            ),
            EndpointObservation(
                method="get",
                raw_url="https://api.example.com/users/456/?bar=2&foo=1",
                source="js",
            ),
        ]

        endpoints = dedup_observations(observations)

        self.assertEqual(len(endpoints), 1)
        endpoint = next(iter(endpoints.values()))
        self.assertEqual(endpoint.method, "GET")
        self.assertEqual(endpoint.url, "https://api.example.com/users/{id}?bar=2&foo=1")
        self.assertEqual(endpoint.sources, {"sitemap", "js"})
        self.assertIn("host_lowercase", endpoint.normalization_rules)
        self.assertIn("default_port_stripped", endpoint.normalization_rules)
        self.assertIn("path_id_templated", endpoint.normalization_rules)
        self.assertIn("query_sorted", endpoint.normalization_rules)
        self.assertIn("foo", endpoint.params)
        self.assertIn("bar", endpoint.params)

    def test_single_observation_keeps_source(self) -> None:
        obs = EndpointObservation(
            method="POST",
            raw_url="http://example.com/api/v1/items/",
            source="ffuf",
        )
        endpoint = normalize_observation(obs)
        self.assertEqual(endpoint.sources, {"ffuf"})
        self.assertEqual(endpoint.url, "http://example.com/api/v1/items")
        self.assertIn("trailing_slash_removed", endpoint.normalization_rules)

    def test_endpoint_key_matches_method_and_canonical_url(self) -> None:
        self.assertEqual(
            endpoint_key("GET", "https://api.example.com/users"),
            "GET https://api.example.com/users",
        )


class TestDedup(unittest.TestCase):
    """Merge behavior and idempotence."""

    def test_merge_unions_sources_and_params(self) -> None:
        observations = [
            EndpointObservation(
                method="GET",
                raw_url="https://api.example.com/users/123",
                params={"q": ParamObservation(name="q", location="query")},
                source="sitemap",
            ),
            EndpointObservation(
                method="GET",
                raw_url="https://api.example.com/users/456",
                params={"limit": ParamObservation(name="limit", location="query")},
                source="js",
            ),
        ]

        endpoints = dedup_observations(observations)

        self.assertEqual(len(endpoints), 1)
        endpoint = next(iter(endpoints.values()))
        self.assertEqual(endpoint.sources, {"sitemap", "js"})
        self.assertEqual(set(endpoint.params), {"q", "limit"})

    def test_dedup_is_idempotent(self) -> None:
        observations = [
            EndpointObservation(method="GET", raw_url="https://a.com/x", source="js"),
            EndpointObservation(method="GET", raw_url="https://a.com/y", source="katana"),
            EndpointObservation(method="GET", raw_url="https://a.com/x", source="sitemap"),
        ]
        once = dedup_observations(observations)
        twice = dedup_endpoints(once)
        self.assertEqual(sorted(once), sorted(twice))
        for key in once:
            self.assertEqual(
                sorted(once[key].sources),
                sorted(twice[key].sources),
            )


class TestDedupPBT(unittest.TestCase):
    """Property-based invariants for the join point."""

    @given(
        st.lists(
            st.tuples(
                st.sampled_from(["GET", "POST"]),
                st.sampled_from(
                    [
                        "https://api.example.com/users/1",
                        "https://api.example.com/users/2",
                        "https://api.example.com/items",
                        "https://api.example.com/items/abc",
                    ]
                ),
                st.sampled_from(["sitemap", "js", "ffuf", "katana"]),
            ),
            min_size=0,
            max_size=30,
        )
    )
    def test_dedup_idempotence(self, fixture: list[tuple[str, str, str]]) -> None:
        observations = [_observation_from_tuple(t) for t in fixture]
        once = dedup_observations(observations)
        twice = dedup_endpoints(once)
        self.assertEqual(set(once), set(twice))

    @given(
        st.lists(
            st.tuples(
                st.sampled_from(["GET", "POST"]),
                st.sampled_from(
                    [
                        "https://api.example.com/users/1",
                        "https://api.example.com/users/2",
                        "https://api.example.com/items",
                    ]
                ),
                st.sampled_from(["sitemap", "js", "ffuf"]),
            ),
            min_size=1,
            max_size=30,
        )
    )
    def test_provenance_completeness(self, fixture: list[tuple[str, str, str]]) -> None:
        observations = [_observation_from_tuple(t) for t in fixture]
        endpoints = dedup_observations(observations)
        for endpoint in endpoints.values():
            self.assertTrue(endpoint.sources)
