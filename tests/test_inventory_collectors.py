"""Tier-1 tests for Phase 3 inventory source collectors."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING

from strix.core.inventory.collectors import (
    collect_arjun,
    collect_code,
    collect_ffuf,
    collect_httpx,
    collect_js,
    collect_katana,
    collect_sitemap,
)


if TYPE_CHECKING:
    from collections.abc import Callable

    from strix.core.inventory.models import EndpointObservation


class TestSitemapCollector(unittest.TestCase):
    """Sitemap entries produce EndpointObservations with the right shape."""

    def test_collects_request_entries_with_source_tag(self) -> None:
        entries = [
            {
                "id": "dom-1",
                "kind": "DOMAIN",
                "label": "api.example.com",
                "has_descendants": True,
                "metadata": {"is_tls": True, "port": 443},
                "request": {"method": "GET", "path": "/users", "status_code": 200},
            },
            {
                "id": "req-1",
                "kind": "REQUEST",
                "label": "/users/123",
                "has_descendants": False,
                "request": {"method": "POST", "path": "/users/123?foo=bar", "status_code": 201},
            },
        ]

        observations = collect_sitemap(entries, default_host="api.example.com")

        self.assertEqual(len(observations), 2)
        self.assertTrue(all(obs.source == "sitemap" for obs in observations))
        self.assertEqual(observations[0].method, "GET")
        self.assertEqual(observations[0].raw_url, "https://api.example.com/users")
        self.assertEqual(observations[1].method, "POST")
        self.assertEqual(observations[1].raw_url, "http://api.example.com/users/123?foo=bar")
        self.assertIn("foo", observations[1].params)

    def test_omits_entries_without_request(self) -> None:
        entries = [
            {
                "id": "dir-1",
                "kind": "DIRECTORY",
                "label": "/static",
                "has_descendants": True,
            },
        ]
        self.assertEqual(collect_sitemap(entries, default_host="api.example.com"), [])


class TestExternalToolCollectors(unittest.TestCase):
    """External tool outputs parse to the common EndpointObservation shape."""

    FFUF_OUTPUT = """{
        "results": [
            {"url": "https://api.example.com/admin", "method": "GET", "status": 200},
            {"url": "https://api.example.com/login", "method": "POST", "status": 200}
        ]
    }"""

    KATANA_OUTPUT = """
    {"url": "https://api.example.com/api/v1/items", "method": "GET", "source": "crawler"}
    {"url": "https://api.example.com/api/v1/items/1", "method": "GET", "source": "crawler"}
    """

    ARJUN_OUTPUT = """{
        "https://api.example.com/search": ["q", "limit"],
        "https://api.example.com/users": ["id"]
    }"""

    HTTPX_OUTPUT = """
    {"url": "https://api.example.com/health", "method": "GET", "status_code": 200, "title": "OK"}
    {"url": "https://api.example.com/upload", "method": "POST", "status_code": 200}
    """

    def _assert_tool_shape(
        self,
        collector: Callable[[str], list[EndpointObservation]],
        output_text: str,
        source: str,
    ) -> None:
        observations = collector(output_text)
        self.assertTrue(observations, f"{source} produced no observations")
        self.assertTrue(all(obs.source == source for obs in observations))
        self.assertTrue(
            all(obs.raw_url.startswith("https://api.example.com") for obs in observations)
        )

    def test_ffuf_emits_single_source_shape(self) -> None:
        self._assert_tool_shape(collect_ffuf, self.FFUF_OUTPUT, "ffuf")

    def test_katana_emits_single_source_shape(self) -> None:
        self._assert_tool_shape(collect_katana, self.KATANA_OUTPUT, "katana")

    def test_arjun_emits_single_source_shape(self) -> None:
        self._assert_tool_shape(collect_arjun, self.ARJUN_OUTPUT, "arjun")

    def test_httpx_emits_single_source_shape(self) -> None:
        self._assert_tool_shape(collect_httpx, self.HTTPX_OUTPUT, "httpx")

    def test_ffuf_returns_sanitized_evidence(self) -> None:
        observations = collect_ffuf(self.FFUF_OUTPUT)
        for obs in observations:
            self.assertIn("status", obs.raw_evidence)
            self.assertNotIn("raw_stderr", obs.raw_evidence)


class TestJSCollector(unittest.TestCase):
    """JS route hints become GET observations."""

    def test_relative_routes_joined_to_base_url(self) -> None:
        observations = collect_js(
            ["/api/users", "/api/users/{id}", "https://api.example.com/legacy"],
            base_url="https://api.example.com",
        )
        self.assertEqual(len(observations), 3)
        self.assertTrue(all(obs.source == "js" for obs in observations))
        self.assertTrue(all(obs.method == "GET" for obs in observations))
        self.assertEqual(observations[0].raw_url, "https://api.example.com/api/users")


class TestCodeCollector(unittest.TestCase):
    """FastAPI source tree yields code observations."""

    FASTAPI_SOURCE = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
def list_users():
    return []

@app.post("/users/{user_id}")
def update_user(user_id: int):
    return {}
"""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def test_fastapi_fixture_yields_routes(self) -> None:
        src = self._temp_fastapi_file()
        observations = collect_code(src, base_url="https://api.example.com")

        self.assertEqual(len(observations), 2)
        self.assertTrue(all(obs.source == "code" for obs in observations))
        methods = {obs.method for obs in observations}
        self.assertEqual(methods, {"GET", "POST"})
        urls = {obs.raw_url for obs in observations}
        self.assertEqual(
            urls,
            {
                "https://api.example.com/users",
                "https://api.example.com/users/{user_id}",
            },
        )

    def _temp_fastapi_file(self) -> Path:
        """Return a temporary file path with the FastAPI fixture written."""
        path = Path(self._tmp.name) / "strix_inventory_fastapi_fixture.py"
        path.write_text(self.FASTAPI_SOURCE)
        return path

    def tearDown(self) -> None:
        pass


class TestScopeBounding(unittest.TestCase):
    """Collectors drop out-of-scope observations."""

    def test_scope_rules_filter_hosts(self) -> None:
        entries = [
            {
                "id": "in-scope",
                "kind": "REQUEST",
                "label": "/users",
                "has_descendants": False,
                "request": {"method": "GET", "path": "/users"},
            },
        ]
        in_scope = collect_sitemap(
            entries,
            default_host="api.example.com",
            scope_rules=["api.example.com"],
        )
        out_of_scope = collect_sitemap(
            entries,
            default_host="evil.com",
            scope_rules=["api.example.com"],
        )
        self.assertEqual(len(in_scope), 1)
        self.assertEqual(out_of_scope, [])
