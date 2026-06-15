"""Tier-1 tests for TG6 FastAPI parser + TG7 reachability seam."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import ClassVar

from hypothesis import given
from hypothesis import strategies as st

from strix.core.inventory.collectors.code import collect_code
from strix.core.inventory.parsers.fastapi import collect_routes
from strix.core.inventory.parsers.reachability import (
    analyze_handler,
    analyze_source_tree,
    annotate_reachability,
)


FASTAPI_FIXTURE = """\
from fastapi import APIRouter, Depends, FastAPI

app = FastAPI()
router = APIRouter(prefix="/items")


def get_current_user():
    return {"user_id": 1}


@app.get("/")
def read_root():
    return {"message": "hello"}


@router.get("/")
def list_items(q: str = "", limit: int = 10):
    return []


@router.get("/{item_id}")
def read_item(item_id: int):
    return {"item_id": item_id}


@router.post("/")
def create_item(name: str, price: float):
    db.execute("INSERT INTO items VALUES (?, ?)", (name, price))
    return {"created": True}


@router.put("/{item_id}")
def update_item(item_id: int, name: str):
    return {"item_id": item_id}


@router.delete("/{item_id}")
def delete_item(item_id: int, user=Depends(get_current_user)):
    os.system(f"rm /data/{item_id}")
    return {"deleted": item_id}


app.include_router(router)
"""


_TMP_DIRS: list[TemporaryDirectory[str]] = []


def _write_fixture() -> Path:
    tmp = TemporaryDirectory()
    _TMP_DIRS.append(tmp)
    path = Path(tmp.name) / "main.py"
    path.write_text(FASTAPI_FIXTURE, encoding="utf-8")
    return path


class TestFastAPIParser(unittest.TestCase):
    """TG6: route + method extraction from a synthetic fixture."""

    def test_collects_routes_from_synthetic_fixture(self) -> None:
        path = _write_fixture()
        observations = collect_routes(path, base_url="https://api.example.com")
        keys = {f"{obs.method} {obs.raw_url}" for obs in observations}
        self.assertIn("GET https://api.example.com/", keys)
        self.assertIn("GET https://api.example.com/items/", keys)
        self.assertIn("GET https://api.example.com/items/{item_id}", keys)
        self.assertIn("POST https://api.example.com/items/", keys)
        self.assertIn("PUT https://api.example.com/items/{item_id}", keys)
        self.assertIn("DELETE https://api.example.com/items/{item_id}", keys)

    def test_extracts_path_params(self) -> None:
        path = _write_fixture()
        observations = collect_routes(path, base_url="https://api.example.com")
        by_url = {obs.raw_url: obs for obs in observations}
        self.assertIn("item_id", by_url["https://api.example.com/items/{item_id}"].params)

    def test_collect_code_uses_fastapi_parser(self) -> None:
        path = _write_fixture()
        observations = collect_code(path, base_url="https://api.example.com")
        self.assertTrue(all(obs.source == "code" for obs in observations))
        self.assertGreater(len(observations), 0)


class TestReachabilityAnalyzer(unittest.TestCase):
    """TG7: route-to-handler-to-sink reachability seam."""

    def test_static_handler_is_unreachable(self) -> None:
        source = """@app.get("/")
def read_root():
    return {"message": "hello"}
"""
        result = analyze_handler(source, 0)
        self.assertEqual(result.status, "unreachable")
        self.assertEqual(result.sinks, [])

    def test_database_sink_is_reachable(self) -> None:
        source = """@app.post("/items")
def create_item(name: str):
    db.execute("INSERT INTO items VALUES (?)", (name,))
    return {"created": True}
"""
        result = analyze_handler(source, 0)
        self.assertEqual(result.status, "reachable")
        self.assertIn("database", result.sinks)

    def test_os_command_sink_is_reachable(self) -> None:
        source = """@app.delete("/items/{item_id}")
def delete_item(item_id: int, user=Depends(get_current_user)):
    os.system(f"rm /data/{item_id}")
    return {"deleted": item_id}
"""
        result = analyze_handler(source, 0)
        self.assertEqual(result.status, "reachable")
        self.assertIn("os_command", result.sinks)
        self.assertTrue(result.auth_required)

    def test_unknown_when_handler_missing(self) -> None:
        result = analyze_handler("no decorator here", 0)
        self.assertEqual(result.status, "unknown")

    def test_analyze_source_tree_maps_keys(self) -> None:
        path = _write_fixture()
        results = analyze_source_tree(path)
        self.assertIn("POST /items/", results)
        self.assertEqual(results["POST /items/"].status, "reachable")
        self.assertEqual(results["GET /"].status, "unreachable")

    def test_annotate_reachability_attaches_to_observations(self) -> None:
        path = _write_fixture()
        observations = collect_routes(path, base_url="https://api.example.com")
        annotate_reachability(observations)
        by_url = {obs.raw_url: obs for obs in observations}
        items_obs = by_url["https://api.example.com/items/"]
        self.assertIsNotNone(items_obs.reachability)
        self.assertEqual(items_obs.reachability.status, "reachable")  # type: ignore[union-attr]
        self.assertIn("database", items_obs.reachability.path)  # type: ignore[union-attr,arg-type]
        root_obs = by_url["https://api.example.com/"]
        self.assertIsNotNone(root_obs.reachability)
        self.assertEqual(root_obs.reachability.status, "unreachable")  # type: ignore[union-attr]


class TestReachabilitySoundnessPBT(unittest.TestCase):
    """7.6: reachable status must carry a concrete sink path."""

    _SINK_SNIPPETS: ClassVar[list[str]] = [
        "cursor.execute(q)",
        "os.system(cmd)",
        "open(p)",
        "requests.get(u)",
    ]
    _SAFE_SNIPPETS: ClassVar[list[str]] = [
        "return 1",
        "x = a + b",
        "logger.info(msg)",
    ]

    @given(st.lists(st.sampled_from(_SINK_SNIPPETS + _SAFE_SNIPPETS), max_size=6))
    def test_reachable_always_carries_a_path(self, lines: list[str]) -> None:
        body = "\n".join(lines)
        result = analyze_handler(body, 0)
        self.assertIn(result.status, {"reachable", "unreachable", "unknown"})
        if result.status == "reachable":
            self.assertTrue(result.sinks, "reachable status with empty path violates 7.6")
