"""E2E tests for the inventory agent tool surface."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType
from typing import Any
from unittest import IsolatedAsyncioTestCase


# Mock the agents SDK before importing the inventory tool module.
_agents: Any = ModuleType("agents")
_agents_usage: Any = ModuleType("agents.usage")


class _Usage:
    pass


_agents_usage.Usage = _Usage
_agents_usage.serialize_usage = lambda _: {}
_agents_usage.deserialize_usage = lambda _: _Usage()


class _RunContextWrapper:
    def __init__(self, context: dict[str, Any] | None = None) -> None:
        self.context = context or {}


def _function_tool(*, timeout: int = 60, strict_mode: bool = False) -> Any:
    _ = timeout, strict_mode

    def decorator(func: Any) -> Any:
        return func

    return decorator


_agents.RunContextWrapper = _RunContextWrapper
_agents.function_tool = _function_tool
sys.modules["agents"] = _agents
sys.modules["agents.usage"] = _agents_usage

from strix.tools.inventory.tools import (  # noqa: E402
    build_ranked_surface_map,
    classify_inventory_params,
    collect_inventory_from_code,
    load_ranked_surface_map,
    spray_inventory_params,
)


FASTAPI_FIXTURE = """\
from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter(prefix="/items")

@app.get("/")
def read_root():
    return {"message": "hello"}

@router.post("/")
def create_item(name: str, price: float):
    db.execute(\"INSERT INTO items VALUES (?, ?)\", (name, price))
    return {\"created\": True}

app.include_router(router)
"""


def _ctx(run_dir: Path) -> _RunContextWrapper:
    return _RunContextWrapper(context={"run_dir": str(run_dir)})


class TestInventoryTools(IsolatedAsyncioTestCase):
    """End-to-end tool surface: code collection -> ranked map -> classify -> spray."""

    def _write_fixture(self) -> Path:
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "main.py"
        path.write_text(FASTAPI_FIXTURE, encoding="utf-8")
        return path

    async def test_collect_inventory_from_code(self) -> None:
        path = self._write_fixture()
        with TemporaryDirectory() as run_dir:
            ctx = _ctx(Path(run_dir))
            result = await collect_inventory_from_code(
                ctx,
                source_path=str(path),
                target_id="demo",
                base_url="https://api.example.com",
            )
            data = json.loads(result)
            self.assertTrue(data["success"])
            self.assertEqual(data["target_id"], "demo")
            self.assertGreater(data["observations"], 0)

    async def test_full_pipeline(self) -> None:
        path = self._write_fixture()
        with TemporaryDirectory() as run_dir:
            run_dir_path = Path(run_dir)
            ctx = _ctx(run_dir_path)
            collected = await collect_inventory_from_code(
                ctx,
                source_path=str(path),
                target_id="demo",
                base_url="https://api.example.com",
            )
            collected_data = json.loads(collected)
            ranked_result = await build_ranked_surface_map(
                ctx,
                observations=collected_data["items"],
                target_id="demo",
            )
            ranked_data = json.loads(ranked_result)
            self.assertTrue(ranked_data["success"])
            self.assertGreater(ranked_data["endpoints"], 0)

            classify_result = await classify_inventory_params(ctx, target_id="demo")
            classify_data = json.loads(classify_result)
            self.assertTrue(classify_data["success"])

            spray_result = await spray_inventory_params(ctx, target_id="demo")
            spray_data = json.loads(spray_result)
            self.assertTrue(spray_data["success"])
            self.assertIn("spray_plan", spray_data)

            loaded = await load_ranked_surface_map(ctx, target_id="demo")
            loaded_data = json.loads(loaded)
            self.assertTrue(loaded_data["success"])
            self.assertEqual(loaded_data["endpoints"], ranked_data["endpoints"])
