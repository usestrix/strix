"""Tier-1 tests for the identity tool surface."""

# ruff: noqa: I001
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any, cast
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, patch


# Mock the agents SDK before importing any report/tool modules.
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

_agents_model_settings: Any = ModuleType("agents.model_settings")


class _ModelSettings:
    pass


_agents_model_settings.ModelSettings = _ModelSettings
sys.modules["agents.model_settings"] = _agents_model_settings
sys.modules["agents"] = _agents
sys.modules["agents.usage"] = _agents_usage

from strix.report.state import (  # noqa: E402
    ReportState,
    get_global_report_state,
    set_global_report_state,
)

# Mock strix.report.dedupe to avoid pulling the full agents model tree in tests.
_dedupe: Any = ModuleType("strix.report.dedupe")


async def _check_duplicate(_candidate: Any, _existing: Any) -> dict[str, Any]:
    return {"is_duplicate": False}


_dedupe.check_duplicate = _check_duplicate
sys.modules["strix.report.dedupe"] = _dedupe

# Replay engine imports caido_sdk_client at module load time; inject a stub.
_CAIDO_MODULES = (
    "caido_sdk_client",
    "caido_sdk_client.api",
    "caido_sdk_client.api.replay",
    "strix.tools.proxy",
    "strix.tools.proxy.caido_api",
)
for _mod in _CAIDO_MODULES:
    if _mod not in sys.modules:
        sys.modules[_mod] = ModuleType(_mod)

_caido_api: Any = sys.modules["strix.tools.proxy.caido_api"]
_caido_api.view_request = AsyncMock(return_value=MagicMock())
_caido_api.get_client = AsyncMock(return_value=MagicMock())
_caido_api.replay_send_raw = AsyncMock(
    return_value={
        "status": "DONE",
        "session_id": "s-1",
        "elapsed_ms": 10,
        "error": None,
        "response_raw": b"HTTP/1.1 200 OK\r\n\r\n{}",
    }
)
_caido_api.parse_raw_response = lambda _: {"status_code": 200, "headers": [], "body": b"{}"}
_caido_api.full_url_from_components = lambda _original, components, _mods: components["url"]
_caido_api.apply_modifications = lambda components, _mods, _full_url: components


class _RawRequest:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.components: dict[str, Any] = {
            "method": "GET",
            "url": "https://example.com/api/users",
            "headers": {
                "Host": "example.com",
                "Cookie": "session=original-session",
                "Authorization": "Bearer ORIGINAL_TOKEN",
                "Content-Type": "application/json",
            },
            "body": "{}",
        }


_caido_api.parse_raw_request = lambda raw: _RawRequest(raw).components


def _build_raw_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: str,
) -> tuple[Any, bytes]:
    raw = (
        f"{method} {url} HTTP/1.1\r\n"
        + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        + "\r\n"
        + (body or "")
    ).encode("utf-8")
    return None, raw


_caido_api.build_raw_request = _build_raw_request

from strix.tools.identity.tools import (  # noqa: E402
    _run_auth_matrix,
    identity_store_list,
    identity_store_upsert,
)

# The real agents.function_tool type stubs make the decorated tools appear
# non-callable to mypy. Cast them to ``Any`` so the tests can call them.
_upsert = cast("Any", identity_store_upsert)
_list = cast("Any", identity_store_list)


class _FakeContext:
    def __init__(self, run_dir: Path) -> None:
        self.context = {"run_dir": str(run_dir)}


class TestIdentityToolsTier1(IsolatedAsyncioTestCase):
    """Focused behaviour tests for the identity tool surface."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"
        self.run_dir.mkdir()
        self.previous_state = get_global_report_state()
        report_state = ReportState(run_name="phase1_test")
        report_state._run_dir = self.run_dir
        set_global_report_state(report_state)

    def tearDown(self) -> None:
        if self.previous_state is not None:
            set_global_report_state(self.previous_state)
        self.tmp.cleanup()

    async def test_identity_store_upsert_and_list(self) -> None:
        ctx = _FakeContext(self.run_dir)
        result = await _upsert(
            ctx,
            "example.com",
            "admin",
            "proxy",
            method="GET",
            url="https://example.com/api/users",
            headers={
                "Authorization": "Bearer admin-token",
                "Cookie": "session=admin-session",
            },
        )
        parsed = json.loads(result)
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["identity"]["role"], "admin")
        self.assertEqual(parsed["identity"]["tokens"]["authorization"], "****")
        self.assertNotIn("admin-token", result)

        listed = await _list(ctx, "example.com")
        listed_parsed = json.loads(listed)
        self.assertTrue(listed_parsed["success"])
        roles = {i["role"] for i in listed_parsed["identities"]}
        self.assertIn("admin", roles)
        self.assertIn("expired", roles)

    async def test_auth_matrix_files_report_with_diff_evidence(self) -> None:
        # Seed the store with an admin identity and a user identity.
        ctx = _FakeContext(self.run_dir)
        await _upsert(
            ctx,
            "example.com",
            "user",
            "proxy",
            method="GET",
            url="https://example.com/api/users",
            headers={"Authorization": "Bearer user-token"},
        )
        await _upsert(
            ctx,
            "example.com",
            "admin",
            "proxy",
            method="GET",
            url="https://example.com/api/users",
            headers={"Authorization": "Bearer admin-token"},
        )

        # All ladder responses are identical (same mocked 200), so the diff engine flags
        # IDOR candidates because every non-anonymous role succeeds with the same response.
        result = await _run_auth_matrix("req-1", "example.com", self.run_dir)
        self.assertTrue(result["success"])
        self.assertGreater(result["finding_count"], 0)
        self.assertTrue(all(r["success"] for r in result["reports"]))

        # Verify evidence_class and artifact attachment on the persisted report.
        report_state = get_global_report_state()
        assert report_state is not None
        self.assertEqual(len(report_state.vulnerability_reports), result["finding_count"])
        for report in report_state.vulnerability_reports:
            self.assertEqual(report["evidence_class"], "diff")
            self.assertIn("artifacts", report)
            artifact_types = {a["artifact_type"] for a in report["artifacts"]}
            self.assertIn("semantic_delta", artifact_types)
            self.assertIn("http_exchange", artifact_types)

    async def test_auth_matrix_empty_diff_no_findings(self) -> None:
        ctx = _FakeContext(self.run_dir)
        await _upsert(
            ctx,
            "example.com",
            "user",
            "proxy",
            method="GET",
            url="https://example.com/api/users",
            headers={"Authorization": "Bearer user-token"},
        )

        with patch("strix.tools.identity.tools.diff") as mock_diff:
            mock_diff.return_value = MagicMock(deltas=[], candidates=[])
            result = await _run_auth_matrix("req-1", "example.com", self.run_dir)

        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["reports"], [])
        report_state = get_global_report_state()
        assert report_state is not None
        self.assertEqual(len(report_state.vulnerability_reports), 0)


if __name__ == "__main__":
    import unittest

    unittest.main()
