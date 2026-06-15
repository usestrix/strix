"""Tier-1 and Tier-2 tests for the identity-aware replay engine."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from types import ModuleType
from typing import Any
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, MagicMock, patch

from hypothesis import given, settings
from hypothesis import strategies as st

from strix.core.identity.capture import capture_from_proxy
from strix.core.identity.models import Freshness, Identity


# The replay engine imports caido_sdk_client at module load time. In test
# environments without the SDK installed we inject a minimal stub that exposes
# the same public surface used by the engine.
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
                "X-Api-Key": "original-api-key",
                "Content-Type": "application/json",
            },
            "body": "{}",
        }


def _parse_raw_request(raw: bytes) -> dict[str, Any]:
    return _RawRequest(raw).components


def _parse_raw_response(_raw: bytes) -> dict[str, Any]:
    return {"status_code": 200, "headers": [], "body": b"{}"}


def _full_url_from_components(
    _original: Any, components: dict[str, Any], _mods: dict[str, Any] | None
) -> Any:
    return components["url"]


def _apply_modifications(
    components: dict[str, Any],
    _mods: dict[str, Any] | None,
    _full_url: str,
) -> dict[str, Any]:
    return components


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


_caido_api.parse_raw_request = _parse_raw_request
_caido_api.parse_raw_response = _parse_raw_response
_caido_api.full_url_from_components = _full_url_from_components
_caido_api.apply_modifications = _apply_modifications
_caido_api.build_raw_request = _build_raw_request


from strix.core.identity.replay import (  # noqa: E402
    _overlay_identity_auth,
    _strip_original_auth,
    replay_as_identity,
    replay_ladder,
)


def _mock_view_request() -> Any:
    result = MagicMock()
    result.request.raw = b"placeholder"
    return result


class TestReplayEngineTier1(IsolatedAsyncioTestCase):
    """Focused behaviour tests for replay-as-identity."""

    async def test_replay_substitutes_identity_creds(self) -> None:
        identity = capture_from_proxy(
            "example.com",
            "admin",
            method="GET",
            url="https://example.com/api/users",
            headers={
                "Authorization": "Bearer admin-token",
                "Cookie": "session=admin",
            },
            body="{}",
        )
        captured_raw: str | None = None

        async def fake_view_request(_request_id: str, **_: Any) -> Any:
            return _mock_view_request()

        async def fake_replay_send_raw(
            _client: Any, *, raw: bytes, connection: Any
        ) -> dict[str, Any]:
            nonlocal captured_raw
            _ = connection
            captured_raw = raw.decode("utf-8")
            return {
                "status": "DONE",
                "session_id": "s-1",
                "elapsed_ms": 10,
                "error": None,
                "response_raw": b"HTTP/1.1 200 OK\r\n\r\n{}",
            }

        with (
            patch(
                "strix.core.identity.replay.caido_api.view_request",
                side_effect=fake_view_request,
            ),
            patch(
                "strix.core.identity.replay.caido_api.get_client",
                new=AsyncMock(),
            ),
            patch(
                "strix.core.identity.replay.caido_api.replay_send_raw",
                side_effect=fake_replay_send_raw,
            ),
        ):
            result = await replay_as_identity("req-1", identity)

        assert captured_raw is not None
        self.assertIn(identity.tokens["authorization"], captured_raw)
        self.assertIn("Cookie: session=admin", captured_raw)
        self.assertNotIn("Bearer ORIGINAL_TOKEN", captured_raw)
        self.assertNotIn("original-session", captured_raw)
        self.assertTrue(result["success"])
        self.assertEqual(result["response"]["status_code"], 200)

    async def test_replay_ladder_returns_one_cell_per_identity(self) -> None:
        identities = [
            capture_from_proxy(
                "example.com",
                role,
                method="GET",
                url="https://example.com/api/users",
                headers={"Authorization": f"Bearer {role}-token"},
                body="{}",
            )
            for role in ("anonymous", "user", "admin", "expired")
        ]
        call_count = 0

        async def fake_view_request(_request_id: str, **_: Any) -> Any:
            return _mock_view_request()

        async def fake_replay_send_raw(
            _client: Any, *, raw: bytes, connection: Any
        ) -> dict[str, Any]:
            nonlocal call_count
            _ = raw, connection
            call_count += 1
            return {
                "status": "DONE",
                "session_id": f"s-{call_count}",
                "elapsed_ms": 10,
                "error": None,
                "response_raw": b"HTTP/1.1 200 OK\r\n\r\n{}",
            }

        with (
            patch(
                "strix.core.identity.replay.caido_api.view_request",
                side_effect=fake_view_request,
            ),
            patch(
                "strix.core.identity.replay.caido_api.get_client",
                new=AsyncMock(),
            ),
            patch(
                "strix.core.identity.replay.caido_api.replay_send_raw",
                side_effect=fake_replay_send_raw,
            ),
        ):
            result = await replay_ladder("req-1", identities)

        self.assertEqual(len(result["results"]), 4)
        self.assertEqual(result["failures"], [])
        self.assertEqual(call_count, 4)
        roles = {r["identity"] for r in result["results"]}
        self.assertEqual(roles, {"anonymous", "user", "admin", "expired"})

    async def test_replay_failure_surfaces_per_identity(self) -> None:
        identity = capture_from_proxy(
            "example.com",
            "user",
            method="GET",
            url="https://example.com/api/users",
            headers={"Authorization": "Bearer user-token"},
            body="{}",
        )

        async def fake_view_request(_request_id: str, **_: Any) -> Any:
            raise RuntimeError("Caido unreachable")

        with (
            patch(
                "strix.core.identity.replay.caido_api.view_request",
                side_effect=fake_view_request,
            ),
            patch(
                "strix.core.identity.replay.caido_api.get_client",
                new=AsyncMock(),
            ),
        ):
            result = await replay_ladder("req-1", [identity])

        self.assertEqual(len(result["results"]), 0)
        self.assertEqual(len(result["failures"]), 1)
        self.assertEqual(result["failures"][0]["identity"], "user")
        self.assertFalse(result["success"])


class TestReplayEngineTier2PBT(TestCase):
    """Property-based invariants for replay auth substitution."""

    _ALPHANUMERIC = st.characters(whitelist_categories=("L", "N"))
    _SAFE_TEXT = st.text(min_size=1, max_size=32, alphabet=_ALPHANUMERIC)

    @given(
        cookie_name=_SAFE_TEXT,
        cookie_value=_SAFE_TEXT,
        token=_SAFE_TEXT,
        header_name=_SAFE_TEXT,
        header_value=_SAFE_TEXT,
    )
    @settings(max_examples=50, deadline=None)
    def test_replay_fidelity_strip_then_overlay(
        self,
        cookie_name: str,
        cookie_value: str,
        token: str,
        header_name: str,
        header_value: str,
    ) -> None:
        # forall r,i: replay(r,i) carries exactly i's auth material and none of r's.
        identity = Identity(
            target_key="example.com",
            role="user",
            cookies={cookie_name: cookie_value},
            tokens={"authorization": f"Bearer {token}"},
            headers={header_name: header_value},
            provenance="proxy_capture",
            freshness=Freshness(captured_at=datetime.now(UTC).isoformat(), status="fresh"),
        )
        original_headers = {
            "Host": "example.com",
            "Cookie": "session=original-session",
            "Authorization": "Bearer original-token",
            "X-Api-Key": "original-api-key",
        }
        stripped = _strip_original_auth(original_headers)
        overlaid = _overlay_identity_auth(stripped, identity)

        # Identity's auth material is present.
        self.assertEqual(overlaid["Cookie"], f"{cookie_name}={cookie_value}")
        self.assertEqual(overlaid["authorization"], f"Bearer {token}")
        self.assertEqual(overlaid[header_name], header_value)

        # Original auth material is gone.
        self.assertNotIn("X-Api-Key", overlaid)
        self.assertNotIn("original-session", overlaid.values())
        self.assertNotIn("original-token", overlaid.values())


if __name__ == "__main__":
    import unittest

    unittest.main()
