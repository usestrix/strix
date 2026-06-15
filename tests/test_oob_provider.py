"""Tier-1 tests for the OOB provider (interactsh adapter), offline.

The interactsh-client subprocess is mocked so these tests never reach a public
or self-hosted OOB server.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, patch

from strix.core.oob.models import OobConfig, OobHit
from strix.runtime.oob.provider import InteractshProvider


class _FakeProcess:
    """Minimal async subprocess stand-in for provider tests."""

    def __init__(self) -> None:
        self.stdout = MagicMock()
        self.stderr = MagicMock()
        self.returncode: int | None = None
        self._terminated = False

    async def wait(self) -> int:
        return 0

    def terminate(self) -> None:
        self._terminated = True

    def kill(self) -> None:
        self._terminated = True


class TestInteractshProviderTier1(IsolatedAsyncioTestCase):
    """Focused offline tests for the interactsh provider adapter."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"
        self.run_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    async def _start_with_fake_process(self, provider: InteractshProvider) -> _FakeProcess:
        """Start provider with a fake subprocess and a fixed hostname."""
        fake_proc = _FakeProcess()
        with (
            patch(
                "asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=fake_proc),
            ),
            patch.object(
                provider,
                "_wait_for_hostname",
                new=AsyncMock(return_value="abc123.oast.pro"),
            ),
        ):
            await provider.start(self.run_dir)
        return fake_proc

    async def test_start_parses_hostname_and_ready(self) -> None:
        provider = InteractshProvider(config=OobConfig())
        await self._start_with_fake_process(provider)

        self.assertTrue(provider.ready())
        self.assertEqual(provider.base_host(), "abc123.oast.pro")
        self.assertEqual(provider.config.server_url, None)

    async def test_self_hosted_url_passed_to_command(self) -> None:
        provider = InteractshProvider(config=OobConfig(server_url="http://self.hosted"))
        await self._start_with_fake_process(provider)
        cmd = provider._build_start_command()
        self.assertIn("-server", cmd)
        self.assertIn("http://self.hosted", cmd)
        self.assertEqual(provider.base_host(), "abc123.oast.pro")

    async def test_poll_interactions_parses_json_log(self) -> None:
        provider = InteractshProvider()
        await self._start_with_fake_process(provider)

        log_path = self.run_dir / "interactsh.log"
        log_path.write_text(
            '{"full-id":"tok1.abc123.oast.pro","protocol":"dns","remote-address":"1.2.3.4"}\n'
            '{"full-id":"tok2.abc123.oast.pro","protocol":"http","raw-request":"GET / HTTP/1.1"}\n'
        )

        hits = await provider.poll_interactions()
        self.assertEqual(len(hits), 2)
        self.assertIsInstance(hits[0], OobHit)
        self.assertEqual(hits[0].token, "tok1")
        self.assertEqual(hits[0].protocol, "dns")
        self.assertEqual(hits[1].protocol, "http")
        self.assertIn(b"GET /", hits[1].raw_request or b"")

    async def test_poll_returns_empty_when_not_ready(self) -> None:
        provider = InteractshProvider()
        hits = await provider.poll_interactions()
        self.assertEqual(hits, [])

    async def test_stop_clears_ready(self) -> None:
        provider = InteractshProvider()
        fake_proc = await self._start_with_fake_process(provider)
        await provider.stop()
        self.assertFalse(provider.ready())
        self.assertTrue(fake_proc._terminated)

    async def test_no_spawn_mode_reads_hostname_from_log(self) -> None:
        provider = InteractshProvider(no_spawn=True)
        log_path = self.run_dir / "interactsh.log"
        log_path.write_text("[INF] Generated payload URL: abcdef123456.oast.pro\n")
        await provider.start(self.run_dir)
        self.assertTrue(provider.ready())
        self.assertEqual(provider.base_host(), "abcdef123456.oast.pro")


if __name__ == "__main__":
    import unittest

    unittest.main()
