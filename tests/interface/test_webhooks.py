"""Tests for the webhook dispatcher module."""

from __future__ import annotations

import argparse
from typing import Any
from unittest.mock import MagicMock, patch

import requests

from strix.interface.webhooks import (
    _format_discord,
    _format_generic,
    _format_slack,
    _resolve_format,
    _severity_counts,
    _targets_summary,
    _vulnerability_summary,
    send_completion_webhook,
)


def _make_tracer(
    vulnerability_reports: list[dict[str, Any]] | None = None,
    scan_completed: bool = True,
) -> MagicMock:
    """Create a mock tracer with configurable vulnerability reports."""
    tracer = MagicMock()
    tracer.vulnerability_reports = vulnerability_reports or []
    tracer.scan_results = {"scan_completed": scan_completed}
    tracer.agents = {"agent-1": {}, "agent-2": {}}
    tracer.get_real_tool_count.return_value = 5
    tracer.get_total_llm_stats.return_value = {
        "total": {
            "input_tokens": 1000,
            "output_tokens": 500,
            "cost": 0.05,
            "requests": 3,
            "cached_tokens": 200,
        }
    }
    return tracer


def _make_args(
    targets_info: list[dict[str, Any]] | None = None,
    run_name: str = "test-run_abcd",
    scan_mode: str = "deep",
) -> argparse.Namespace:
    """Create a mock args namespace."""
    default_targets: list[dict[str, Any]] = [
        {"original": "https://example.com", "type": "web_application"},
    ]
    return argparse.Namespace(
        targets_info=targets_info if targets_info is not None else default_targets,
        run_name=run_name,
        scan_mode=scan_mode,
    )


SAMPLE_VULNS: list[dict[str, Any]] = [
    {
        "id": "VULN-001",
        "title": "SQL Injection in login endpoint",
        "severity": "critical",
        "cvss": 9.8,
        "target": "https://example.com",
        "endpoint": "/api/login",
        "description": "Unsanitised input allows SQL injection.",
    },
    {
        "id": "VULN-002",
        "title": "Reflected XSS",
        "severity": "high",
        "cvss": 7.1,
        "target": "https://example.com",
        "endpoint": "/search?q=<script>",
        "description": "User input reflected without encoding.",
    },
]


class TestResolveFormat:
    """Tests for webhook format auto-detection."""

    def test_explicit_slack_format(self) -> None:
        """Explicit format should override auto-detection."""
        assert _resolve_format("https://example.com/hook", "slack") == "slack"

    def test_explicit_discord_format(self) -> None:
        """Explicit format should override auto-detection."""
        assert _resolve_format("https://example.com/hook", "discord") == "discord"

    def test_auto_detect_slack(self) -> None:
        """Slack URLs should be auto-detected."""
        url = "https://hooks.slack.com/services/T00/B00/xxx"
        assert _resolve_format(url, "generic") == "slack"

    def test_auto_detect_discord(self) -> None:
        """Discord URLs should be auto-detected."""
        url = "https://discord.com/api/webhooks/123456/token"
        assert _resolve_format(url, "generic") == "discord"

    def test_auto_detect_discordapp(self) -> None:
        """Legacy discordapp.com URLs should be auto-detected."""
        url = "https://discordapp.com/api/webhooks/123456/token"
        assert _resolve_format(url, "generic") == "discord"

    def test_generic_fallback(self) -> None:
        """Unknown URLs should stay generic."""
        assert _resolve_format("https://example.com/hook", "generic") == "generic"


class TestTargetsSummary:
    """Tests for _targets_summary."""

    def test_single_target(self) -> None:
        args = _make_args()
        assert _targets_summary(args) == "https://example.com"

    def test_multiple_targets(self) -> None:
        args = _make_args(
            targets_info=[
                {"original": "https://a.com"},
                {"original": "https://b.com"},
            ]
        )
        assert _targets_summary(args) == "https://a.com, https://b.com"

    def test_no_targets(self) -> None:
        args = _make_args(targets_info=[])
        assert _targets_summary(args) == "unknown"


class TestSeverityCounts:
    """Tests for _severity_counts."""

    def test_counts_severities(self) -> None:
        tracer = _make_tracer(vulnerability_reports=SAMPLE_VULNS)
        counts = _severity_counts(tracer)
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 0

    def test_empty_reports(self) -> None:
        tracer = _make_tracer()
        counts = _severity_counts(tracer)
        assert all(v == 0 for v in counts.values())


class TestVulnerabilitySummary:
    """Tests for _vulnerability_summary."""

    def test_returns_expected_keys(self) -> None:
        tracer = _make_tracer(vulnerability_reports=SAMPLE_VULNS)
        result = _vulnerability_summary(tracer)
        assert len(result) == 2
        assert result[0]["id"] == "VULN-001"
        assert result[0]["severity"] == "critical"

    def test_empty_reports(self) -> None:
        tracer = _make_tracer()
        assert _vulnerability_summary(tracer) == []


class TestFormatGeneric:
    """Tests for the generic JSON formatter."""

    def test_structure(self) -> None:
        tracer = _make_tracer(vulnerability_reports=SAMPLE_VULNS)
        args = _make_args()
        payload = _format_generic(tracer, args)

        assert payload["event"] == "scan_completed"
        assert payload["run_name"] == "test-run_abcd"
        assert payload["vulnerability_count"] == 2
        assert payload["completed"] is True
        assert "vulnerabilities" in payload
        assert "stats" in payload

    def test_scan_not_completed(self) -> None:
        tracer = _make_tracer(scan_completed=False)
        args = _make_args()
        payload = _format_generic(tracer, args)

        assert payload["event"] == "scan_ended"
        assert payload["completed"] is False


class TestFormatSlack:
    """Tests for the Slack Block Kit formatter."""

    def test_structure(self) -> None:
        tracer = _make_tracer(vulnerability_reports=SAMPLE_VULNS)
        args = _make_args()
        payload = _format_slack(tracer, args)

        assert "blocks" in payload
        blocks = payload["blocks"]
        assert blocks[0]["type"] == "header"
        assert blocks[1]["type"] == "section"

    def test_no_vulnerabilities(self) -> None:
        tracer = _make_tracer()
        args = _make_args()
        payload = _format_slack(tracer, args)

        # Should still have header + summary blocks, just no vuln blocks
        assert len(payload["blocks"]) == 3


class TestFormatDiscord:
    """Tests for the Discord embed formatter."""

    def test_structure(self) -> None:
        tracer = _make_tracer(vulnerability_reports=SAMPLE_VULNS)
        args = _make_args()
        payload = _format_discord(tracer, args)

        assert "embeds" in payload
        embed = payload["embeds"][0]
        assert "Scan Completed" in embed["title"]
        assert embed["color"] == 0xDC2626  # critical = red

    def test_clean_scan_is_green(self) -> None:
        tracer = _make_tracer()
        args = _make_args()
        payload = _format_discord(tracer, args)

        embed = payload["embeds"][0]
        assert embed["color"] == 0x22C55E  # green


class TestSendCompletionWebhook:
    """Tests for the top-level send function."""

    @patch("strix.interface.webhooks.requests.post")
    def test_posts_to_url(self, mock_post: MagicMock) -> None:
        """Verify that the function POSTs to the provided URL."""
        mock_post.return_value = MagicMock(status_code=200)
        tracer = _make_tracer()
        args = _make_args()

        send_completion_webhook("https://example.com/hook", "generic", tracer, args)

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs[1]["json"]["event"] == "scan_completed"

    @patch("strix.interface.webhooks.requests.post")
    def test_auto_detects_slack(self, mock_post: MagicMock) -> None:
        """Verify Slack auto-detection produces Block Kit payload."""
        mock_post.return_value = MagicMock(status_code=200)
        tracer = _make_tracer()
        args = _make_args()

        send_completion_webhook(
            "https://hooks.slack.com/services/T00/B00/xxx", "generic", tracer, args
        )

        payload = mock_post.call_args[1]["json"]
        assert "blocks" in payload

    @patch("strix.interface.webhooks.requests.post")
    def test_failure_does_not_raise(self, mock_post: MagicMock) -> None:
        """Webhook delivery failures should be logged, not raised."""
        mock_post.side_effect = requests.ConnectionError("refused")
        tracer = _make_tracer()
        args = _make_args()

        # Should not raise
        send_completion_webhook("https://example.com/hook", "generic", tracer, args)
