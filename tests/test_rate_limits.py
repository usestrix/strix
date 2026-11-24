"""Tests for per-domain request rate limits."""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.agents.prompt import render_scope_prompt
from strix.core.rate_limits import normalize_rate_limits, rate_limits_for_targets
from strix.interface.cli_args import _positive_budget


def test_normalize_keeps_valid_hosts_and_rates() -> None:
    raw: dict[str, Any] = {
        "Example.COM.": 5,
        "*.api.example.com": "2.5",
        "": 3,
        "zero.example.com": 0,
        "neg.example.com": -1,
        "nan.example.com": float("nan"),
        "text.example.com": "fast",
    }

    assert normalize_rate_limits(raw) == {"example.com": 5.0, "api.example.com": 2.5}
    assert normalize_rate_limits(None) == {}


def test_normalize_keeps_endpoint_path_case() -> None:
    assert normalize_rate_limits({"API.Example.com/V1/Pay/": 1}) == {"api.example.com/V1/Pay": 1.0}


def test_targets_map_to_their_hosts() -> None:
    scan_config = {
        "targets": [
            {"type": "web_application", "details": {"target_url": "https://app.example.com/login"}},
            {"type": "ip_address", "details": {"target_ip": "10.0.0.5"}},
            {"type": "repository", "details": {"target_repo": "https://github.com/acme/app"}},
            {
                "type": "api_spec",
                "details": {
                    "target_spec": "./openapi.json",
                    "base_urls": ["https://api.example.com"],
                },
            },
        ],
    }

    assert rate_limits_for_targets(scan_config, 5) == {
        "app.example.com": 5.0,
        "10.0.0.5": 5.0,
        "api.example.com": 5.0,
    }


def test_scope_prompt_states_the_limits() -> None:
    prompt = render_scope_prompt(
        {"rate_limits": [{"domain": "example.com", "per_second": 5.0}]},
    )

    assert "REQUEST RATE LIMITS:" in prompt
    assert "- example.com: 5 requests per second" in prompt


def test_scope_prompt_omits_the_section_without_limits() -> None:
    assert "REQUEST RATE LIMITS" not in render_scope_prompt({})


def test_max_rps_rejects_non_positive_values() -> None:
    with pytest.raises(Exception, match="greater than 0"):
        _positive_budget("0")
    assert json.loads(json.dumps({"a": _positive_budget("2")})) == {"a": 2.0}
