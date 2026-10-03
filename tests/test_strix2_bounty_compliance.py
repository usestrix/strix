"""Tests for bounty HTTP ROE enforcement (required header + rate cap)."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import pytest

from strix.agents.factory import _wrap_repeat_request
from strix.bounty import compile_to_scope, evaluate_roe
from strix.bounty.bootstrap import _derive_http_roe
from strix.bounty.compliance import (
    check_http_compliance,
    enforce_bounty_http,
    required_headers_for_run,
)
from strix.bounty.runtime import BountyContext, set_bounty_context
from strix.bounty.schema import BountyProgram, RulesOfEngagement


if TYPE_CHECKING:
    from collections.abc import Iterator


_HDRS = {"X-Bug-Bounty": "HackerOne-alice"}


@pytest.fixture(autouse=True)
def _reset() -> Iterator[None]:
    yield
    set_bounty_context(None)


# --- check_http_compliance (pure) --------------------------------------------


def test_inactive_when_no_header_or_rate() -> None:
    assert check_http_compliance(
        "curl https://x.acme.com", required_headers={}, rate_limit_rps=None
    ) is None


def test_http_command_missing_required_header_is_refused() -> None:
    reason = check_http_compliance(
        "curl https://console.neon.tech/api", required_headers=_HDRS, rate_limit_rps=None
    )
    assert reason is not None and "X-Bug-Bounty" in reason


def test_http_command_with_header_passes() -> None:
    cmd = "curl -H 'X-Bug-Bounty: HackerOne-alice' https://console.neon.tech/api"
    assert check_http_compliance(cmd, required_headers=_HDRS, rate_limit_rps=None) is None


def test_non_http_command_is_ignored() -> None:
    assert check_http_compliance(
        "ls -la /workspace", required_headers=_HDRS, rate_limit_rps=10
    ) is None


def test_help_without_target_is_ignored() -> None:
    assert check_http_compliance("curl --help", required_headers=_HDRS, rate_limit_rps=None) is None


def test_volume_tool_without_rate_flag_is_refused() -> None:
    cmd = "nuclei -H 'X-Bug-Bounty: HackerOne-alice' -u https://console.neon.tech"
    reason = check_http_compliance(cmd, required_headers=_HDRS, rate_limit_rps=10)
    assert reason is not None and "rate" in reason.lower()


def test_volume_tool_with_rate_flag_passes() -> None:
    cmd = "nuclei -H 'X-Bug-Bounty: HackerOne-alice' -rl 10 -u https://console.neon.tech"
    assert check_http_compliance(cmd, required_headers=_HDRS, rate_limit_rps=10) is None


def test_single_request_tool_not_subject_to_rate() -> None:
    # curl is one request; a missing rate flag must NOT trip the rate rule.
    cmd = "curl -H 'X-Bug-Bounty: HackerOne-alice' https://console.neon.tech/api"
    assert check_http_compliance(cmd, required_headers=_HDRS, rate_limit_rps=10) is None


# --- enforce_bounty_http (reads the active context) --------------------------


def _bind(**roe_kwargs: object) -> None:
    program = BountyProgram(
        platform="hackerone",
        handle="neon_bbp",
        in_scope=[],
        roe=RulesOfEngagement(**roe_kwargs),  # type: ignore[arg-type]
    )
    set_bounty_context(
        BountyContext(
            program=program,
            gate=evaluate_roe(program),
            compiled=compile_to_scope(program),
        )
    )


def test_enforce_reads_context() -> None:
    _bind(required_headers=_HDRS, rate_limit_rps=10)
    assert enforce_bounty_http("curl https://console.neon.tech/api") is not None
    compliant = "curl -H 'X-Bug-Bounty: HackerOne-alice' https://console.neon.tech/api"
    assert enforce_bounty_http(compliant) is None
    assert required_headers_for_run() == _HDRS


def test_enforce_noop_without_context() -> None:
    set_bounty_context(None)
    assert enforce_bounty_http("curl https://console.neon.tech/api") is None
    assert required_headers_for_run() == {}


# --- bootstrap policy derivation ---------------------------------------------


def test_derive_http_roe_from_policy() -> None:
    program = BountyProgram(
        platform="hackerone",
        handle="neon_bbp",
        roe=RulesOfEngagement(
            notes="Use a unique header X-Bug-Bounty:HackerOne-username. Keep requests to "
            "10 per second or lower."
        ),
    )
    derived = _derive_http_roe(program, username="truongblackbear937")
    assert derived.roe.required_headers == {"X-Bug-Bounty": "HackerOne-truongblackbear937"}
    assert derived.roe.rate_limit_rps == 10.0


def test_derive_does_not_override_explicit_roe() -> None:
    program = BountyProgram(
        platform="hackerone",
        handle="x",
        roe=RulesOfEngagement(
            notes="X-Bug-Bounty required; 10 per second.",
            required_headers={"X-Custom": "v"},
            rate_limit_rps=3,
        ),
    )
    derived = _derive_http_roe(program, username="alice")
    assert derived.roe.required_headers == {"X-Custom": "v"}
    assert derived.roe.rate_limit_rps == 3


# --- proxy replay header injection -------------------------------------------


class _FakeTool:
    name = "repeat_request"

    def __init__(self) -> None:
        self.captured: str | None = None

        async def _invoke(ctx: object, raw: str) -> str:
            del ctx
            self.captured = raw
            return "ok"

        self.on_invoke_tool = _invoke


async def _run_wrapper(raw_input: str) -> str | None:
    tool = _FakeTool()
    _wrap_repeat_request(tool)  # type: ignore[arg-type]
    await tool.on_invoke_tool(None, raw_input)
    return tool.captured


def test_repeat_request_injects_required_headers() -> None:
    _bind(required_headers=_HDRS, rate_limit_rps=None)
    captured = asyncio.run(_run_wrapper(json.dumps({"request_id": "r1"})))
    assert captured is not None
    mods = json.loads(captured)["modifications"]
    assert mods["headers"]["X-Bug-Bounty"] == "HackerOne-alice"


def test_repeat_request_noop_without_bounty() -> None:
    set_bounty_context(None)
    raw = json.dumps({"request_id": "r1"})
    assert asyncio.run(_run_wrapper(raw)) == raw
