"""Subscription usage-limit gate: classification, waiting, and resumption."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from zoneinfo import ZoneInfo

import pytest

from strix.config import claude_bridge, claude_code, claude_process, claude_quota


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_TURN: dict[str, Any] = {
    "type": "user",
    "message": {"role": "user", "content": [{"type": "text", "text": "prompt"}]},
}
# The package re-exports the function `main`, which shadows the module name.
strix_main = importlib.import_module("strix.interface.main")
_REFUSAL_TEXT = "You've hit your session limit · resets 12:30pm (Europe/London)"


@pytest.fixture(autouse=True)
def _fresh_gate(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """A fresh gate per test, with waits short enough to run."""
    claude_quota.GATE.reset()
    monkeypatch.setattr(claude_quota, "_RESET_MARGIN_S", 0.0)
    monkeypatch.setattr(claude_quota, "_SLEEP_STEP_S", 0.02)
    monkeypatch.delenv("STRIX_CLAUDE_CODE_QUOTA_MAX_WAIT", raising=False)
    monkeypatch.delenv("STRIX_CLAUDE_CODE_QUOTA_CEILING", raising=False)
    yield
    claude_quota.GATE.reset()


def _rate_limit_event(status: str, resets_at: float, **windows: float) -> dict[str, Any]:
    return {
        "type": "rate_limit_event",
        "rate_limit_info": {
            "status": status,
            "resetsAt": resets_at,
            "rateLimitType": "five_hour",
            "unifiedWindows": {
                name: {"utilization": used, "resetsAt": resets_at} for name, used in windows.items()
            },
        },
    }


def _refused_stdout(resets_at: float) -> str:
    events = [
        {"type": "system", "subtype": "init"},
        _rate_limit_event("rejected", resets_at, five_hour=1.0),
        {"type": "result", "subtype": "success", "is_error": True, "result": _REFUSAL_TEXT},
    ]
    return "\n".join(json.dumps(event) for event in events) + "\n"


def _served_stdout(resets_at: float, used: float = 0.4) -> str:
    events = [
        _rate_limit_event("allowed", resets_at, five_hour=used),
        {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "structured_output": {"text": "ok", "tool_calls": []},
        },
    ]
    return "\n".join(json.dumps(event) for event in events) + "\n"


def _completed(stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["claude"], returncode=0, stdout=stdout, stderr="")


class _FakeProcess:
    pid = 4321

    def poll(self) -> int:
        return 0

    def kill(self) -> None:  # pragma: no cover - never running
        pass


def _patch_turns(monkeypatch: pytest.MonkeyPatch, outputs: list[str]) -> list[float]:
    """Serve ``outputs`` in order, one per spawned turn; returns the spawn times."""
    spawned: list[float] = []
    queue = list(outputs)
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")

    def _spawn(*_a: Any, **_k: Any) -> _FakeProcess:
        spawned.append(time.time())
        return _FakeProcess()

    monkeypatch.setattr(claude_process, "_spawn", _spawn)
    monkeypatch.setattr(claude_process, "_communicate", lambda *_a, **_k: _completed(queue.pop(0)))
    return spawned


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #


def test_reset_text_with_a_zone_is_read_in_that_zone() -> None:
    now = datetime(2026, 10, 6, 8, 33, tzinfo=UTC)  # 09:33 in London (BST)
    resets = claude_quota.parse_reset_text(_REFUSAL_TEXT, now=now)
    assert resets == datetime(2026, 10, 6, 12, 30, tzinfo=ZoneInfo("Europe/London")).timestamp()


def test_reset_time_already_past_today_is_tomorrow() -> None:
    now = datetime(2026, 10, 6, 13, 0, tzinfo=ZoneInfo("Europe/London"))
    resets = claude_quota.parse_reset_text("resets 4am (Europe/London)", now=now)
    assert resets == datetime(2026, 10, 7, 4, 0, tzinfo=ZoneInfo("Europe/London")).timestamp()


def test_reset_text_with_a_date_is_read_as_that_date() -> None:
    now = datetime(2026, 10, 22, 9, 0, tzinfo=UTC)
    text = "You've hit your weekly limit · resets Oct 25, 4am (Europe/London)"
    resets = claude_quota.parse_reset_text(text, now=now)
    assert resets == datetime(2026, 10, 25, 4, 0, tzinfo=ZoneInfo("Europe/London")).timestamp()


def test_reset_text_in_the_older_epoch_form() -> None:
    assert claude_quota.parse_reset_text("Claude AI usage limit reached|1792698000") == 1792698000


@pytest.mark.parametrize("text", ["", "resets soon", "rate limited", "resets 25:99pm"])
def test_unreadable_reset_text_is_none(text: str) -> None:
    assert claude_quota.parse_reset_text(text) is None


def test_parse_transcript_keeps_the_latest_rate_limit_info() -> None:
    result = claude_bridge.parse_transcript(_refused_stdout(1792698000).split("\n"))
    info = result[claude_bridge.RATE_LIMIT_KEY]
    assert info["status"] == "rejected"
    assert info["resetsAt"] == 1792698000


def test_refusal_uses_the_event_reset_time() -> None:
    result = claude_bridge.parse_transcript(_refused_stdout(1792698000).split("\n"))
    refused = claude_quota.refusal(result)
    assert refused is not None
    assert refused.resets_at == 1792698000
    assert refused.window == "five_hour"


def test_refusal_falls_back_to_the_message_without_an_event() -> None:
    result = {"type": "result", "is_error": True, "result": _REFUSAL_TEXT}
    refused = claude_quota.refusal(result)
    assert refused is not None
    assert refused.resets_at == claude_quota.parse_reset_text(_REFUSAL_TEXT)


def test_a_served_turn_is_never_a_refusal() -> None:
    # A rejected status beside a successful result: served anyway (overage).
    result = claude_bridge.parse_transcript(_served_stdout(1792698000).split("\n"))
    result[claude_bridge.RATE_LIMIT_KEY]["status"] = "rejected"
    assert claude_quota.refusal(result) is None


def test_other_errors_are_not_refusals() -> None:
    result = {"type": "result", "is_error": True, "result": "API Error: 529 overloaded"}
    assert claude_quota.refusal(result) is None


def test_over_ceiling_picks_the_window_that_resets_last() -> None:
    result = {
        claude_bridge.RATE_LIMIT_KEY: {
            "unifiedWindows": {
                "five_hour": {"utilization": 0.95, "resetsAt": 100.0},
                "seven_day": {"utilization": 0.91, "resetsAt": 900.0},
            }
        }
    }
    assert claude_quota.over_ceiling(result, 0.9) == ("seven_day", 900.0)
    assert claude_quota.over_ceiling(result, 0.96) is None


# --------------------------------------------------------------------------- #
# The gate in the transport
# --------------------------------------------------------------------------- #


def test_refused_turn_waits_for_the_reset_and_is_sent_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resets_at = time.time() + 0.3
    spawned = _patch_turns(monkeypatch, [_refused_stdout(resets_at), _served_stdout(resets_at)])

    result = asyncio.run(claude_process.run_turn("claude-opus-4-8", _TURN))

    assert result["structured_output"] == {"text": "ok", "tool_calls": []}
    assert len(spawned) == 2
    assert spawned[1] >= resets_at
    assert claude_quota.GATE.closures == 1


def test_turns_wait_at_a_closed_gate_without_spawning(monkeypatch: pytest.MonkeyPatch) -> None:
    opens = time.time() + 0.3
    claude_quota.GATE.close(opens, "test")
    spawned = _patch_turns(monkeypatch, [_served_stdout(opens)] * 3)

    async def _three() -> None:
        await asyncio.gather(*[claude_process.run_turn("claude-opus-4-8", _TURN) for _ in range(3)])

    asyncio.run(_three())

    assert len(spawned) == 3
    assert min(spawned) >= opens


def test_waiting_off_fails_at_once_and_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_CLAUDE_CODE_QUOTA_MAX_WAIT", "0")
    spawned = _patch_turns(monkeypatch, [_refused_stdout(time.time() + 60)])

    with pytest.raises(claude_quota.QuotaExhaustedError) as caught:
        asyncio.run(claude_process.run_turn("claude-opus-4-8", _TURN))

    assert len(spawned) == 1
    assert claude_code.is_permanent_error(caught.value)


def test_a_reset_beyond_the_maximum_wait_stops_the_turn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_CLAUDE_CODE_QUOTA_MAX_WAIT", "60")
    _patch_turns(monkeypatch, [_refused_stdout(time.time() + 3600)])

    with pytest.raises(claude_quota.QuotaExhaustedError, match="QUOTA_MAX_WAIT"):
        asyncio.run(claude_process.run_turn("claude-opus-4-8", _TURN))


def test_no_waiting_block_raises_instead_of_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_turns(monkeypatch, [_refused_stdout(time.time() + 3600)])

    async def _preflight() -> None:
        with claude_quota.no_waiting():
            await claude_process.run_turn("claude-opus-4-8", _TURN, structured=False)

    with pytest.raises(claude_quota.QuotaExhaustedError):
        asyncio.run(_preflight())


def test_ceiling_closes_the_gate_before_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_CLAUDE_CODE_QUOTA_CEILING", "0.85")
    resets_at = time.time() + 3600
    _patch_turns(monkeypatch, [_served_stdout(resets_at, used=0.9)])

    asyncio.run(claude_process.run_turn("claude-opus-4-8", _TURN))

    assert claude_quota.GATE.is_closed()
    assert claude_quota.GATE.until == resets_at


def test_ceiling_is_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_turns(monkeypatch, [_served_stdout(time.time() + 3600, used=0.99)])
    asyncio.run(claude_process.run_turn("claude-opus-4-8", _TURN))
    assert not claude_quota.GATE.is_closed()


def test_the_gate_keeps_the_later_reset() -> None:
    gate = claude_quota.QuotaGate()
    gate.close(200.0, "first")
    gate.close(100.0, "earlier")
    assert gate.until == 200.0


# --------------------------------------------------------------------------- #
# A real subprocess: a stand-in `claude` that refuses once, then serves
# --------------------------------------------------------------------------- #


_FAKE_CLAUDE = """\
import json, os, sys, time
sys.stdin.read()
state = os.environ["FAKE_CLAUDE_STATE"]
calls = int(open(state).read() or 0) if os.path.exists(state) else 0
open(state, "w").write(str(calls + 1))
resets_at = float(os.environ["FAKE_CLAUDE_RESETS_AT"])
if calls == 0:
    print(json.dumps({"type": "rate_limit_event", "rate_limit_info": {
        "status": "rejected", "resetsAt": resets_at, "rateLimitType": "five_hour"}}))
    print(json.dumps({"type": "result", "is_error": True,
        "result": "You've hit your session limit \\u00b7 resets 4am"}))
    sys.exit(1)
print(json.dumps({"type": "result", "is_error": False,
    "structured_output": {"text": "served after reset", "tool_calls": []}}))
"""


@pytest.mark.skipif(sys.platform == "win32", reason="shebang script stand-in")
def test_real_subprocess_refused_then_served(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    script = tmp_path / "claude"
    script.write_text(f"#!{sys.executable}\n{_FAKE_CLAUDE}")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    resets_at = time.time() + 0.5
    monkeypatch.setenv("FAKE_CLAUDE_STATE", str(tmp_path / "calls"))
    monkeypatch.setenv("FAKE_CLAUDE_RESETS_AT", str(resets_at))
    monkeypatch.setattr(claude_code, "binary_path", lambda: str(script))

    result = asyncio.run(claude_process.run_turn("claude-opus-4-8", _TURN))

    assert result["structured_output"]["text"] == "served after reset"
    assert (tmp_path / "calls").read_text() == "2"
    assert time.time() >= resets_at
    assert os.environ["FAKE_CLAUDE_STATE"]


# --------------------------------------------------------------------------- #
# Warm-up
# --------------------------------------------------------------------------- #


def test_warm_up_waits_out_a_spent_window(monkeypatch: pytest.MonkeyPatch) -> None:
    resets_at = time.time() + 0.3
    calls: list[float] = []

    async def _preflight(*_a: Any, **_k: Any) -> None:
        calls.append(time.time())
        if len(calls) == 1:
            raise claude_quota.QuotaExhaustedError("refused", resets_at=resets_at)

    monkeypatch.setattr(strix_main, "preflight_model_connection", _preflight)
    console = strix_main.Console(file=open(os.devnull, "w"))  # noqa: SIM115, PTH123

    asyncio.run(strix_main._preflight_through_quota("claude-code/x", None, console))  # type: ignore[arg-type]

    assert len(calls) == 2
    assert calls[1] >= resets_at


def test_warm_up_with_waiting_off_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_CLAUDE_CODE_QUOTA_MAX_WAIT", "0")

    async def _preflight(*_a: Any, **_k: Any) -> None:
        raise claude_quota.QuotaExhaustedError("refused", resets_at=time.time() + 60)

    monkeypatch.setattr(strix_main, "preflight_model_connection", _preflight)
    console = strix_main.Console(file=open(os.devnull, "w"))  # noqa: SIM115, PTH123

    with pytest.raises(claude_quota.QuotaExhaustedError):
        asyncio.run(strix_main._preflight_through_quota("claude-code/x", None, console))  # type: ignore[arg-type]


def test_describe_exhaustion_names_reset_time() -> None:
    # A known reset time is rendered in the local zone and the message points at
    # the headless wait path (the TUI fails fast rather than hanging).
    resets_at = time.time() + 3600
    msg = claude_quota.describe_exhaustion(resets_at)
    assert "usage limit reached" in msg
    assert "resets at" in msg
    assert "STRIX_CLAUDE_CODE_QUOTA_MAX_WAIT" in msg


def test_describe_exhaustion_without_reset_time() -> None:
    msg = claude_quota.describe_exhaustion(None)
    assert "reset shortly" in msg
    assert "resets at" not in msg
