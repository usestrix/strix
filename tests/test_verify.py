"""Unit tests for the opt-in verify-before-emit pass (strix.report.verify)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from strix.config import loader
from strix.report import verify


def _reset_cache() -> None:
    loader._cached = None
    loader._override = None


@pytest.fixture(autouse=True)
def clean_settings(monkeypatch: pytest.MonkeyPatch):
    for key in (
        "STRIX_VERIFY",
        "STRIX_VERIFY_MODEL",
        "STRIX_VERIFY_MIN_SEVERITY",
        "STRIX_VERIFY_MIN_CONFIDENCE",
        "STRIX_LLM",
    ):
        monkeypatch.delenv(key, raising=False)
    _reset_cache()
    yield
    _reset_cache()


def test_min_confidence_defaults_to_high():
    _reset_cache()
    assert loader.load_settings().verify.min_confidence == 0.8


def test_min_confidence_is_configurable(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("STRIX_VERIFY_MIN_CONFIDENCE", "0.95")
    _reset_cache()
    assert loader.load_settings().verify.min_confidence == 0.95


def test_min_confidence_rejects_out_of_range(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("STRIX_VERIFY_MIN_CONFIDENCE", "1.5")
    _reset_cache()
    with pytest.raises(ValidationError):
        loader.load_settings()


def test_verify_disabled_by_default():
    _reset_cache()
    assert loader.load_settings().verify.enabled is False


def test_severity_gate():
    assert verify._meets_min_severity("critical", "high")
    assert verify._meets_min_severity("high", "high")
    assert not verify._meets_min_severity("medium", "high")
    assert not verify._meets_min_severity("low", "high")
    assert not verify._meets_min_severity("info", "high")
    # a lower floor lets more through
    assert verify._meets_min_severity("medium", "medium")
    assert verify._meets_min_severity("low", "info")


def test_parse_verdict_plain():
    v = verify._parse_verdict(
        '{"verdict": "REAL", "confidence": 0.9, "reason": "guard bypassable"}'
    )
    assert v["verdict"] == "REAL"
    assert v["confidence"] == 0.9
    assert v["reason"] == "guard bypassable"


def test_parse_verdict_fenced():
    v = verify._parse_verdict('```json\n{"verdict": "FALSE_POSITIVE", "confidence": 0.85}\n```')
    assert v["verdict"] == "FALSE_POSITIVE"
    assert v["confidence"] == 0.85


def test_parse_verdict_bad_confidence_defaults_zero():
    v = verify._parse_verdict('{"verdict": "REAL", "confidence": "high"}')
    assert v["confidence"] == 0.0


def test_parse_verdict_no_json_raises():
    with pytest.raises(ValueError):
        verify._parse_verdict("I think this is real, sorry no JSON")


async def test_disabled_emits():
    # enabled defaults to False → never rejects, no model call.
    _reset_cache()
    out = await verify.verify_finding({"title": "x"}, "critical")
    assert out["reject"] is False
    assert out["verdict"] == "SKIPPED"


async def test_below_min_severity_skips(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("STRIX_VERIFY", "true")
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-x")
    _reset_cache()
    out = await verify.verify_finding({"title": "x"}, "low")
    assert out["reject"] is False
    assert out["verdict"] == "SKIPPED"
    assert "below min_severity" in out["reason"]


async def test_missing_or_unreachable_model_emits(monkeypatch: pytest.MonkeyPatch):
    # Enabled + a model name that can't actually be reached (no creds) must never
    # reject — the fail-open posture turns any call failure into an EMIT. Whether
    # the guard skips (no model resolved) or the call errors, reject stays False.
    monkeypatch.setenv("STRIX_VERIFY", "true")
    monkeypatch.setenv("STRIX_VERIFY_MODEL", "openai/definitely-not-reachable")
    _reset_cache()
    out = await verify.verify_finding({"title": "x"}, "critical")
    assert out["reject"] is False
    assert out["verdict"] in {"SKIPPED", "ERROR"}


async def _run_with_stubbed_model(
    monkeypatch: pytest.MonkeyPatch, response_text: str, severity: str, min_conf: str | None = None
) -> dict:
    """Drive verify_finding with the model call fully stubbed (no network).

    _extract_text is patched to return the canned response, so the fake model's
    get_response only needs to be awaitable — its return value is never read.
    """
    monkeypatch.setenv("STRIX_VERIFY", "true")
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-x")
    if min_conf is not None:
        monkeypatch.setenv("STRIX_VERIFY_MIN_CONFIDENCE", min_conf)
    _reset_cache()

    class _FakeModel:
        async def get_response(self, *args: object, **kwargs: object) -> object:  # noqa: ARG002
            return object()

    monkeypatch.setattr(verify.StrixProvider, "get_model", lambda self, m: _FakeModel())  # noqa: ARG005
    monkeypatch.setattr(verify, "configure_sdk_model_defaults", lambda s: None)  # noqa: ARG005
    monkeypatch.setattr(verify, "_extract_text", lambda r: response_text)  # noqa: ARG005
    monkeypatch.setattr(verify, "get_global_report_state", lambda: None)
    return await verify.verify_finding({"title": "candidate"}, severity)


async def test_confident_false_positive_rejects(monkeypatch: pytest.MonkeyPatch):
    out = await _run_with_stubbed_model(
        monkeypatch,
        '{"verdict": "FALSE_POSITIVE", "confidence": 0.9, "reason": "already patched"}',
        "high",
    )
    assert out["reject"] is True
    assert out["verdict"] == "FALSE_POSITIVE"


async def test_low_confidence_false_positive_emits(monkeypatch: pytest.MonkeyPatch):
    # Below the 0.8 default → NOT suppressed (FN=0 posture).
    out = await _run_with_stubbed_model(
        monkeypatch, '{"verdict": "FALSE_POSITIVE", "confidence": 0.55, "reason": "maybe"}', "high"
    )
    assert out["reject"] is False


async def test_real_verdict_emits(monkeypatch: pytest.MonkeyPatch):
    out = await _run_with_stubbed_model(
        monkeypatch,
        '{"verdict": "REAL", "confidence": 0.99, "reason": "sink reachable"}',
        "critical",
    )
    assert out["reject"] is False
    assert out["verdict"] == "REAL"


async def test_raised_min_confidence_makes_it_more_conservative(monkeypatch: pytest.MonkeyPatch):
    # Same 0.9 FP verdict that rejects at default 0.8 must EMIT when the floor is 0.95.
    out = await _run_with_stubbed_model(
        monkeypatch,
        '{"verdict": "FALSE_POSITIVE", "confidence": 0.9, "reason": "patched"}',
        "high",
        min_conf="0.95",
    )
    assert out["reject"] is False


async def test_unparseable_response_emits(monkeypatch: pytest.MonkeyPatch):
    out = await _run_with_stubbed_model(monkeypatch, "no json here", "critical")
    assert out["reject"] is False
    assert out["verdict"] == "ERROR"
