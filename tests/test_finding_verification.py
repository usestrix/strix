"""Configuration and fail-closed finding-verification tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from strix.config.settings import FindingVerificationSettings
from strix.report.state import ReportState, set_global_report_state
from strix.report.verification import _verifier_model_settings
from strix.tools.reporting.tool import _do_create


if TYPE_CHECKING:
    from pathlib import Path


def test_verifier_key_sent_per_call_not_via_global_env() -> None:
    verification = FindingVerificationSettings(
        enabled=True,
        model="anthropic/verifier",
        api_key="verifier-key",
    )
    settings = _verifier_model_settings(verification, "anthropic/verifier")
    # The key rides on the request, so a shared-provider primary key can't
    # clobber it (and vice versa) through the global provider env var.
    assert settings.extra_args["api_key"] == "verifier-key"


def test_verifier_settings_omit_api_key_when_unset() -> None:
    verification = FindingVerificationSettings(enabled=True, model="anthropic/verifier")
    settings = _verifier_model_settings(verification, "anthropic/verifier")
    assert "api_key" not in (settings.extra_args or {})
    assert "api_base" not in (settings.extra_args or {})


def test_verifier_endpoint_sent_per_call() -> None:
    verification = FindingVerificationSettings(
        enabled=True,
        model="openai/verifier",
        api_key="verifier-key",
        api_base="https://verifier.example/v1",
    )
    settings = _verifier_model_settings(verification, "openai/verifier")
    # A distinct verification endpoint rides on the request instead of the
    # process-wide base URL, so it can't clobber the primary model's endpoint.
    assert settings.extra_args["api_base"] == "https://verifier.example/v1"
    assert settings.extra_args["api_key"] == "verifier-key"


_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "H",
    "availability": "H",
}


def test_verification_defaults_off() -> None:
    settings = FindingVerificationSettings()
    assert settings.enabled is False
    assert settings.model is None


def test_enabled_verification_requires_model() -> None:
    with pytest.raises(ValidationError, match="STRIX_VERIFICATION_MODEL"):
        FindingVerificationSettings(enabled=True)


@pytest.mark.asyncio
async def test_rejected_finding_is_not_persisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    state = ReportState("verification-test")
    set_global_report_state(state)

    async def reject(_candidate: dict[str, object]) -> dict[str, object]:
        return {"status": "rejected", "confidence": 0.99, "reason": "PoC is contradicted"}

    monkeypatch.setattr("strix.report.verification.verify_finding", reject)
    result = await _do_create(
        title="Claimed SQL injection",
        description="Claim.",
        impact="Database access.",
        target="https://example.com",
        technical_analysis="Claimed sink.",
        poc_description="1. Send payload.",
        poc_script_code="GET /?id=1",
        remediation_steps="Parameterize queries.",
        evidence="A normal response.",
        assumptions="None.",
        fix_effort="low",
        cvss_breakdown=_CVSS,
        endpoint="/",
        method="GET",
        cve=None,
        cwe="CWE-89",
        code_locations=None,
    )

    assert result["success"] is False
    assert result["verification"]["status"] == "rejected"
    assert state.vulnerability_reports == []
