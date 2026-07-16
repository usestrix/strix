"""Configuration and fail-closed finding-verification tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from strix.config import loader
from strix.config.settings import FindingVerificationSettings
from strix.report.state import ReportState, set_global_report_state
from strix.tools.reporting.tool import _do_create


if TYPE_CHECKING:
    from pathlib import Path


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


def test_structured_config_loads_skill_routes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in (
        "STRIX_LLM",
        "STRIX_ORCHESTRATOR_MODEL",
        "STRIX_SUBAGENT_MODEL",
        "STRIX_VERIFY_FINDINGS",
        "STRIX_VERIFICATION_MODEL",
    ):
        monkeypatch.delenv(key, raising=False)
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "llm": {
                    "model": "openai/root",
                    "subagent_model": "deepseek/cheap",
                    "skill_model_routes": [
                        {"operator": "AND", "skills": ["oauth", "xss"], "model": "qwen/hard"}
                    ],
                },
                "verification": {"enabled": True, "model": "anthropic/verifier"},
            }
        ),
        encoding="utf-8",
    )
    loader._cached = None
    loader._override = path
    try:
        settings = loader.load_settings()
    finally:
        loader._cached = None
        loader._override = None

    assert settings.llm.model == "openai/root"
    assert settings.llm.subagent_model == "deepseek/cheap"
    assert settings.llm.skill_model_routes[0].matches(["oauth", "xss"])
    assert settings.verification.enabled is True
    assert settings.verification.model == "anthropic/verifier"


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
