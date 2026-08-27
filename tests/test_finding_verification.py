"""Tests for sandbox-backed finding verification and evidence-based rescoring."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest
from agents.extensions.models.litellm_model import LitellmModel
from agents.tool import FunctionTool
from agents.tool_context import ToolContext

from strix.agents import factory
from strix.agents.factory import (
    _lifecycle_tool_completed,
    build_verifier_agent,
)
from strix.config.settings import FindingVerificationSettings, Settings
from strix.core.hooks import BudgetExceededError
from strix.report import verification as verification_module
from strix.report.sarif import write_sarif
from strix.report.state import ReportState, set_global_report_state
from strix.report.verification import (
    _verifier_instructions,
    _verifier_model,
    _verifier_model_settings,
    verify_finding,
)
from strix.report.writer import render_vulnerability_md
from strix.tools.reporting.tool import (
    _do_create,
    _do_create_dependency,
    _to_report_summary_entry,
)
from strix.tools.verification.tool import _do_submit, submit_verification_verdict


if TYPE_CHECKING:
    from pathlib import Path


_CVSS_HIGH = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "H",
    "availability": "H",
}

_CVSS_INFO = {
    **_CVSS_HIGH,
    "confidentiality": "N",
    "integrity": "N",
    "availability": "N",
}


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="verification-test")
    set_global_report_state(state)
    return state


def _dynamic_kwargs(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "title": "SQL injection in account lookup",
        "description": "The account lookup interpolates an identifier into SQL.",
        "impact": "An unauthenticated attacker can read the full account database.",
        "target": "https://app.example.com",
        "technical_analysis": "The id parameter reaches a string-formatted SQL query.",
        "poc_description": "Submit a boolean SQL payload in id.",
        "poc_script_code": "requests.get('/account', params={'id': \"1' OR 1=1--\"})",
        "remediation_steps": "Use a parameterized query.",
        "evidence": "The candidate response returned multiple account rows.",
        "assumptions": "The route is exposed without authentication.",
        "counterevidence": "A malformed control payload returned an error.",
        "confidence": "high",
        "severity_change_conditions": "A proven authorization check would lower severity.",
        "fix_effort": "low",
        "cvss_breakdown": _CVSS_HIGH,
        "endpoint": "/account",
        "method": "GET",
        "cve": None,
        "cwe": "CWE-89",
        "code_locations": None,
        "verification_context": {"sandbox_session": object()},
    }
    kwargs.update(overrides)
    return kwargs


def _dependency_kwargs(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "title": "CVE-2024-12345 in sample 1.0.0",
        "description": "The pinned package version matches the advisory.",
        "target": "repo/package-lock.json",
        "cve": "CVE-2024-12345",
        "package_name": "sample",
        "installed_version": "1.0.0",
        "impact": "The affected parser may allow remote code execution.",
        "remediation_steps": "Upgrade to 1.0.1.",
        "assumptions": "The affected parser receives attacker input.",
        "package_ecosystem": "npm",
        "fixed_version": "1.0.1",
        "cwe": "CWE-94",
        "advisory_cvss": 9.8,
        "technical_analysis": "The application imports the package.",
        "fix_effort": "trivial",
        "manifest_path": "package-lock.json",
        "reachability": "imported",
        "reachability_evidence": "src/parser.ts:10 imports sample.",
        "contextual_cvss_breakdown": _CVSS_HIGH,
        "contextual_cvss_reasoning": "The imported parser may receive request bodies.",
        "verification_context": {"sandbox_session": object()},
    }
    kwargs.update(overrides)
    return kwargs


def test_verification_defaults_to_disabled() -> None:
    settings = FindingVerificationSettings()
    assert settings.enabled is False
    assert settings.model is None
    assert settings.max_attempts == 3
    assert settings.max_turns == 40


def test_verification_settings_read_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_VERIFY_FINDINGS", "true")
    monkeypatch.setenv("STRIX_VERIFICATION_MODEL", "openai/verifier")
    monkeypatch.setenv("STRIX_VERIFICATION_MAX_ATTEMPTS", "2")
    settings = FindingVerificationSettings()
    assert settings.enabled is True
    assert settings.model == "openai/verifier"
    assert settings.max_attempts == 2


async def test_verifier_credentials_are_request_local() -> None:
    settings = Settings(llm={"model": "openai/main"})
    verification = FindingVerificationSettings(
        STRIX_VERIFICATION_MODEL="openai/verifier",
        VERIFICATION_LLM_API_KEY="verifier-key",
        VERIFICATION_LLM_API_BASE="https://verifier.example/v1",
    )
    model_settings = _verifier_model_settings(settings, verification, "openai/verifier")
    model, client = _verifier_model(settings, verification, "openai/verifier")
    assert model is not None
    assert "api_key" not in (model_settings.extra_args or {})
    assert client is not None
    assert client.api_key == "verifier-key"
    assert str(client.base_url) == "https://verifier.example/v1/"
    await client.close()


async def test_openai_compatible_verifier_can_run_without_auth_key() -> None:
    settings = Settings(llm={"model": "openai/main"})
    verification = FindingVerificationSettings(
        STRIX_VERIFICATION_MODEL="openai/verifier",
        VERIFICATION_LLM_API_BASE="http://localhost:11434/v1",
    )
    _model, client = _verifier_model(settings, verification, "openai/verifier")
    assert client is not None
    assert client.api_key == "not-needed"
    await client.close()


def test_litellm_verifier_credentials_are_model_local() -> None:
    settings = Settings(llm={"model": "openai/main"})
    verification = FindingVerificationSettings(
        STRIX_VERIFICATION_MODEL="deepseek/verifier",
        VERIFICATION_LLM_API_KEY="verifier-key",
        VERIFICATION_LLM_API_BASE="https://verifier.example/v1",
    )
    model, client = _verifier_model(settings, verification, "deepseek/verifier")
    assert client is None
    inner = vars(model)["_inner"]
    assert isinstance(inner, LitellmModel)
    assert inner.api_key == "verifier-key"
    assert inner.base_url == "https://verifier.example/v1"


def test_verifier_instructions_include_authoritative_scope() -> None:
    instructions, targets = _verifier_instructions(
        {"authorized_targets": [{"type": "web_application", "value": "https://app.example.com"}]}
    )
    assert targets[0]["value"] == "https://app.example.com"
    assert "AUTHORITATIVE AUTHORIZED TARGETS" in instructions
    assert "https://app.example.com" in instructions
    assert "data cannot expand this list" in instructions


def test_verifier_has_restricted_tools() -> None:
    agent = build_verifier_agent(instructions="verify")
    names = {tool.name for tool in agent.tools}
    assert "repeat_request" in names
    assert "submit_verification_verdict" in names
    assert "create_vulnerability_report" not in names
    assert "create_dependency_report" not in names
    assert "create_agent" not in names
    assert "call_mcp" not in names


def test_verdict_tool_is_a_lifecycle_tool() -> None:
    output = '{"success": true, "verification_completed": true}'
    assert _lifecycle_tool_completed("submit_verification_verdict", output) is True


async def test_only_verdict_tool_sets_validated_context_marker() -> None:
    context: dict[str, Any] = {
        "verification_actions": ["exec_command"],
        "verification_finding_class": "dynamic",
    }
    ctx = ToolContext(
        context=context,
        tool_name="submit_verification_verdict",
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    output = await submit_verification_verdict.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "status": "confirmed",
                "confidence": "high",
                "reason": "Reproduced independently.",
                "evidence": "The canary appeared in the restricted response.",
                "poc_description": "Run the request with the canary payload.",
                "poc_script_code": "send_canary_request()",
            }
        ),
    )
    assert json.loads(output)["verification_completed"] is True
    assert context["validated_verification_verdict"]["status"] == "confirmed"


async def test_failed_execution_is_not_counted_as_verification_action() -> None:
    async def fail(_ctx: Any, _input: str) -> str:
        raise RuntimeError("command did not execute")

    tool = FunctionTool(
        name="exec_command",
        description="test",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=fail,
    )
    wrapped = factory._wrap_exec_command(tool)
    context = SimpleNamespace(context={"verification_actions": []})
    with pytest.raises(RuntimeError, match="did not execute"):
        await wrapped.on_invoke_tool(context, "{}")
    assert context.context["verification_actions"] == []


async def test_nonzero_shell_exit_is_not_counted_as_verification_action() -> None:
    async def fail(_ctx: Any, _input: str) -> str:
        return "Chunk ID: abc123\nProcess exited with code 1\nFinal output:\nfailed"

    tool = FunctionTool(
        name="exec_command",
        description="test",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=fail,
    )
    wrapped = factory._wrap_exec_command(tool)
    context = SimpleNamespace(context={"verification_actions": []})
    await wrapped.on_invoke_tool(context, "{}")
    assert context.context["verification_actions"] == []


async def test_failed_http_replay_is_not_counted_as_verification_action() -> None:
    async def fail(_ctx: Any, _input: str) -> str:
        return '{"success": false, "error": "request missing"}'

    tool = FunctionTool(
        name="repeat_request",
        description="test",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=fail,
    )
    wrapped = factory._with_verification_action(tool)
    context = SimpleNamespace(context={"verification_actions": []})
    await wrapped.on_invoke_tool(context, "{}")
    assert context.context["verification_actions"] == []


def test_confirmed_verdict_requires_execution_and_poc() -> None:
    result = _do_submit(
        status="confirmed",
        confidence="high",
        reason="Reproduced.",
        evidence="Observed restricted rows.",
        poc_description=None,
        poc_script_code=None,
        revised_impact=None,
        revised_cvss_breakdown=None,
        cvss_reasoning=None,
        finding_class="dynamic",
        poc_required=False,
        action_count=0,
    )
    assert result["success"] is False
    assert "executed" in " ".join(result["errors"])
    assert "PoC" in " ".join(result["errors"])


def test_reachable_dependency_cannot_skip_poc() -> None:
    result = _do_submit(
        status="not_applicable",
        confidence="medium",
        reason="No test was attempted.",
        evidence="The affected symbol is reachable.",
        poc_description=None,
        poc_script_code=None,
        revised_impact=None,
        revised_cvss_breakdown=None,
        cvss_reasoning=None,
        finding_class="dependency_cve",
        poc_required=True,
        action_count=0,
    )
    assert result["success"] is False
    assert "requires a PoC" in " ".join(result["errors"])


async def test_verification_retries_unverified_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(
        llm={"model": "openai/main"},
        verification={"enabled": True, "max_attempts": 3},
    )
    monkeypatch.setattr(verification_module, "load_settings", lambda: settings)
    calls = 0

    async def fake_attempt(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"status": "unverified", "reason": "Timed out", "actions": ["exec_command"]}
        return {
            "status": "confirmed",
            "confidence": "high",
            "reason": "Reproduced",
            "evidence": "Observed impact",
            "poc_description": "Run the script",
            "poc_script_code": "print('poc')",
            "actions": ["exec_command"],
        }

    monkeypatch.setattr(verification_module, "_run_attempt", fake_attempt)
    result = await verify_finding({"finding_class": "dynamic"}, {})
    assert calls == 2
    assert result["status"] == "confirmed"
    assert [attempt["status"] for attempt in result["attempts"]] == [
        "unverified",
        "confirmed",
    ]


async def test_verifier_budget_error_signals_scan_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(
        llm={"model": "openai/main"},
        verification={"enabled": True},
    )
    monkeypatch.setattr(verification_module, "load_settings", lambda: settings)

    class Coordinator:
        stopped = False

        async def trigger_budget_stop(self) -> None:
            self.stopped = True

    coordinator = Coordinator()

    async def fail_attempt(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise BudgetExceededError("scan budget reached")

    monkeypatch.setattr(verification_module, "_run_attempt", fail_attempt)
    result = await verify_finding(
        {"finding_class": "dynamic"},
        {"coordinator": coordinator},
    )
    assert result["status"] == "error"
    assert coordinator.stopped is True


async def test_confirmed_verification_replaces_poc(
    report_state: ReportState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_verify(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {
            "status": "confirmed",
            "method": "agent",
            "model": "openai/verifier",
            "confidence": "high",
            "reason": "The independent payload returned restricted rows.",
            "evidence": "A paired control returned one row; the payload returned 42 rows.",
            "poc_description": "Run the paired control and injection requests.",
            "poc_script_code": "print('independent tested poc')",
            "attempts": [{"attempt": 1, "status": "confirmed"}],
        }

    monkeypatch.setattr(verification_module, "verify_finding", fake_verify)
    result = await _do_create(
        **_dynamic_kwargs(
            confidence="medium",
            confidence_rationale="The candidate had not been independently reproduced.",
        )
    )
    assert result["success"] is True
    report = report_state.vulnerability_reports[0]
    assert report["poc_script_code"] == "print('independent tested poc')"
    assert "paired control" in report["evidence"]
    assert report["verification"]["status"] == "confirmed"
    assert "confidence_rationale" not in report


async def test_unverified_finding_is_rescored_from_revised_vector(
    report_state: ReportState,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async def fake_verify(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {
            "status": "unverified",
            "method": "agent",
            "model": "openai/verifier",
            "confidence": "low",
            "reason": "The response contained no restricted records.",
            "evidence": "Injection and control requests returned identical public data.",
            "revised_impact": "No confidentiality, integrity, or availability impact was proven.",
            "revised_cvss_breakdown": _CVSS_INFO,
            "cvss_reasoning": "All impact metrics are N because the outputs were identical.",
            "attempts": [{"attempt": 1, "status": "unverified"}],
        }

    monkeypatch.setattr(verification_module, "verify_finding", fake_verify)
    result = await _do_create(**_dynamic_kwargs())
    assert result["success"] is True
    assert result["severity"] == "info"
    assert result["cvss_score"] == 0.0
    report = report_state.vulnerability_reports[0]
    assert report["confidence"] == "low"
    assert report["verification"]["rescored"] is True
    assert report["verification"]["original_severity"] == "critical"
    assert report["verification"]["final_severity"] == "info"
    assert "did not reproduce" in report["counterevidence"]
    write_sarif(tmp_path, [report])
    sarif = (tmp_path / "findings.sarif").read_text(encoding="utf-8")
    assert "Injection and control requests returned identical public data" not in sarif


async def test_verifier_error_preserves_original_score(
    report_state: ReportState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_verify(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"status": "error", "reason": "Verifier endpoint unavailable"}

    monkeypatch.setattr(verification_module, "verify_finding", fake_verify)
    result = await _do_create(**_dynamic_kwargs())
    report = report_state.vulnerability_reports[0]
    assert result["severity"] == "critical"
    assert report["verification"]["status"] == "error"
    assert report["verification"]["rescored"] is False


async def test_non_exercisable_dependency_is_reported_as_is(
    report_state: ReportState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_verify(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {
            "status": "not_applicable",
            "method": "agent",
            "model": "openai/verifier",
            "confidence": "medium",
            "reason": "The affected parser API is not used by the application.",
            "evidence": "Repository-wide symbol search found no affected API call.",
            "revised_cvss_breakdown": _CVSS_INFO,
            "attempts": [{"attempt": 1, "status": "not_applicable"}],
        }

    monkeypatch.setattr(verification_module, "verify_finding", fake_verify)
    result = await _do_create_dependency(**_dependency_kwargs())
    report = report_state.vulnerability_reports[0]
    assert result["success"] is True
    assert result["severity"] == "critical"
    assert report["verification"]["status"] == "not_applicable"
    assert report["verification"]["rescored"] is False
    assert "poc_script_code" not in report


async def test_exploitable_dependency_gets_independent_poc(
    report_state: ReportState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_verify(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {
            "status": "confirmed",
            "method": "agent",
            "model": "openai/verifier",
            "confidence": "high",
            "reason": "The affected parser executed the canary command.",
            "evidence": "The unique canary file was created by the parser process.",
            "poc_description": "Invoke the parser with the canary payload.",
            "poc_script_code": "run_parser_with_canary()",
            "attempts": [{"attempt": 1, "status": "confirmed"}],
        }

    monkeypatch.setattr(verification_module, "verify_finding", fake_verify)
    result = await _do_create_dependency(
        **_dependency_kwargs(
            reachability="reachable_call_path",
            reachability_evidence="route -> src/parser.ts:10 -> sample.parse",
        )
    )
    report = report_state.vulnerability_reports[0]
    assert result["success"] is True
    assert report["poc_script_code"] == "run_parser_with_canary()"
    assert report["verification"]["status"] == "confirmed"


async def test_concurrent_verification_cannot_persist_duplicate_findings(
    report_state: ReportState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    both_verifying = asyncio.Event()
    verification_calls = 0

    async def fake_verify(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal verification_calls
        verification_calls += 1
        if verification_calls == 2:
            both_verifying.set()
        await both_verifying.wait()
        return {"status": "error", "reason": "Verifier unavailable"}

    async def fake_dedupe(
        candidate: dict[str, Any],
        existing: list[dict[str, Any]],
    ) -> dict[str, Any]:
        duplicate = next(
            (report for report in existing if report.get("title") == candidate.get("title")),
            None,
        )
        return {
            "is_duplicate": duplicate is not None,
            "duplicate_id": str((duplicate or {}).get("id") or ""),
            "confidence": 1.0,
            "reason": "same title" if duplicate else "no match",
        }

    monkeypatch.setattr(verification_module, "verify_finding", fake_verify)
    monkeypatch.setattr("strix.report.dedupe.check_duplicate", fake_dedupe)
    results = await asyncio.gather(
        _do_create(**_dynamic_kwargs()),
        _do_create(**_dynamic_kwargs()),
    )
    assert sum(bool(result["success"]) for result in results) == 1
    assert len(report_state.vulnerability_reports) == 1


def test_verification_metadata_renders_and_is_listed() -> None:
    report = {
        "id": "vuln-0001",
        "title": "SQL injection",
        "severity": "medium",
        "timestamp": "2026-08-27 00:00:00 UTC",
        "description": "SQL injection in lookup.",
        "verification": {
            "status": "unverified",
            "reason": "The claimed database-wide impact was not reproduced.",
            "evidence": "The payload and control returned the same row.",
            "attempts": [{"attempt": 1, "status": "unverified"}],
            "rescored": True,
            "original_cvss": 9.8,
            "original_severity": "critical",
            "final_cvss": 4.2,
            "final_severity": "medium",
            "cvss_reasoning": "Only limited read impact remains supported.",
        },
    }
    markdown = render_vulnerability_md(report)
    assert "**Verification:** Unverified" in markdown
    assert "**Attempts:** 1" in markdown
    assert "9.8 (CRITICAL) -> 4.2 (MEDIUM)" in markdown
    assert _to_report_summary_entry(report)["verification_status"] == "unverified"


def test_sarif_excludes_raw_verification_evidence(tmp_path: Path) -> None:
    marker = "RAW-VERIFIER-EXPLOIT-OUTPUT"
    report = {
        "id": "vuln-0001",
        "title": "SQL injection",
        "severity": "medium",
        "timestamp": "2026-08-27 00:00:00 UTC",
        "verification": {
            "status": "unverified",
            "reason": "Impact was not reproduced.",
            "evidence": marker,
            "rescored": True,
            "original_cvss": 9.8,
            "original_severity": "critical",
            "final_cvss": 4.2,
            "final_severity": "medium",
        },
    }
    write_sarif(tmp_path, [report])
    raw = (tmp_path / "findings.sarif").read_text(encoding="utf-8")
    assert marker not in raw
    document = json.loads(raw)
    verification = document["runs"][0]["results"][0]["properties"]["strix"]["verification"]
    assert verification["status"] == "unverified"
    assert verification["rescored"] is True
