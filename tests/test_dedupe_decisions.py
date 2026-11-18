"""Only validated model decisions may suppress a finding."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest
from agents.items import ModelResponse
from agents.usage import Usage
from openai.types.responses import ResponseOutputMessage, ResponseOutputText

from strix.config import loader
from strix.report import dedupe
from strix.report.state import ReportState, get_global_report_state, set_global_report_state
from strix.tools.reporting.tool import _do_create


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReportState]:
    monkeypatch.chdir(tmp_path)
    previous = get_global_report_state()
    state = ReportState(run_name="dedupe-decisions")
    set_global_report_state(state)
    state.add_vulnerability_report(title="Existing finding", severity="low")
    try:
        yield state
    finally:
        set_global_report_state(previous)


def _mock_judge(monkeypatch: pytest.MonkeyPatch, decision: dict[str, Any]) -> AsyncMock:
    settings = loader.load_settings().model_copy(deep=True)
    settings.llm.model = "openai/synthetic-model"
    model = AsyncMock()
    model.get_response.return_value = ModelResponse(
        output=[
            ResponseOutputMessage(
                id="msg_synthetic",
                type="message",
                role="assistant",
                status="completed",
                content=[
                    ResponseOutputText(
                        type="output_text",
                        annotations=[],
                        text=json.dumps({"confidence": 0.95, "reason": "Synthetic", **decision}),
                    )
                ],
            )
        ],
        usage=Usage(),
        response_id="synthetic",
    )
    monkeypatch.setattr(dedupe, "load_settings", lambda: settings)
    monkeypatch.setattr(dedupe, "configure_sdk_model_defaults", lambda _: None)
    monkeypatch.setattr(dedupe, "resolve_dedupe_model", lambda *_: model)
    return model


async def _file_finding() -> dict[str, Any]:
    return await _do_create(
        title="New finding",
        description="The endpoint reflects unencoded input.",
        impact="The reflected script executes in a victim's browser.",
        target="https://example.invalid",
        technical_analysis="Input is interpolated into HTML without encoding.",
        poc_description="Open the endpoint with the reflected parameter.",
        poc_script_code="print('synthetic reproduction')",
        remediation_steps="Encode output for its HTML context.",
        evidence="The synthetic response contains the unencoded parameter.",
        assumptions="A victim follows the crafted link.",
        counterevidence="No encoding or content security policy is present.",
        confidence="high",
        severity_change_conditions="A strict content security policy would lower the impact.",
        fix_effort="low",
        cvss_breakdown={
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "R",
            "scope": "U",
            "confidentiality": "L",
            "integrity": "L",
            "availability": "N",
        },
        endpoint="/search",
        method="GET",
        cve=None,
        cwe="CWE-79",
        code_locations=None,
    )


@pytest.mark.parametrize("value", ["false", "true", 0, 1, None, [], {}])
def test_dedupe_parser_requires_a_boolean(value: Any) -> None:
    with pytest.raises(TypeError, match="is_duplicate"):
        dedupe._parse_dedupe_response(json.dumps({"is_duplicate": value}))


@pytest.mark.parametrize(
    "decision",
    [
        {"is_duplicate": "false", "duplicate_id": "vuln-0001"},
        {"is_duplicate": "true", "duplicate_id": "vuln-0001"},
        {"is_duplicate": 1, "duplicate_id": "vuln-0001"},
        {"is_duplicate": True, "duplicate_id": "vuln-9999"},
        {"is_duplicate": True, "duplicate_id": ""},
        {"is_duplicate": True, "duplicate_id": None},
        {"is_duplicate": True, "duplicate_id": ["vuln-0001"]},
        {"is_duplicate": True},
    ],
)
async def test_invalid_dedupe_decision_does_not_suppress_finding(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch, decision: dict[str, Any]
) -> None:
    model = _mock_judge(monkeypatch, decision)

    result = await _file_finding()

    assert result["success"] is True
    model.get_response.assert_awaited_once()
    saved = json.loads((report_state.get_run_dir() / "vulnerabilities.json").read_text())
    assert [report["title"] for report in saved] == ["Existing finding", "New finding"]
    assert (report_state.get_run_dir() / "vulnerabilities" / "vuln-0002.md").is_file()


@pytest.mark.parametrize("is_duplicate", [False, True])
async def test_valid_dedupe_decisions_keep_their_meaning(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch, is_duplicate: bool
) -> None:
    # An extraneous ID must not turn a valid false decision into a duplicate.
    _mock_judge(monkeypatch, {"is_duplicate": is_duplicate, "duplicate_id": "vuln-0001"})

    result = await _file_finding()

    assert result["success"] is not is_duplicate
    saved = json.loads((report_state.get_run_dir() / "vulnerabilities.json").read_text())
    assert len(saved) == (1 if is_duplicate else 2)
    if is_duplicate:
        assert result["duplicate_of"] == "vuln-0001"


async def test_dedupe_id_is_matched_without_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    existing_id = "x" * 64
    _mock_judge(monkeypatch, {"is_duplicate": True, "duplicate_id": existing_id + "-unknown"})

    result = await dedupe.check_duplicate(
        {"title": "New finding"}, [{"id": existing_id, "title": "Existing finding"}]
    )

    assert result["is_duplicate"] is False
    assert "error" in result
