"""The safety model may decide immediately or use one inspection call."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Literal

import pytest
from agents import Agent, Runner
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.tool_context import ToolContext
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

import strix.safety.reviewer as reviewer_module
from strix.config.settings import SafetySettings
from strix.safety.evidence import EvidenceBundle
from strix.safety.reviewer import SafetyReviewer, run_inspection
from strix.safety.types import InspectionContext, SafetyVerdict


if TYPE_CHECKING:
    from pytest import MonkeyPatch


class _InspectionRunner:
    def __init__(self) -> None:
        self.calls = 0

    async def run(self, *, evidence_dir: str, script: str) -> str:
        self.calls += 1
        return f"inspected {Path(evidence_dir).name}: {script}"


class _Result:
    def __init__(self, verdict: SafetyVerdict) -> None:
        self._verdict = verdict
        self.context_wrapper = SimpleNamespace(usage=SimpleNamespace())

    def final_output_as(self, _cls: type[Any], *, raise_if_incorrect_type: bool) -> SafetyVerdict:
        assert raise_if_incorrect_type is True
        return self._verdict


def _settings() -> Any:
    return SimpleNamespace(
        safety=SafetySettings(model="test-model"),
        llm=SimpleNamespace(
            model="main-model",
            extra_headers=None,
        ),
    )


@pytest.mark.asyncio
async def test_reviewer_is_capped_at_two_turns_and_zero_retries(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def fake_run(agent: Any, *, input: str, context: Any, max_turns: int) -> _Result:  # noqa: A002
        captured.update(agent=agent, input=input, context=context, max_turns=max_turns)
        return _Result(
            SafetyVerdict(
                decision="allow",
                risk="low",
                categories=[],
                reason="read only",
                confidence=0.99,
            )
        )

    monkeypatch.setattr(reviewer_module, "load_settings", _settings)
    monkeypatch.setattr(reviewer_module, "configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr(
        reviewer_module.StrixProvider, "get_model", lambda _self, _name: "test-model"
    )
    monkeypatch.setattr(reviewer_module.Runner, "run", fake_run)
    monkeypatch.setattr(reviewer_module, "get_global_report_state", lambda: None)
    bundle = EvidenceBundle(
        case_id="case-1",
        root=tmp_path,
        packet={"completeness": {"status": "complete"}},
        complete=True,
        incomplete_reasons=[],
    )

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(bundle)

    assert decision.allowed is True
    assert captured["max_turns"] == 2
    assert [tool.name for tool in captured["agent"].tools] == ["run_inspection"]
    assert captured["agent"].model_settings.retry.max_retries == 0
    # The cap also covers reasoning tokens; a verdict-sized budget would truncate the
    # structured output on a reasoning model and fail every review closed.
    assert captured["agent"].model_settings.max_tokens == SafetySettings().max_output_tokens


@pytest.mark.asyncio
async def test_review_budget_covers_both_turns_and_the_inspection(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def fake_wait_for(awaitable: Any, *, timeout: float) -> Any:
        captured["timeout"] = timeout
        return await awaitable

    async def fake_run(_agent: Any, **_kwargs: Any) -> _Result:
        return _Result(
            SafetyVerdict(
                decision="allow",
                risk="low",
                categories=[],
                reason="read only",
                confidence=0.99,
            )
        )

    monkeypatch.setattr(reviewer_module, "load_settings", _settings)
    monkeypatch.setattr(reviewer_module, "configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr(
        reviewer_module.StrixProvider, "get_model", lambda _self, _name: "test-model"
    )
    monkeypatch.setattr(reviewer_module.Runner, "run", fake_run)
    monkeypatch.setattr(reviewer_module, "get_global_report_state", lambda: None)
    monkeypatch.setattr(reviewer_module.asyncio, "wait_for", fake_wait_for)
    bundle = EvidenceBundle(
        case_id="case-budget",
        root=tmp_path,
        packet={"completeness": {"status": "complete"}},
        complete=True,
        incomplete_reasons=[],
    )

    await SafetyReviewer(inspection_runner=_InspectionRunner()).review(bundle)

    safety = SafetySettings()
    assert captured["timeout"] == 2 * safety.timeout + safety.inspection_timeout


@pytest.mark.asyncio
async def test_inspection_tool_can_only_run_once(tmp_path: Path) -> None:
    runner = _InspectionRunner()
    state = InspectionContext(evidence_dir=str(tmp_path), runner=runner)
    ctx = ToolContext(
        context=state,
        tool_name="run_inspection",
        tool_call_id="inspect-1",
        tool_arguments="{}",
    )
    raw = json.dumps({"reason": "correlate files", "script": "print('ok')"})

    first = await run_inspection.on_invoke_tool(ctx, raw)
    second = await run_inspection.on_invoke_tool(ctx, raw)

    assert "inspected" in first
    assert "already used" in second
    assert runner.calls == 1
    assert state.attempts == 2
    assert state.incomplete is True


@pytest.mark.asyncio
async def test_inspection_collects_workspace_files_before_running_script(tmp_path: Path) -> None:
    collected: list[tuple[str, ...]] = []

    async def collect(paths: tuple[str, ...]) -> tuple[str, bool]:
        collected.append(paths)
        return '{"workspace_artifacts":[{"path":"/workspace/hosts.txt"}]}', False

    runner = _InspectionRunner()
    state = InspectionContext(
        evidence_dir=str(tmp_path),
        runner=runner,
        collect_workspace=collect,
    )
    ctx = ToolContext(
        context=state,
        tool_name="run_inspection",
        tool_call_id="inspect-collect",
        tool_arguments="{}",
    )

    result = await run_inspection.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "reason": "resolve host list",
                "workspace_paths": ["/workspace/hosts.txt"],
                "script": "print('analyzed')",
            }
        ),
    )

    assert collected == [("/workspace/hosts.txt",)]
    assert "workspace_artifacts" in result
    assert "inspected" in result
    assert runner.calls == 1


@pytest.mark.asyncio
async def test_inspection_can_collect_without_analysis_script(tmp_path: Path) -> None:
    async def collect(_paths: tuple[str, ...]) -> tuple[str, bool]:
        return "collected file", False

    state = InspectionContext(
        evidence_dir=str(tmp_path),
        runner=_InspectionRunner(),
        collect_workspace=collect,
    )
    ctx = ToolContext(
        context=state,
        tool_name="run_inspection",
        tool_call_id="inspect-read",
        tool_arguments="{}",
    )

    result = await run_inspection.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "reason": "read missing file",
                "workspace_paths": ["/workspace/missing.txt"],
            }
        ),
    )

    assert "collected file" in result
    assert state.incomplete is False


@pytest.mark.asyncio
async def test_real_sdk_loop_replays_inspection_output_into_second_turn(tmp_path: Path) -> None:
    class LoopModel(Model):
        def __init__(self) -> None:
            self.inputs: list[Any] = []
            self.tool_names: list[list[str]] = []

        async def get_response(self, *_args: Any, **kwargs: Any) -> ModelResponse:
            self.inputs.append(kwargs["input"])
            self.tool_names.append([tool.name for tool in kwargs["tools"]])
            if len(self.inputs) == 1:
                return ModelResponse(
                    output=[
                        ResponseFunctionToolCall(
                            call_id="inspect-call",
                            name="run_inspection",
                            arguments=json.dumps(
                                {
                                    "reason": "read host list",
                                    "workspace_paths": ["/workspace/hosts.txt"],
                                }
                            ),
                            type="function_call",
                        )
                    ],
                    usage=Usage(),
                    response_id="response-1",
                )
            replay = json.dumps(kwargs["input"], default=str)
            assert "function_call_output" in replay
            assert "host-a.example.test" in replay
            verdict = SafetyVerdict(
                decision="allow",
                risk="low",
                categories=["read_only_reconnaissance"],
                reason="collected host list proves one bounded GET",
                confidence=0.99,
            ).model_dump_json()
            return ModelResponse(
                output=[
                    ResponseOutputMessage.model_construct(
                        id="message-1",
                        type="message",
                        role="assistant",
                        status="completed",
                        content=[
                            ResponseOutputText(
                                type="output_text",
                                text=verdict,
                                annotations=[],
                            )
                        ],
                    )
                ],
                usage=Usage(),
                response_id="response-2",
            )

        def stream_response(self, *_args: Any, **_kwargs: Any) -> Any:
            raise NotImplementedError

    async def collect(_paths: tuple[str, ...]) -> tuple[str, bool]:
        return '{"path":"/workspace/hosts.txt","source":"host-a.example.test"}', False

    model = LoopModel()
    agent: Agent[InspectionContext] = Agent(
        name="Safety loop test",
        instructions="Use the tool once, then return the typed verdict.",
        model=model,
        tools=[run_inspection],
        output_type=SafetyVerdict,
        tool_use_behavior="run_llm_again",
    )
    context = InspectionContext(
        evidence_dir=str(tmp_path),
        runner=_InspectionRunner(),
        collect_workspace=collect,
    )

    result = await Runner.run(agent, input="deterministic packet", context=context, max_turns=2)

    assert result.final_output_as(SafetyVerdict).decision == "allow"
    assert model.tool_names == [["run_inspection"], []]
    assert len(model.inputs) == 2


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patched_sdk")
async def test_repeated_inspection_attempt_fails_review_closed(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    async def fake_run(_agent: Any, *, context: Any, **_kwargs: Any) -> _Result:
        context.used = True
        context.attempts = 2
        return _Result(
            SafetyVerdict(
                decision="defer",
                risk="medium",
                categories=[],
                reason="still uncertain",
                confidence=0.9,
            )
        )

    monkeypatch.setattr(reviewer_module.Runner, "run", fake_run)

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(
        _incomplete_bundle(tmp_path, "case-repeated-inspection"),
        human_approval_available=True,
    )

    assert decision.source == "review_error"
    assert decision.categories == ("inspection_repeated",)


@pytest.mark.asyncio
async def test_reviewer_failure_blocks(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    async def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("provider down")

    monkeypatch.setattr(reviewer_module, "load_settings", _settings)
    monkeypatch.setattr(reviewer_module, "configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr(
        reviewer_module.StrixProvider, "get_model", lambda _self, _name: "test-model"
    )
    monkeypatch.setattr(reviewer_module.Runner, "run", fail)
    bundle = EvidenceBundle(
        case_id="case-2",
        root=tmp_path,
        packet={"completeness": {"status": "complete"}},
        complete=True,
        incomplete_reasons=[],
    )

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(bundle)

    assert decision.allowed is False
    assert decision.source == "review_error"


@pytest.fixture
def _patched_sdk(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(reviewer_module, "load_settings", _settings)
    monkeypatch.setattr(reviewer_module, "configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr(
        reviewer_module.StrixProvider, "get_model", lambda _self, _name: "test-model"
    )
    monkeypatch.setattr(reviewer_module, "get_global_report_state", lambda: None)


def _bundle(tmp_path: Path, case_id: str) -> EvidenceBundle:
    return EvidenceBundle(
        case_id=case_id,
        root=tmp_path,
        packet={"completeness": {"status": "complete"}},
        complete=True,
        incomplete_reasons=[],
    )


def _incomplete_bundle(tmp_path: Path, case_id: str) -> EvidenceBundle:
    return EvidenceBundle(
        case_id=case_id,
        root=tmp_path,
        packet={
            "completeness": {
                "status": "incomplete",
                "reasons": ["dynamic network destination"],
            }
        },
        complete=False,
        incomplete_reasons=["dynamic network destination"],
    )


def _reviewable_bundle(tmp_path: Path, case_id: str) -> EvidenceBundle:
    return EvidenceBundle(
        case_id=case_id,
        root=tmp_path,
        packet={
            "completeness": {
                "status": "reviewable",
                "hard_gaps": [],
                "reviewable_issues": ["dynamic network destination"],
            }
        },
        complete=True,
        incomplete_reasons=[],
        reviewable_issues=["dynamic network destination"],
    )


def _verdict_run(verdict: SafetyVerdict) -> Any:
    async def fake_run(_agent: Any, **_kwargs: Any) -> _Result:
        return _Result(verdict)

    return fake_run


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patched_sdk")
async def test_low_confidence_allow_is_refused(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    """An allow the reviewer is unsure of is the case the threshold exists for."""
    monkeypatch.setattr(
        reviewer_module.Runner,
        "run",
        _verdict_run(
            SafetyVerdict(
                decision="allow",
                risk="medium",
                categories=["target_mutation"],
                reason="probably fine",
                confidence=0.5,
            )
        ),
    )

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(
        _bundle(tmp_path, "case-low-confidence")
    )

    assert decision.allowed is False
    assert decision.deferred is False
    assert decision.source == "reviewer"
    assert "below the 0.75 threshold" in decision.reason
    assert decision.categories == ("target_mutation",)


@pytest.mark.parametrize("model_decision", ["allow", "block"])
@pytest.mark.asyncio
@pytest.mark.usefixtures("_patched_sdk")
async def test_interactive_low_confidence_verdict_defers(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    model_decision: Literal["allow", "block"],
) -> None:
    monkeypatch.setattr(
        reviewer_module.Runner,
        "run",
        _verdict_run(
            SafetyVerdict(
                decision=model_decision,
                risk="medium",
                categories=["ambiguous_effect"],
                reason="effect is unclear",
                confidence=0.5,
            )
        ),
    )

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(
        _bundle(tmp_path, f"case-low-{model_decision}"),
        human_approval_available=True,
    )

    assert decision.allowed is False
    assert decision.deferred is True
    assert decision.risk == "medium"
    assert "below the 0.75 threshold" in decision.reason


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patched_sdk")
async def test_explicit_defer_requires_an_approval_channel(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reviewer_module.Runner,
        "run",
        _verdict_run(
            SafetyVerdict(
                decision="defer",
                risk="high",
                categories=["ambiguous_effect"],
                reason="persistence depends on endpoint behavior",
                confidence=0.9,
            )
        ),
    )
    reviewer = SafetyReviewer(inspection_runner=_InspectionRunner())

    interactive = await reviewer.review(
        _bundle(tmp_path, "case-explicit-interactive"),
        human_approval_available=True,
    )
    noninteractive = await reviewer.review(_bundle(tmp_path, "case-explicit-headless"))

    assert interactive.deferred is True
    assert interactive.risk == "high"
    assert noninteractive.allowed is False
    assert noninteractive.deferred is False
    assert "no human approval channel" in noninteractive.reason


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patched_sdk")
async def test_interactive_incomplete_evidence_can_defer_without_inspection(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reviewer_module.Runner,
        "run",
        _verdict_run(
            SafetyVerdict(
                decision="defer",
                risk="medium",
                categories=["incomplete_evidence"],
                reason="destination remains unknown",
                confidence=0.9,
            )
        ),
    )

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(
        _incomplete_bundle(tmp_path, "case-uninspected"),
        human_approval_available=True,
    )

    assert decision.allowed is False
    assert decision.deferred is True
    assert decision.source == "reviewer"
    assert decision.categories == ("incomplete_evidence",)


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patched_sdk")
async def test_confident_allow_without_inspection_is_respected_despite_a_hard_gap(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    # A confident allow stands even when the optional inspection is unnecessary:
    # the packet already proves that the missing file is an output, not an input.
    async def fake_run(_agent: Any, **_kwargs: Any) -> _Result:
        return _Result(
            SafetyVerdict(
                decision="allow",
                risk="low",
                categories=["read_only_reconnaissance"],
                reason="the missing file is an output the command creates, not an input",
                confidence=0.95,
            )
        )

    monkeypatch.setattr(reviewer_module.Runner, "run", fake_run)

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(
        _incomplete_bundle(tmp_path, "case-uninspected-allow"),
        human_approval_available=True,
    )

    assert decision.allowed is True
    assert decision.deferred is False
    assert "the missing file is an output the command creates" in decision.reason


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patched_sdk")
async def test_unsure_allow_on_a_hard_gap_still_defers_to_human(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    # The confidence gate is the backstop: an allow the reviewer is not confident
    # in does not slip through on a hard gap, it defers.
    async def fake_run(_agent: Any, *, context: Any, **_kwargs: Any) -> _Result:
        context.used = True
        return _Result(
            SafetyVerdict(
                decision="allow",
                risk="medium",
                categories=["incomplete_evidence"],
                reason="probably fine but I am not sure",
                confidence=0.5,
            )
        )

    monkeypatch.setattr(reviewer_module.Runner, "run", fake_run)

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(
        _incomplete_bundle(tmp_path, "case-unsure"),
        human_approval_available=True,
    )

    assert decision.allowed is False
    assert decision.deferred is True
    assert "0.75 threshold" in decision.reason


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patched_sdk")
async def test_reviewable_issue_can_be_allowed_after_inspection(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    async def fake_run(_agent: Any, *, context: Any, **_kwargs: Any) -> _Result:
        context.used = True
        return _Result(
            SafetyVerdict(
                decision="allow",
                risk="low",
                categories=["read_only_reconnaissance"],
                reason="inspection resolved the destination and found fixed GET requests",
                confidence=0.95,
            )
        )

    monkeypatch.setattr(reviewer_module.Runner, "run", fake_run)

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(
        _reviewable_bundle(tmp_path, "case-reviewable")
    )

    assert decision.allowed is True
    assert decision.deferred is False
    assert decision.source == "reviewer"


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patched_sdk")
async def test_collected_workspace_file_can_resolve_hard_gap_and_allow(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    bundle = _incomplete_bundle(tmp_path, "case-collected-hard-gap")

    async def collect(paths: tuple[str, ...]) -> tuple[str, bool]:
        assert paths == ("/workspace/hosts.txt",)
        bundle.incomplete_reasons.clear()
        bundle.complete = True
        bundle.packet["completeness"] = {
            "status": "complete",
            "hard_gaps": [],
            "reviewable_issues": [],
        }
        return "collected hosts", False

    async def fake_run(_agent: Any, *, context: Any, **_kwargs: Any) -> _Result:
        assert context.collect_workspace is not None
        await context.collect_workspace(("/workspace/hosts.txt",))
        context.used = True
        return _Result(
            SafetyVerdict(
                decision="allow",
                risk="low",
                categories=["read_only_reconnaissance"],
                reason="collected host list proves bounded GET requests",
                confidence=0.95,
            )
        )

    monkeypatch.setattr(reviewer_module.Runner, "run", fake_run)

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(
        bundle,
        human_approval_available=True,
        workspace_collector=collect,
    )

    assert decision.allowed is True
    assert decision.deferred is False


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patched_sdk")
async def test_reviewable_issue_can_be_allowed_without_inspection(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reviewer_module.Runner,
        "run",
        _verdict_run(
            SafetyVerdict(
                decision="allow",
                risk="low",
                categories=[],
                reason="looks safe",
                confidence=0.95,
            )
        ),
    )

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(
        _reviewable_bundle(tmp_path, "case-reviewable-uninspected")
    )

    assert decision.allowed is True
    assert decision.source == "reviewer"
    assert decision.reason == "looks safe"


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patched_sdk")
async def test_confident_allow_passes(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(
        reviewer_module.Runner,
        "run",
        _verdict_run(
            SafetyVerdict(
                decision="allow",
                risk="low",
                categories=[],
                reason="read only",
                confidence=0.8,
            )
        ),
    )

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(
        _bundle(tmp_path, "case-confident")
    )

    assert decision.allowed is True
    assert decision.source == "reviewer"


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patched_sdk")
async def test_block_verdict_is_returned_as_a_block(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reviewer_module.Runner,
        "run",
        _verdict_run(
            SafetyVerdict(
                decision="block",
                risk="high",
                categories=["state_mutation"],
                reason="deletes a record",
                confidence=0.99,
            )
        ),
    )

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(
        _bundle(tmp_path, "case-block")
    )

    assert decision.allowed is False
    assert decision.deferred is False
    assert decision.source == "reviewer"
    assert decision.reason == "deletes a record"


@pytest.mark.asyncio
async def test_missing_model_configuration_blocks(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reviewer_module,
        "load_settings",
        lambda: SimpleNamespace(
            safety=SafetySettings(model=None),
            llm=SimpleNamespace(model="", extra_headers=None),
        ),
    )

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(
        _bundle(tmp_path, "case-no-model")
    )

    assert decision.allowed is False
    assert decision.source == "review_error"
    assert decision.categories == ("review_unavailable",)


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patched_sdk")
@pytest.mark.parametrize("model_decision", ["allow", "defer"])
async def test_non_block_after_a_failed_inspection_is_refused(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    model_decision: Literal["allow", "defer"],
) -> None:
    """The reviewer decides from the inspection's own output, so an inspection that failed
    must not be able to underwrite an allow."""

    async def fake_run(_agent: Any, *, context: Any, **_kwargs: Any) -> _Result:
        context.incomplete = True
        return _Result(
            SafetyVerdict(
                decision=model_decision,
                risk="low",
                categories=[],
                reason="looked fine",
                confidence=0.99,
            )
        )

    monkeypatch.setattr(reviewer_module.Runner, "run", fake_run)

    decision = await SafetyReviewer(inspection_runner=_InspectionRunner()).review(
        _bundle(tmp_path, "case-bad-inspection"),
        human_approval_available=True,
    )

    assert decision.allowed is False
    assert decision.deferred is False
    assert decision.categories == ("inspection_incomplete",)


@pytest.mark.parametrize(
    "output",
    [
        "Inspection failed: frozen evidence directory is unavailable.",
        "Inspection exit code: 1",
        "... output truncated ...",
    ],
)
@pytest.mark.asyncio
async def test_inspection_failure_output_is_recognized(tmp_path: Path, output: str) -> None:
    """These strings are produced in inspection.py and matched by substring here, so a
    reword on either side silently stops marking failed inspections."""

    class _Failing:
        async def run(self, *, evidence_dir: str, script: str) -> str:  # noqa: ARG002
            return output

    state = InspectionContext(evidence_dir=str(tmp_path), runner=_Failing())
    ctx = ToolContext(
        context=state,
        tool_name="run_inspection",
        tool_call_id="inspect-1",
        tool_arguments="{}",
    )

    await run_inspection.on_invoke_tool(
        ctx, json.dumps({"reason": "check", "script": "print('x')"})
    )

    assert state.incomplete is True


def test_prompt_judges_security_testing_by_effect_not_technique() -> None:
    """Pins the effect-based guardrails so a future edit cannot silently revert to
    blocking in-scope offensive testing on the technique alone."""
    prompt = reviewer_module._SAFETY_PROMPT
    normalized = " ".join(prompt.split())

    # Authorization framing and the effect-not-technique rule.
    assert "authorized penetration test" in prompt
    assert "not, by itself, a reason to block" in normalized
    # Read probes pass; writes and destruction block.
    assert "OR 1=1" in prompt
    for keyword in ("DROP", "DELETE", "INSERT", "TRUNCATE", "OUTFILE", "xp_cmdshell"):
        assert keyword in prompt
    # Scope enforcement belongs elsewhere, including for passive third-party services.
    assert "Do not enforce authorization scope" in prompt
    assert "crt.sh" in prompt
    assert "solely because their hostname is outside" in prompt
    # Ambiguity only reaches a human when an approval channel exists.
    assert "Return defer only when approval is available" in prompt
    assert "Without human approval, ambiguity must block" in normalized
    assert "The inspection call is optional" in normalized
    # A hard gap is judged by relevance, not blocked outright.
    assert "A hard gap is missing evidence, not proof of danger" in normalized
    assert "do not block or defer merely because a gap remains" in normalized
    assert "an output that does not exist yet" in normalized
    # Non-negotiable guardrails survive.
    assert 'do not defer merely because completeness.status is "reviewable"' in normalized
    assert "Deterministic policy blocks cannot be overridden" in prompt
    assert "analysis.mutating_request" in prompt


def test_prompt_explains_input_files() -> None:
    prompt = " ".join(reviewer_module._SAFETY_PROMPT.split())
    assert 'role "input"' in prompt
