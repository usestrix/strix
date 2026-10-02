"""Real Strix loop + SDK shell/filesystem + customer tests, with scripted inference."""

from __future__ import annotations

import json
import shlex
import sys
import zipfile
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest
from agents import Agent, Model, RunConfig, RunContextWrapper
from agents.exceptions import MaxTurnsExceeded
from agents.items import ModelResponse
from agents.sandbox import SandboxRunConfig
from agents.tool import CustomTool
from agents.usage import Usage
from openai.types.responses import (
    ResponseCustomToolCall,
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

import strix.core.hooks as hooks_module
from strix.config.models import _completed_stream_event
from strix.core.hooks import BudgetExceededError, ReportUsageHooks
from strix.fix import PreparationState
from strix.fix import runtime as fix_runtime
from strix.fix.runtime import _FixHooks
from strix.interface.fix_cli import _summary
from tests.test_fix_reliability import environment, existing_suite
from tests.test_fix_runtime import _request, _workspace


if TYPE_CHECKING:
    from pathlib import Path


def call(name: str, **arguments: Any) -> ResponseFunctionToolCall:
    return ResponseFunctionToolCall(
        type="function_call", name=name, call_id=name, arguments=json.dumps(arguments)
    )


def finish(outcome: str, summary: str = "Fix and validation results reviewed.") -> Any:
    return call("agent_finish", success=outcome == "done", result_summary=summary)


def shell(cmd: str) -> Any:
    return call("exec_command", cmd=cmd, login=False, yield_time_ms=10000)


def patch(value: str = "safe") -> list[Any]:
    production = "def result():\n    return " + repr(value) + "\n"
    regression = (
        "import unittest\nfrom app import result\nclass Security(unittest.TestCase):\n"
        "    def test_safe(self): self.assertEqual(result(),'safe')\n"
    )
    return [
        shell(f"printf %s {shlex.quote(production)} > app.py"),
        shell(f"printf %s {shlex.quote(regression)} > tests/test_security.py"),
    ]


def suite_commands() -> list[Any]:
    python = shlex.quote(sys.executable)
    return [
        shell(f"{python} -m unittest discover -s tests -p test_existing.py"),
        shell(f"{python} -m unittest discover -s tests -p test_security.py"),
    ]


class ScriptedModel(Model):
    def __init__(self, repair: list[Any], review: list[Any] | None = None) -> None:
        self.responses = {
            "repair": repair,
            "review": review if review is not None else [finish("done", "Independently approved.")],
        }
        self.inputs: dict[str, list[Any]] = {"repair": [], "review": []}
        self.tools: set[str] = set()

    async def get_response(self, **kwargs: Any) -> ModelResponse:
        role = "review" if "Independently verify" in kwargs["system_instructions"] else "repair"
        self.inputs[role].append(list(kwargs["input"]))
        self.tools.update(t.name for t in kwargs["tools"])
        assert self.responses[role], f"Unexpected additional {role} turn"
        item = self.responses[role].pop(0)
        if isinstance(item, str):
            item = ResponseOutputMessage(
                id=f"msg-{role}-{len(self.inputs[role])}",
                type="message",
                role="assistant",
                status="completed",
                content=[ResponseOutputText(type="output_text", text=item, annotations=[])],
            )
        else:
            arguments = json.loads(item.arguments)
            item = item.model_copy(
                update={
                    "call_id": f"{role}-{len(self.inputs[role])}",
                    "arguments": json.dumps(arguments),
                }
            )
            if item.name == "apply_patch" and any(
                isinstance(t, CustomTool) and t.name == item.name for t in kwargs["tools"]
            ):
                item = ResponseCustomToolCall(
                    type="custom_tool_call",
                    name=item.name,
                    call_id=item.call_id,
                    input=arguments["patch"],
                )
        return ModelResponse(output=[item], usage=Usage(requests=1), response_id=None)

    async def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        kwargs.update(
            zip(
                [
                    "system_instructions",
                    "input",
                    "model_settings",
                    "tools",
                    "output_schema",
                    "handoffs",
                    "tracing",
                ],
                args,
                strict=False,
            )
        )
        yield _completed_stream_event(await self.get_response(**kwargs), "scripted")


async def scenario(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    model: ScriptedModel,
    turns: int = 30,
    *,
    repair_turns: int | None = None,
    review_turns: int | None = None,
) -> tuple[Any, Any]:
    workspace, _ = _workspace(tmp_path)
    commit = existing_suite(workspace)
    env = environment(workspace, tmp_path)
    monkeypatch.setattr(
        fix_runtime,
        "_run_config",
        lambda env: RunConfig(
            model=model, sandbox=SandboxRunConfig(session=env.session), tracing_disabled=True
        ),
    )
    request = _request(commit)
    request.max_agent_turns = turns
    request.max_repair_turns = repair_turns
    request.max_review_turns = review_turns
    result = await fix_runtime.run_fix_preparation(
        request,
        workspace,
        sandbox_session=env.session,
        runtime_environment=env,
        artifact_path=tmp_path / "prepared.zip",
    )
    return result, env


@pytest.mark.asyncio
async def test_agent_implements_runs_both_test_suites_and_exports_after_review(
    tmp_path, monkeypatch
):
    model = ScriptedModel([*patch(), *suite_commands(), finish("done", "Both suites passed")])
    result, _env = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.READY, result.model_dump_json()
    assert result.validation_mode == "agent_review"
    assert model.inputs["review"]
    assert result.verifier.summary == "Independently approved."
    assert result.completion.turns_used == 5
    assert all("Ran 1 test" in c.output for c in result.checks[-2:])
    assert {"exec_command", "apply_patch", "agent_finish"} <= model.tools
    assert not {"create_agent", "finish_scan", "record_coverage"} & model.tools
    with zipfile.ZipFile(tmp_path / "prepared.zip") as artifact:
        assert "files/tests/test_security.py" in artifact.namelist()
    assert "Both suites passed" in _summary(result)


@pytest.mark.asyncio
async def test_agent_corrects_failed_test_in_same_conversation(tmp_path, monkeypatch):
    model = ScriptedModel(
        [*patch("still unsafe"), *suite_commands(), *patch(), *suite_commands(), finish("done")]
    )
    result, _ = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.READY
    assert any(c.exit_code != 0 for c in result.checks)
    assert all(c.exit_code == 0 for c in result.checks[-2:])
    assert model.inputs["review"]


@pytest.mark.asyncio
@pytest.mark.parametrize("end", ["blocked", "limit"])
async def test_blocked_or_capped_agent_discards_patch(tmp_path, monkeypatch, end):
    model = ScriptedModel([*patch(), finish("blocked", "Database unavailable")])
    result, _ = await scenario(tmp_path, monkeypatch, model, turns=2 if end == "limit" else 10)
    assert result.state is PreparationState.BLOCKED
    assert not result.final_file_manifest
    assert not (tmp_path / "prepared.zip").exists()
    assert len(model.inputs["repair"]) <= (2 if end == "limit" else 3)


@pytest.mark.asyncio
async def test_native_lifecycle_ignores_legacy_quoted_outcome(tmp_path, monkeypatch):
    model = ScriptedModel(
        [
            *patch(),
            *suite_commands(),
            call("agent_finish", outcome='"done"', success=True, result_summary="Complete"),
        ]
    )
    result, _ = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.READY
    assert result.completion.turns_used == 5


@pytest.mark.asyncio
async def test_resume_consumes_remaining_turn_allowance(tmp_path):

    env = environment(tmp_path / "source", tmp_path)
    env.turns_used = 299
    env.max_repair_turns = 500
    saved = []
    env.turn_sink = saved.append
    hooks = _FixHooks(env)

    context = RunContextWrapper(context={})
    await hooks.on_llm_start(context, Agent(name="fix"), "", [])
    with pytest.raises(MaxTurnsExceeded):
        await hooks.on_llm_start(context, Agent(name="fix"), "", [])
    assert saved == [300]


@pytest.mark.asyncio
async def test_completion_recommendations_are_in_summary(tmp_path, monkeypatch):
    model = ScriptedModel(
        [
            *patch(),
            *suite_commands(),
            call(
                "agent_finish",
                outcome="done",
                result_summary="Fixed and tested",
                final_recommendations=["Run the nightly suite"],
            ),
        ]
    )
    result, _ = await scenario(tmp_path, monkeypatch, model)
    assert "Run the nightly suite" in _summary(result)


@pytest.mark.asyncio
async def test_fix_respects_live_scan_budget_without_double_counting(tmp_path, monkeypatch):

    recorded = []
    state = SimpleNamespace(
        get_total_llm_cost=lambda: 2.0, record_sdk_usage=lambda **kwargs: recorded.append(kwargs)
    )
    monkeypatch.setattr(hooks_module, "get_global_report_state", lambda: state)
    env = environment(tmp_path / "source", tmp_path)
    shared = ReportUsageHooks(model="test", max_budget_usd=10)
    env.scan_hooks = shared
    hooks = _FixHooks(env)
    context = RunContextWrapper(context={"agent_id": "fix", "parent_id": "root"})
    shared.set_max_budget_usd(1)
    with pytest.raises(BudgetExceededError):
        await hooks.on_llm_end(
            context,
            Agent(name="fix"),
            ModelResponse(output=[], usage=Usage(requests=1), response_id=None),
        )
    assert len(recorded) == 1


@pytest.mark.asyncio
async def test_dependency_symlink_does_not_hide_new_source_or_regression(tmp_path, monkeypatch):
    model = ScriptedModel(
        [
            *patch(),
            shell("ln -s /tmp node_modules"),
            shell("printf 'VALUE = 1\\n' > helper.py"),
            *suite_commands(),
            finish("done"),
        ]
    )
    result, _ = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.READY, result.stop_reason
    with zipfile.ZipFile(tmp_path / "prepared.zip") as artifact:
        names = artifact.namelist()
        assert "files/helper.py" in names and "files/tests/test_security.py" in names
        assert not any("node_modules" in name for name in names)


@pytest.mark.asyncio
async def test_checkpoint_failure_is_correctable_before_completion(tmp_path, monkeypatch):
    model = ScriptedModel(
        [
            *patch(),
            shell("ln -s app.py helper.py"),
            finish("done"),
            shell("rm helper.py"),
            *suite_commands(),
            finish("done"),
        ]
    )
    result, _ = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.READY, result.stop_reason
    assert any("Could not package this fix" in str(items) for items in model.inputs["repair"])


@pytest.mark.asyncio
async def test_three_identical_completion_errors_stop_with_real_reason(tmp_path, monkeypatch):
    model = ScriptedModel(
        [
            *patch(),
            shell("ln -s app.py helper.py"),
            finish("done"),
            finish("done"),
            finish("done"),
        ]
    )
    result, _ = await scenario(tmp_path, monkeypatch, model, turns=300)
    assert result.state is PreparationState.BLOCKED
    assert result.completion.turns_used == 6
    assert "Completion failed three times" in result.completion.summary
    assert not (tmp_path / "prepared.zip").exists()
