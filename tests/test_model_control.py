"""Fine-grained per-task model control.

Covers skill-based routing, per-model budget fallback chains, independent
finding verification, and the dedicated deduplication model — all of which
select which model runs a given piece of work.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
from agents.model_settings import ModelSettings
from agents.usage import Usage
from pydantic import ValidationError

from strix.agents.factory import build_strix_agent, make_child_factory
from strix.config import loader
from strix.config.settings import (
    DedupeSettings,
    FindingVerificationSettings,
    LlmSettings,
    Settings,
    SkillModelRoute,
)
from strix.core.agents import AgentCoordinator
from strix.core.hooks import ModelFallbackError, ReportUsageHooks
from strix.core.model_routing import chain_uses_chat_completions_tools, resolve_budget_model
from strix.interface.utils import build_tui_stats_text
from strix.report.state import ReportState, set_global_report_state
from strix.report.usage import LLMUsageLedger
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


# --------------------------------------------------------------------------- #
# Skill-based routing
# --------------------------------------------------------------------------- #
def test_build_agent_accepts_model_and_settings() -> None:
    model_settings = ModelSettings(parallel_tool_calls=False)
    agent = build_strix_agent(
        is_root=True,
        model="openai/frontier",
        model_settings=model_settings,
    )
    assert agent.model == "openai/frontier"
    assert agent.model_settings is model_settings


def test_skill_route_matching_operators() -> None:
    assert SkillModelRoute(skill="xss", model="one").matches(["xss"])
    assert SkillModelRoute(operator="AND", skills=["oauth", "xss"], model="two").matches(
        ["xss", "oauth", "nmap"]
    )
    assert SkillModelRoute(operator="OR", skills=["xss", "sqli"], model="three").matches(
        ["sqli"]
    )
    assert SkillModelRoute(operator="ANY", model="four").matches(["nmap"])
    assert not SkillModelRoute(operator="ANY", model="four").matches([])


def test_child_factory_precedence_and_per_model_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(
        llm=LlmSettings(
            model="openai/root",
            subagent_model="deepseek/cheap",
            skill_model_routes=[
                {"skill": "xss", "model": "anthropic/specialist"},
                {"operator": "ANY", "model": "qwen/fallback"},
            ],
        )
    )
    seen_schema_models: list[str] = []
    monkeypatch.setattr(
        "strix.core.model_routing.uses_chat_completions_tool_schema",
        lambda model, _settings: seen_schema_models.append(model) or model != "openai/escalated",
    )
    monkeypatch.setattr(
        "strix.agents.factory.make_model_settings",
        lambda *_args, **_kwargs: ModelSettings(),
    )
    factory = make_child_factory(settings=settings, default_model="openai/root")

    routed = factory(name="specialist", skills=["xss"])
    explicit = factory(name="escalated", skills=["xss"], model="openai/escalated")

    assert routed.model == "anthropic/specialist"
    assert explicit.model == "openai/escalated"
    assert seen_schema_models == ["anthropic/specialist", "openai/escalated"]


def test_child_factory_falls_back_to_orchestrator() -> None:
    settings = Settings(llm=LlmSettings(model="openai/root"))
    child = make_child_factory(settings=settings, default_model="openai/root")(
        name="child",
        skills=[],
    )
    assert child.model == "openai/root"


@pytest.mark.asyncio
async def test_usage_hook_records_each_agents_actual_model() -> None:
    hooks = ReportUsageHooks(model="openai/root")
    state = MagicMock()
    state.get_total_llm_cost.return_value = 0.0
    context = SimpleNamespace(context={"agent_id": "child-1"})
    agent = SimpleNamespace(name="child", model="deepseek/cheap")
    response = SimpleNamespace(usage=Usage(input_tokens=10, output_tokens=5, total_tokens=15))

    with patch("strix.core.hooks.get_global_report_state", return_value=state):
        await hooks.on_llm_end(context, agent, response)

    assert state.record_sdk_usage.call_args.kwargs["model"] == "deepseek/cheap"


# --------------------------------------------------------------------------- #
# Per-model budget fallback chains
# --------------------------------------------------------------------------- #
def test_fallback_chain_and_case_insensitive_lookup() -> None:
    llm = LlmSettings(
        model_budgets_usd={"openai/GPT": 5, "z-ai/GLM": 3},
        model_fallbacks={
            "openai/GPT": "z-ai/GLM",
            "z-ai/GLM": "deepseek/final",
        },
    )

    assert llm.budget_for("OPENAI/gpt") == 5
    assert llm.fallback_for("Z-AI/glm") == "deepseek/final"
    assert llm.model_chain("openai/GPT") == [
        "openai/GPT",
        "z-ai/GLM",
        "deepseek/final",
    ]


def test_fallback_source_requires_budget_and_cycles_are_rejected() -> None:
    with pytest.raises(ValidationError, match="requires a model_budgets_usd entry"):
        LlmSettings(model_fallbacks={"a": "b"})
    with pytest.raises(ValidationError, match="cycle"):
        LlmSettings(
            model_budgets_usd={"a": 1, "b": 1},
            model_fallbacks={"a": "b", "b": "a"},
        )


def test_new_agent_skips_an_already_exhausted_model() -> None:
    llm = LlmSettings(
        model_budgets_usd={"gpt": 1, "glm": 2},
        model_fallbacks={"gpt": "glm", "glm": "final"},
    )
    state = MagicMock()
    state.get_model_llm_cost.side_effect = lambda model: {"gpt": 1.5, "glm": 1.0}[model]

    with patch("strix.core.model_routing.get_global_report_state", return_value=state):
        assert resolve_budget_model("gpt", llm) == "glm"


def test_tool_schema_is_compatible_with_entire_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = SimpleNamespace(
        llm=LlmSettings(
            model_budgets_usd={"openai/gpt": 1},
            model_fallbacks={"openai/gpt": "z-ai/glm"},
        )
    )
    monkeypatch.setattr(
        "strix.core.model_routing.uses_chat_completions_tool_schema",
        lambda model, _settings: model == "z-ai/glm",
    )

    assert chain_uses_chat_completions_tools("openai/gpt", settings)


def test_usage_ledger_groups_tokens_by_actual_model() -> None:
    ledger = LLMUsageLedger()
    ledger.record(
        agent_id="root",
        model="openai/gpt",
        usage=Usage(input_tokens=100, output_tokens=20, total_tokens=120),
    )
    ledger.record(
        agent_id="child",
        model="z-ai/glm",
        usage=Usage(input_tokens=50, output_tokens=10, total_tokens=60),
    )

    models = {item["model"]: item for item in ledger.to_record()["models"]}
    assert models["openai/gpt"]["total_tokens"] == 120
    assert models["z-ai/glm"]["total_tokens"] == 60


def test_usage_hydration_preserves_model_cost_without_double_counting() -> None:
    ledger = LLMUsageLedger()
    ledger.hydrate(
        {
            "total_tokens": 10,
            "cost": 1.5,
            "models": [{"model": "gpt", "total_tokens": 10, "cost": 1.5}],
            "agents": [],
        }
    )

    assert ledger.model_cost("gpt") == 1.5
    assert ledger.to_record()["models"][0]["cost"] == 1.5


def test_tui_stats_lists_tokens_for_every_model() -> None:
    state = MagicMock()
    state.caido_url = None
    state.get_total_llm_usage.return_value = {
        "models": [
            {"model": "openai/gpt", "total_tokens": 1500, "cost": 1.25},
            {"model": "z-ai/glm", "total_tokens": 700, "cost": 0.2},
        ]
    }

    rendered = build_tui_stats_text(state).plain
    assert "openai/gpt  1.5K tokens · $1.25" in rendered
    assert "z-ai/glm  700 tokens · $0.20" in rendered


@pytest.mark.asyncio
async def test_hook_switches_all_matching_agents_at_response_boundary() -> None:
    llm = LlmSettings(
        reasoning_effort="none",
        model_budgets_usd={"openai/gpt": 1},
        model_fallbacks={"openai/gpt": "z-ai/glm"},
    )
    hooks = ReportUsageHooks(model="openai/gpt", llm_settings=llm)
    coordinator = AgentCoordinator()
    root = SimpleNamespace(name="strix", model="openai/gpt", model_settings=ModelSettings())
    child = SimpleNamespace(name="xss", model="openai/gpt", model_settings=ModelSettings())
    await coordinator.register("root", "strix", None, model="openai/gpt")
    await coordinator.register("child", "xss", "root", model="openai/gpt")
    await coordinator.attach_runtime("root", agent=root)
    await coordinator.attach_runtime("child", agent=child)

    state = MagicMock()
    state.get_total_llm_cost.return_value = 1.1
    state.get_model_llm_cost.return_value = 1.1
    context = SimpleNamespace(
        context={"agent_id": "root", "parent_id": None, "coordinator": coordinator}
    )
    response = SimpleNamespace(usage=Usage(input_tokens=10, output_tokens=5, total_tokens=15))

    with (
        patch("strix.core.hooks.get_global_report_state", return_value=state),
        patch("strix.core.hooks.make_model_settings", return_value=ModelSettings()),
        pytest.raises(ModelFallbackError) as exc_info,
    ):
        await hooks.on_llm_end(context, root, response)

    assert exc_info.value.next_model == "z-ai/glm"
    assert root.model == "z-ai/glm"
    assert child.model == "z-ai/glm"
    assert coordinator.metadata["root"]["model"] == "z-ai/glm"
    assert coordinator.metadata["child"]["model"] == "z-ai/glm"


@pytest.mark.asyncio
async def test_stale_inflight_response_retries_existing_fallback_without_advancing() -> None:
    llm = LlmSettings(
        reasoning_effort="none",
        model_budgets_usd={"gpt": 1, "glm": 2},
        model_fallbacks={"gpt": "glm", "glm": "final"},
    )
    hooks = ReportUsageHooks(model="gpt", llm_settings=llm)
    coordinator = AgentCoordinator()
    agent = SimpleNamespace(name="child", model="gpt", model_settings=ModelSettings())
    await coordinator.register("child", "child", "root", model="gpt")
    await coordinator.attach_runtime("child", agent=agent)
    context = SimpleNamespace(
        context={"agent_id": "child", "parent_id": "root", "coordinator": coordinator}
    )
    await hooks.on_llm_start(context, agent, None, [])
    agent.model = "glm"  # A concurrent gpt response already switched the shared route.
    state = MagicMock()
    state.get_model_llm_cost.return_value = 1.2

    with (
        patch("strix.core.hooks.get_global_report_state", return_value=state),
        pytest.raises(ModelFallbackError) as exc_info,
    ):
        await hooks.on_llm_end(context, agent, SimpleNamespace(usage=Usage(total_tokens=1)))

    assert exc_info.value.next_model == "glm"
    assert agent.model == "glm"


@pytest.mark.asyncio
async def test_hook_can_continue_to_second_fallback_layer() -> None:
    llm = LlmSettings(
        reasoning_effort="none",
        model_budgets_usd={"gpt": 1, "glm": 2},
        model_fallbacks={"gpt": "glm", "glm": "final"},
    )
    hooks = ReportUsageHooks(model="gpt", llm_settings=llm)
    coordinator = AgentCoordinator()
    agent = SimpleNamespace(name="strix", model="glm", model_settings=ModelSettings())
    await coordinator.register("root", "strix", None, model="glm")
    await coordinator.attach_runtime("root", agent=agent)
    state = MagicMock()
    state.get_total_llm_cost.return_value = 3.0
    state.get_model_llm_cost.return_value = 2.1
    context = SimpleNamespace(
        context={"agent_id": "root", "parent_id": None, "coordinator": coordinator}
    )

    with (
        patch("strix.core.hooks.get_global_report_state", return_value=state),
        patch("strix.core.hooks.make_model_settings", return_value=ModelSettings()),
        pytest.raises(ModelFallbackError) as exc_info,
    ):
        await hooks.on_llm_end(context, agent, SimpleNamespace(usage=Usage(total_tokens=1)))

    assert exc_info.value.next_model == "final"
    assert agent.model == "final"


# --------------------------------------------------------------------------- #
# Independent finding verification
# --------------------------------------------------------------------------- #
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


# --------------------------------------------------------------------------- #
# Structured config: skill routes, verification, and dedupe together
# --------------------------------------------------------------------------- #
def test_dedupe_defaults_are_empty() -> None:
    settings = DedupeSettings()
    assert settings.model is None
    assert settings.reasoning_effort is None
    assert settings.api_key is None


def test_dedupe_model_read_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_DEDUPE_MODEL", "deepseek/deepseek-v4-flash")
    monkeypatch.setenv("STRIX_DEDUPE_REASONING_EFFORT", "low")

    settings = DedupeSettings()

    assert settings.model == "deepseek/deepseek-v4-flash"
    assert settings.reasoning_effort == "low"


def test_structured_config_loads_all_model_routes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in (
        "STRIX_LLM",
        "STRIX_ORCHESTRATOR_MODEL",
        "STRIX_SUBAGENT_MODEL",
        "STRIX_VERIFY_FINDINGS",
        "STRIX_VERIFICATION_MODEL",
        "STRIX_DEDUPE_MODEL",
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
                "dedupe": {"model": "deepseek/cheap", "reasoning_effort": "minimal"},
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
    assert settings.dedupe.model == "deepseek/cheap"
    assert settings.dedupe.reasoning_effort == "minimal"
