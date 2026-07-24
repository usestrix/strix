"""Per-model root, child, skill, and usage routing tests."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from agents.model_settings import ModelSettings
from agents.usage import Usage

from strix.agents.factory import _resolve_child_api_key, build_strix_agent, make_child_factory
from strix.config.settings import LlmSettings, Settings, SkillModelRoute
from strix.core.hooks import ReportUsageHooks


def test_child_api_key_prefers_explicit_subagent_key() -> None:
    llm = LlmSettings(
        model="openai/root",
        api_key="root-key",
        subagent_api_key="child-key",
    )
    # Explicit subagent key wins even when the child shares the root provider.
    assert _resolve_child_api_key(llm, "openai/child", "openai/root") == "child-key"


def test_child_api_key_reuses_root_key_only_for_same_provider() -> None:
    llm = LlmSettings(model="openai/root", api_key="root-key")
    assert _resolve_child_api_key(llm, "openai/mini", "openai/root") == "root-key"
    # A cross-provider child must not receive the root provider's credential.
    assert _resolve_child_api_key(llm, "anthropic/opus", "openai/root") is None


def test_child_api_key_flows_into_model_settings_extra_args() -> None:
    settings = Settings(
        llm=LlmSettings(
            model="openai/root",
            api_key="root-key",
            subagent_api_key="child-key",
        )
    )
    child = make_child_factory(settings=settings, default_model="openai/root")(
        name="worker",
        skills=[],
        model="anthropic/opus",
    )
    assert child.model_settings.extra_args["api_key"] == "child-key"


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
        "strix.agents.factory.uses_chat_completions_tool_schema",
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
