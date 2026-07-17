"""Strix application settings — pydantic-settings powered."""

from __future__ import annotations

import math
from typing import Literal

from pydantic import AliasChoices, BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh"]
SkillRouteOperator = Literal["AND", "OR", "ANY"]

_BASE_CONFIG = SettingsConfigDict(
    case_sensitive=False,
    populate_by_name=True,
    extra="ignore",
)


class SkillModelRoute(BaseModel):
    """Select a child model from its injected skills.

    Rules are evaluated in config order. ``skill`` is the concise form for a
    single-skill rule. ``ANY`` matches every child that has at least one skill.
    """

    model_config = {"populate_by_name": True, "extra": "forbid"}

    model: str
    operator: SkillRouteOperator | None = Field(default=None, pattern="^(AND|OR|ANY)$")
    skills: list[str] = Field(default_factory=list)
    skill: str | None = None
    reasoning_effort: ReasoningEffort | None = None

    @model_validator(mode="after")
    def validate_rule(self) -> SkillModelRoute:
        self.model = self.model.strip()
        self.skills = [skill.strip() for skill in self.skills if skill.strip()]
        if self.skill:
            self.skill = self.skill.strip() or None
        if not self.model:
            raise ValueError("skill model route requires a non-empty model")
        if self.skill and (self.operator is not None or self.skills):
            raise ValueError("use either 'skill' or 'operator'/'skills', not both")
        if self.skill:
            return self
        if self.operator is None:
            raise ValueError("skill model route requires 'skill' or 'operator'")
        if self.operator != "ANY" and not self.skills:
            raise ValueError(f"{self.operator} skill model route requires skills")
        return self

    def matches(self, injected_skills: list[str]) -> bool:
        assigned = {skill.strip().lower() for skill in injected_skills if skill.strip()}
        if self.skill:
            return self.skill.lower() in assigned
        configured = {skill.lower() for skill in self.skills}
        if self.operator == "ANY":
            return bool(assigned)
        if self.operator == "AND":
            return bool(configured) and configured <= assigned
        return bool(configured & assigned)


class LlmSettings(BaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(
        default=None,
        alias="STRIX_ORCHESTRATOR_MODEL",
        validation_alias=AliasChoices("STRIX_ORCHESTRATOR_MODEL", "STRIX_LLM"),
    )
    subagent_model: str | None = Field(default=None, alias="STRIX_SUBAGENT_MODEL")
    skill_model_routes: list[SkillModelRoute] = Field(default_factory=list)
    model_budgets_usd: dict[str, float] = Field(
        default_factory=dict,
        alias="STRIX_MODEL_BUDGETS_USD",
    )
    model_fallbacks: dict[str, str] = Field(
        default_factory=dict,
        alias="STRIX_MODEL_FALLBACKS",
    )
    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("LLM_API_KEY", "OPENAI_API_KEY"),
    )
    api_base: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "LLM_API_BASE",
            "OPENAI_API_BASE",
            "OPENAI_BASE_URL",
            "LITELLM_BASE_URL",
            "OLLAMA_API_BASE",
        ),
    )
    reasoning_effort: ReasoningEffort = Field(default="high", alias="STRIX_REASONING_EFFORT")
    subagent_reasoning_effort: ReasoningEffort | None = Field(
        default=None,
        alias="STRIX_SUBAGENT_REASONING_EFFORT",
    )
    subagent_api_key: str | None = Field(default=None, alias="SUBAGENT_LLM_API_KEY")
    force_required_tool_choice: bool = Field(
        default=False,
        alias="STRIX_FORCE_REQUIRED_TOOL_CHOICE",
    )
    timeout: int = Field(default=300, alias="LLM_TIMEOUT")

    @field_validator("model_budgets_usd", mode="before")
    @classmethod
    def validate_model_budgets(cls, value: object) -> object:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise TypeError("model_budgets_usd must be a model-to-USD mapping")
        normalized: dict[str, float] = {}
        for raw_model, raw_budget in value.items():
            model = str(raw_model).strip()
            if not model:
                raise ValueError("model_budgets_usd contains an empty model name")
            try:
                budget = float(raw_budget)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"budget for {model!r} must be a number") from exc
            if not math.isfinite(budget) or budget <= 0:
                raise ValueError(f"budget for {model!r} must be finite and greater than 0")
            normalized[model] = budget
        return normalized

    @field_validator("model_fallbacks", mode="before")
    @classmethod
    def validate_model_fallbacks(cls, value: object) -> object:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise TypeError("model_fallbacks must be a model-to-model mapping")
        normalized: dict[str, str] = {}
        for raw_model, raw_fallback in value.items():
            model = str(raw_model).strip()
            fallback = str(raw_fallback).strip()
            if not model or not fallback:
                raise ValueError("model_fallbacks cannot contain empty model names")
            if model.lower() == fallback.lower():
                raise ValueError(f"model {model!r} cannot fall back to itself")
            normalized[model] = fallback
        return normalized

    @model_validator(mode="after")
    def validate_fallback_graph(self) -> LlmSettings:
        budget_keys = {name.lower() for name in self.model_budgets_usd}
        fallbacks = {name.lower(): target.lower() for name, target in self.model_fallbacks.items()}
        display_names = {name.lower(): name for name in self.model_fallbacks}
        for source in fallbacks:
            if source not in budget_keys:
                raise ValueError(
                    f"model_fallbacks source {display_names[source]!r} requires a "
                    "model_budgets_usd entry"
                )
            seen: set[str] = set()
            current = source
            while current in fallbacks:
                if current in seen:
                    raise ValueError("model_fallbacks contains a cycle")
                seen.add(current)
                current = fallbacks[current]
        return self

    def budget_for(self, model: str) -> float | None:
        normalized = model.strip().lower()
        return next(
            (
                budget
                for name, budget in self.model_budgets_usd.items()
                if name.lower() == normalized
            ),
            None,
        )

    def fallback_for(self, model: str) -> str | None:
        normalized = model.strip().lower()
        return next(
            (
                fallback
                for name, fallback in self.model_fallbacks.items()
                if name.lower() == normalized
            ),
            None,
        )

    def model_chain(self, model: str) -> list[str]:
        chain: list[str] = []
        current: str | None = model.strip()
        while current:
            chain.append(current)
            current = self.fallback_for(current)
        return chain


class FindingVerificationSettings(BaseSettings):
    model_config = _BASE_CONFIG

    enabled: bool = Field(default=False, alias="STRIX_VERIFY_FINDINGS")
    model: str | None = Field(default=None, alias="STRIX_VERIFICATION_MODEL")
    reasoning_effort: ReasoningEffort | None = Field(
        default="high",
        alias="STRIX_VERIFICATION_REASONING_EFFORT",
    )
    api_key: str | None = Field(default=None, alias="VERIFICATION_LLM_API_KEY")

    @model_validator(mode="after")
    def require_model_when_enabled(self) -> FindingVerificationSettings:
        if self.enabled and not (self.model or "").strip():
            raise ValueError(
                "STRIX_VERIFICATION_MODEL must be set when STRIX_VERIFY_FINDINGS is enabled"
            )
        return self


class DedupeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, alias="STRIX_DEDUPE_MODEL")
    reasoning_effort: ReasoningEffort | None = Field(
        default=None,
        alias="STRIX_DEDUPE_REASONING_EFFORT",
    )
    api_key: str | None = Field(default=None, alias="DEDUPE_LLM_API_KEY")


class RuntimeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    image: str = Field(
        default="ghcr.io/usestrix/strix-sandbox:1.0.0",
        alias="STRIX_IMAGE",
    )
    backend: str = Field(default="docker", alias="STRIX_RUNTIME_BACKEND")
    # Hard cap on a local target's size before we refuse to stream it into the
    # sandbox file-by-file (the SDK copies every file individually, which stalls
    # on large repos). Above this, the user must bind-mount via ``--mount``.
    # Set to 0 (or less) to disable the pre-flight check entirely.
    max_local_copy_mb: int = Field(default=1024, alias="STRIX_MAX_LOCAL_COPY_MB")
    # Max screenshot/image tool outputs kept live per agent context (0 = none).
    max_context_images: int = Field(default=3, ge=0, alias="STRIX_MAX_CONTEXT_IMAGES")


class TelemetrySettings(BaseSettings):
    model_config = _BASE_CONFIG

    enabled: bool = Field(default=True, alias="STRIX_TELEMETRY")


class IntegrationSettings(BaseSettings):
    model_config = _BASE_CONFIG

    perplexity_api_key: str | None = Field(default=None, alias="PERPLEXITY_API_KEY")


class Settings(BaseSettings):
    model_config = _BASE_CONFIG

    llm: LlmSettings = Field(default_factory=LlmSettings)
    verification: FindingVerificationSettings = Field(default_factory=FindingVerificationSettings)
    dedupe: DedupeSettings = Field(default_factory=DedupeSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
