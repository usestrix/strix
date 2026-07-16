"""Strix application settings — pydantic-settings powered."""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, BaseModel, Field, model_validator
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
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
