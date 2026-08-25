"""Strix application settings — pydantic-settings powered."""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh", "max"]
SafetyMode = Literal["off", "guarded"]
SAFETY_MODES: tuple[SafetyMode, ...] = ("off", "guarded")
# The mode a scan runs in unless the operator opts out with
# --dangerously-disable-safety. Reads of a missing safety_mode key default here.
DEFAULT_SAFETY_MODE: SafetyMode = "guarded"

ResumeSafetyModeError = Literal["observe_removed", "invalid", "changed"]


def resume_safety_mode_error(persisted: str, requested: SafetyMode) -> ResumeSafetyModeError | None:
    """Why a persisted run's safety mode blocks resuming as ``requested``, or None.

    One source of truth for the resume policy, shared by the CLI pre-check and the
    runner's defense-in-depth check so the two cannot drift. Each caller formats its
    own message (the CLI further splits "changed" by direction).
    """
    if persisted == "observe":
        return "observe_removed"
    if persisted not in SAFETY_MODES:
        return "invalid"
    if persisted != requested:
        return "changed"
    return None


DEFAULT_MAX_TURNS = 500

_BASE_CONFIG = SettingsConfigDict(
    case_sensitive=False,
    populate_by_name=True,
    extra="ignore",
)


class LlmSettings(BaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, alias="STRIX_LLM")
    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("LLM_API_KEY", "OPENAI_API_KEY"),
        repr=False,
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
    extra_headers: dict[str, str] | None = Field(
        default=None,
        alias="LLM_EXTRA_HEADERS",
        repr=False,
    )
    reasoning_effort: ReasoningEffort = Field(default="high", alias="STRIX_REASONING_EFFORT")
    force_required_tool_choice: bool = Field(
        default=False,
        alias="STRIX_FORCE_REQUIRED_TOOL_CHOICE",
    )
    prompt_cache: bool = Field(
        default=True,
        alias="STRIX_PROMPT_CACHE",
    )
    disable_streaming: bool = Field(
        default=False,
        alias="LLM_DISABLE_STREAMING",
    )
    timeout: int = Field(default=300, alias="LLM_TIMEOUT")
    stream_idle_timeout: int = Field(default=300, ge=0, alias="LLM_STREAM_IDLE_TIMEOUT")
    max_tool_calls_per_turn: int = Field(
        default=32,
        ge=0,
        alias="LLM_MAX_TOOL_CALLS_PER_TURN",
    )


class DedupeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, alias="STRIX_DEDUPE_MODEL")
    reasoning_effort: ReasoningEffort | None = Field(
        default=None,
        alias="STRIX_DEDUPE_REASONING_EFFORT",
    )
    api_key: str | None = Field(default=None, alias="DEDUPE_LLM_API_KEY", repr=False)
    api_base: str | None = Field(default=None, alias="DEDUPE_LLM_API_BASE")
    extra_headers: dict[str, str] | None = Field(
        default=None,
        alias="DEDUPE_LLM_EXTRA_HEADERS",
        repr=False,
    )


class ContextSettings(BaseSettings):
    """Context-window management: per-tool-output caps and history compaction."""

    model_config = _BASE_CONFIG

    auto_compact: bool = Field(default=True, alias="STRIX_CONTEXT_AUTO_COMPACT")
    compact_buffer_tokens: int = Field(default=20_000, gt=0, alias="STRIX_CONTEXT_BUFFER_TOKENS")
    keep_tokens: int = Field(default=8_000, gt=0, alias="STRIX_CONTEXT_KEEP_TOKENS")
    fallback_context_tokens: int = Field(
        default=200_000, gt=0, alias="STRIX_CONTEXT_FALLBACK_TOKENS"
    )
    summary_max_tokens: int = Field(default=4_096, gt=0, alias="STRIX_CONTEXT_SUMMARY_TOKENS")
    tool_output_max_tokens: int = Field(default=8_000, gt=0, alias="STRIX_TOOL_OUTPUT_MAX_TOKENS")
    tool_output_max_lines: int = Field(default=2_000, gt=0, alias="STRIX_TOOL_OUTPUT_MAX_LINES")
    # Floor above the truncation-notice size so a preview always fits.
    tool_output_max_bytes: int = Field(
        default=50 * 1024, ge=1024, alias="STRIX_TOOL_OUTPUT_MAX_BYTES"
    )


class RuntimeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    image: str = Field(
        default="ghcr.io/usestrix/strix-sandbox:1.3.0",
        alias="STRIX_IMAGE",
    )
    backend: str = Field(default="docker", alias="STRIX_RUNTIME_BACKEND")
    # Max screenshot/image tool outputs kept live per agent context (0 = none).
    max_context_images: int = Field(default=3, ge=0, alias="STRIX_MAX_CONTEXT_IMAGES")


class SafetySettings(BaseSettings):
    """Pre-execution action review and isolated inspection settings."""

    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, alias="STRIX_SAFETY_MODEL")
    reasoning_effort: ReasoningEffort | None = Field(
        default="low",
        alias="STRIX_SAFETY_REASONING_EFFORT",
    )
    timeout: int = Field(default=60, gt=0, alias="STRIX_SAFETY_TIMEOUT")
    max_output_tokens: int = Field(
        default=8192,
        ge=1024,
        alias="STRIX_SAFETY_MAX_OUTPUT_TOKENS",
    )
    max_input_chars: int = Field(
        default=240_000,
        ge=16_384,
        alias="STRIX_SAFETY_MAX_INPUT_CHARS",
    )
    max_artifact_bytes: int = Field(
        default=256 * 1024,
        ge=4096,
        alias="STRIX_SAFETY_MAX_ARTIFACT_BYTES",
    )
    max_total_artifact_bytes: int = Field(
        default=4 * 1024 * 1024,
        ge=4096,
        alias="STRIX_SAFETY_MAX_TOTAL_ARTIFACT_BYTES",
    )
    max_dependencies: int = Field(
        default=32,
        ge=1,
        alias="STRIX_SAFETY_MAX_DEPENDENCIES",
    )
    inspection_timeout: int = Field(
        default=5,
        gt=0,
        alias="STRIX_SAFETY_INSPECTION_TIMEOUT",
    )
    inspection_output_bytes: int = Field(
        default=16 * 1024,
        ge=1024,
        alias="STRIX_SAFETY_INSPECTION_OUTPUT_BYTES",
    )
    inspection_image: str | None = Field(
        default=None,
        alias="STRIX_SAFETY_INSPECTION_IMAGE",
    )


class TelemetrySettings(BaseSettings):
    model_config = _BASE_CONFIG

    enabled: bool = Field(default=True, alias="STRIX_TELEMETRY")


class IntegrationSettings(BaseSettings):
    model_config = _BASE_CONFIG

    perplexity_api_key: str | None = Field(
        default=None,
        alias="PERPLEXITY_API_KEY",
        repr=False,
    )
    postman_api_key: str | None = Field(
        default=None,
        alias="POSTMAN_API_KEY",
        repr=False,
    )


class ViewerSettings(BaseSettings):
    model_config = _BASE_CONFIG

    # Base URL of the Strix relay the local viewer proxies to for email
    # verification and encrypted report delivery. The browser never talks to
    # the relay directly; the local server is the only caller.
    app_url: str = Field(default="https://app.strix.ai", alias="STRIX_APP_URL")


class Settings(BaseSettings):
    model_config = _BASE_CONFIG

    llm: LlmSettings = Field(default_factory=LlmSettings)
    dedupe: DedupeSettings = Field(default_factory=DedupeSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    safety: SafetySettings = Field(default_factory=SafetySettings)
    context: ContextSettings = Field(default_factory=ContextSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
    viewer: ViewerSettings = Field(default_factory=ViewerSettings)
