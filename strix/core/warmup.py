"""Preflight probe: verify the configured LLM endpoint returns structured tool calls.

Strix is entirely tool-driven: every working turn must be a native ``tool_call``.
Some self-hosted / OpenAI-compatible endpoints (llama.cpp without ``--jinja``, an
Ollama model whose template lacks tool wiring, a misconfigured vLLM tool parser)
never emit structured tool calls — they return the call as plain assistant text.
The SDK then treats that as a normal final message and the agent silently parks
on "Send message to resume" (issue #520).

This module fires one cheap request with a throwaway tool before the scan starts.
If the endpoint cannot produce a structured tool call, it aborts immediately with
actionable guidance instead of letting the scan stall mid-run.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from agents import FunctionTool
from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from openai.types.responses import ResponseFunctionToolCall

from strix.config.models import StrixProvider


if TYPE_CHECKING:
    from strix.config.settings import Settings


logger = logging.getLogger(__name__)

_PROBE_TOOL_NAME = "strix_preflight_check"
_PROBE_MAX_TOKENS = 2048
_PROBE_ATTEMPTS = 2

# Substrings in a provider error that indicate a tool-calling *capability* problem
# (as opposed to auth/connectivity), so we can attach the config guidance.
_TOOL_CONFIG_ERROR_MARKERS = (
    "jinja",
    "tool use",
    "tool_use",
    "tool calling",
    "tool_choice",
    "does not support tools",
    "support tool",
    "tool call parser",
    "tool-call-parser",
)

_GUIDANCE = (
    "The configured LLM endpoint did not return a structured tool call.\n"
    "Strix requires native tool calling; when the endpoint returns the call as "
    "plain text the scan cannot execute any action and would stall.\n\n"
    "Fix it on the inference server:\n"
    "  - llama.cpp (llama-server): run with --jinja and a correct tool-use chat "
    "template (matching --chat-template / --chat-template-file); upgrade to a "
    "recent build. Disable/align reasoning for thinking models.\n"
    "  - Ollama: use a recent Ollama and a model whose template wires tools; for "
    "reasoning models (e.g. qwen3) disable thinking (STRIX_REASONING_EFFORT=none, "
    "which sends think=false).\n"
    "  - vLLM: start with --enable-auto-tool-choice, a matching --tool-call-parser "
    "(hermes / qwen3_xml / llama3_json), and a matching --reasoning-parser.\n\n"
    "See the Strix docs (Local & self-hosted models) for the full matrix. "
    "Set STRIX_SKIP_TOOL_CALL_PROBE=1 to bypass this check."
)


class ToolCallingUnsupportedError(RuntimeError):
    """Raised when the configured endpoint cannot return structured tool calls."""


def requires_tool_call_probe(model_name: str, settings: Settings) -> bool:
    """Probe only self-hosted / OpenAI-compatible routes, where #520 occurs.

    Hosted providers (OpenAI/Anthropic/Gemini/... with no custom ``api_base``)
    reliably return structured tool calls, so we skip the extra request there.
    """
    name = (model_name or "").strip().lower()
    if name.startswith("ollama/"):
        return True
    return bool(settings.llm.api_base)


def _build_probe_tool() -> FunctionTool:
    async def _noop(_ctx: Any, _args: str) -> str:
        return ""

    return FunctionTool(
        name=_PROBE_TOOL_NAME,
        description=(
            "Connectivity self-check. Call this tool with ok=true to confirm "
            "tool calling is available."
        ),
        params_json_schema={
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
            "additionalProperties": False,
        },
        on_invoke_tool=_noop,
        strict_json_schema=True,
    )


def _response_has_tool_call(output: list[Any]) -> bool:
    return any(isinstance(item, ResponseFunctionToolCall) for item in output)


def _looks_like_tool_config_error(exc: BaseException) -> bool:
    text = str(exc).lower()
    return any(marker in text for marker in _TOOL_CONFIG_ERROR_MARKERS)


async def probe_tool_calling(
    model_name: str,
    settings: Settings,
    *,
    request_timeout: float | None = None,
) -> None:
    """Verify the endpoint emits a structured tool call; raise if it cannot.

    No-op for hosted providers and when ``STRIX_SKIP_TOOL_CALL_PROBE`` is set.
    """
    if settings.llm.skip_tool_call_probe:
        return
    if not requires_tool_call_probe(model_name, settings):
        return

    logger.info("Preflight: probing tool-calling capability for %s", model_name)
    model = StrixProvider().get_model(model_name)
    tool = _build_probe_tool()
    extra_args: dict[str, Any] = {}
    if request_timeout and request_timeout > 0:
        extra_args["timeout"] = request_timeout
    headers = settings.llm.extra_headers
    model_settings = ModelSettings(
        max_tokens=_PROBE_MAX_TOKENS,
        parallel_tool_calls=False,
        extra_headers=dict(headers) if headers else None,
        extra_args=extra_args or None,
    )
    instructions = (
        "You are performing a one-time connectivity self-check. Respond by "
        f"calling the {_PROBE_TOOL_NAME} tool with ok=true. Do not answer in text."
    )

    last_error: BaseException | None = None
    reached_model = False
    for attempt in range(1, _PROBE_ATTEMPTS + 1):
        try:
            response = await model.get_response(
                system_instructions=instructions,
                input=f"Call the {_PROBE_TOOL_NAME} tool now.",
                model_settings=model_settings,
                tools=[tool],
                output_schema=None,
                handoffs=[],
                tracing=ModelTracing.DISABLED,
                previous_response_id=None,
                conversation_id=None,
                prompt=None,
            )
        except ToolCallingUnsupportedError:
            raise
        except Exception as exc:
            last_error = exc
            if _looks_like_tool_config_error(exc):
                raise ToolCallingUnsupportedError(f"{_GUIDANCE}\n\nProvider error: {exc}") from exc
            logger.warning(
                "Preflight tool-call probe attempt %d/%d errored: %s",
                attempt,
                _PROBE_ATTEMPTS,
                exc,
            )
            continue

        reached_model = True
        if _response_has_tool_call(response.output):
            logger.info("Preflight: endpoint returned a structured tool call (ok).")
            return
        logger.warning(
            "Preflight tool-call probe attempt %d/%d returned no structured tool call.",
            attempt,
            _PROBE_ATTEMPTS,
        )

    if not reached_model and last_error is not None:
        # Every attempt failed before we saw a response, and none of the errors
        # pointed at tool configuration. This is a connectivity/auth/provider
        # problem, not a missing capability — surface it as-is rather than
        # sending the user off to change chat templates.
        raise last_error
    raise ToolCallingUnsupportedError(_GUIDANCE)
