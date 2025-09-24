import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import litellm
from jinja2 import (
    Environment,
    FileSystemLoader,
    select_autoescape,
)
from litellm import ModelResponse, completion_cost
from litellm.utils import supports_prompt_caching

from strix.llm.config import LLMConfig
from strix.llm.memory_compressor import MemoryCompressor
from strix.llm.request_queue import get_global_queue
from strix.llm.utils import _truncate_to_first_function, parse_tool_invocations
from strix.prompts import load_prompt_modules
from strix.tools import get_tools_prompt


logger = logging.getLogger(__name__)

api_key = os.getenv("LLM_API_KEY")
if api_key:
    litellm.api_key = api_key

api_base = (
    os.getenv("LLM_API_BASE")
    or os.getenv("OPENAI_API_BASE")
    or os.getenv("LITELLM_BASE_URL")
    or os.getenv("OLLAMA_API_BASE")
)
if api_base:
    litellm.api_base = api_base


class LLMRequestFailedError(Exception):
    def __init__(self, message: str, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details


MODELS_WITHOUT_STOP_WORDS = [
    "gpt-5",
    "gpt-5-mini",
    "gpt-5-nano",
    "o1-mini",
    "o1-preview",
    "o1",
    "o1-2024-12-17",
    "o3",
    "o3-2025-04-16",
    "o3-mini-2025-01-31",
    "o3-mini",
    "o4-mini",
    "o4-mini-2025-04-16",
    "grok-4-0709",
]

REASONING_EFFORT_SUPPORTED_MODELS = [
    "gpt-5",
    "gpt-5-mini",
    "gpt-5-nano",
    "o1-2024-12-17",
    "o1",
    "o3",
    "o3-2025-04-16",
    "o3-mini-2025-01-31",
    "o3-mini",
    "o4-mini",
    "o4-mini-2025-04-16",
    "gemini-2.5-flash",
    "gemini-2.5-pro",
]


class StepRole(str, Enum):
    AGENT = "agent"
    USER = "user"
    SYSTEM = "system"


@dataclass
class LLMResponse:
    content: str
    tool_invocations: list[dict[str, Any]] | None = None
    scan_id: str | None = None
    step_number: int = 1
    role: StepRole = StepRole.AGENT


@dataclass
class RequestStats:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    cache_creation_tokens: int = 0
    cost: float = 0.0
    requests: int = 0
    failed_requests: int = 0

    def to_dict(self) -> dict[str, int | float]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_tokens": self.cached_tokens,
            "cache_creation_tokens": self.cache_creation_tokens,
            "cost": round(self.cost, 4),
            "requests": self.requests,
            "failed_requests": self.failed_requests,
        }


class LLM:
    def __init__(self, config: LLMConfig, agent_name: str | None = None):
        self.config = config
        self.agent_name = agent_name
        self._total_stats = RequestStats()
        self._last_request_stats = RequestStats()

        self.memory_compressor = MemoryCompressor()

        if agent_name:
            prompt_dir = Path(__file__).parent.parent / "agents" / agent_name
            prompts_dir = Path(__file__).parent.parent / "prompts"

            loader = FileSystemLoader([prompt_dir, prompts_dir])
            self.jinja_env = Environment(
                loader=loader,
                autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
            )

            try:
                prompt_module_content = load_prompt_modules(
                    self.config.prompt_modules or [], self.jinja_env
                )

                def get_module(name: str) -> str:
                    return prompt_module_content.get(name, "")

                self.jinja_env.globals["get_module"] = get_module

                self.system_prompt = self.jinja_env.get_template("system_prompt.jinja").render(
                    get_tools_prompt=get_tools_prompt,
                    loaded_module_names=list(prompt_module_content.keys()),
                    **prompt_module_content,
                )
            except (FileNotFoundError, OSError, ValueError) as e:
                logger.warning(f"Failed to load system prompt for {agent_name}: {e}")
                self.system_prompt = "You are a helpful AI assistant."
        else:
            self.system_prompt = "You are a helpful AI assistant."

    def _add_cache_control_to_content(
        self, content: str | list[dict[str, Any]]
    ) -> str | list[dict[str, Any]]:
        if isinstance(content, str):
            return [{"type": "text", "text": content, "cache_control": {"type": "ephemeral"}}]
        if isinstance(content, list) and content:
            last_item = content[-1]
            if isinstance(last_item, dict) and last_item.get("type") == "text":
                return content[:-1] + [{**last_item, "cache_control": {"type": "ephemeral"}}]
        return content

    def _is_anthropic_model(self) -> bool:
        if not self.config.model_name:
            return False
        model_lower = self.config.model_name.lower()
        return any(provider in model_lower for provider in ["anthropic/", "claude"])

    def _calculate_cache_interval(self, total_messages: int) -> int:
        if total_messages <= 1:
            return 10

        max_cached_messages = 3
        non_system_messages = total_messages - 1

        interval = 10
        while non_system_messages // interval > max_cached_messages:
            interval += 10

        return interval

    def _prepare_cached_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if (
            not self.config.enable_prompt_caching
            or not supports_prompt_caching(self.config.model_name)
            or not messages
        ):
            return messages

        if not self._is_anthropic_model():
            return messages

        cached_messages = list(messages)

        if cached_messages and cached_messages[0].get("role") == "system":
            system_message = cached_messages[0].copy()
            system_message["content"] = self._add_cache_control_to_content(
                system_message["content"]
            )
            cached_messages[0] = system_message

        total_messages = len(cached_messages)
        if total_messages > 1:
            interval = self._calculate_cache_interval(total_messages)

            cached_count = 0
            for i in range(interval, total_messages, interval):
                if cached_count >= 3:
                    break

                if i < len(cached_messages):
                    message = cached_messages[i].copy()
                    message["content"] = self._add_cache_control_to_content(message["content"])
                    cached_messages[i] = message
                    cached_count += 1

        return cached_messages

    async def generate(  # noqa: PLR0912, PLR0915
        self,
        conversation_history: list[dict[str, Any]],
        scan_id: str | None = None,
        step_number: int = 1,
    ) -> LLMResponse:
        messages = [{"role": "system", "content": self.system_prompt}]

        compressed_history = list(self.memory_compressor.compress_history(conversation_history))

        conversation_history.clear()
        conversation_history.extend(compressed_history)
        messages.extend(compressed_history)

        cached_messages = self._prepare_cached_messages(messages)

        try:
            response = await self._make_request(cached_messages)
            self._update_usage_stats(response)

            content = ""
            if (
                response.choices
                and hasattr(response.choices[0], "message")
                and response.choices[0].message
            ):
                content = getattr(response.choices[0].message, "content", "") or ""

            content = _truncate_to_first_function(content)

            if "</function>" in content:
                function_end_index = content.find("</function>") + len("</function>")
                content = content[:function_end_index]

            tool_invocations = parse_tool_invocations(content)

            return LLMResponse(
                scan_id=scan_id,
                step_number=step_number,
                role=StepRole.AGENT,
                content=content,
                tool_invocations=tool_invocations if tool_invocations else None,
            )

        except litellm.RateLimitError as e:
            raise LLMRequestFailedError("LLM request failed: Rate limit exceeded", str(e)) from e
        except litellm.AuthenticationError as e:
            raise LLMRequestFailedError("LLM request failed: Invalid API key", str(e)) from e
        except litellm.NotFoundError as e:
            raise LLMRequestFailedError("LLM request failed: Model not found", str(e)) from e
        except litellm.ContextWindowExceededError as e:
            raise LLMRequestFailedError("LLM request failed: Context too long", str(e)) from e
        except litellm.ContentPolicyViolationError as e:
            raise LLMRequestFailedError(
                "LLM request failed: Content policy violation", str(e)
            ) from e
        except litellm.ServiceUnavailableError as e:
            raise LLMRequestFailedError("LLM request failed: Service unavailable", str(e)) from e
        except litellm.Timeout as e:
            raise LLMRequestFailedError("LLM request failed: Request timed out", str(e)) from e
        except litellm.UnprocessableEntityError as e:
            raise LLMRequestFailedError("LLM request failed: Unprocessable entity", str(e)) from e
        except litellm.InternalServerError as e:
            raise LLMRequestFailedError("LLM request failed: Internal server error", str(e)) from e
        except litellm.APIConnectionError as e:
            raise LLMRequestFailedError("LLM request failed: Connection error", str(e)) from e
        except litellm.UnsupportedParamsError as e:
            raise LLMRequestFailedError("LLM request failed: Unsupported parameters", str(e)) from e
        except litellm.BudgetExceededError as e:
            raise LLMRequestFailedError("LLM request failed: Budget exceeded", str(e)) from e
        except litellm.APIResponseValidationError as e:
            raise LLMRequestFailedError(
                "LLM request failed: Response validation error", str(e)
            ) from e
        except litellm.JSONSchemaValidationError as e:
            raise LLMRequestFailedError(
                "LLM request failed: JSON schema validation error", str(e)
            ) from e
        except litellm.InvalidRequestError as e:
            raise LLMRequestFailedError("LLM request failed: Invalid request", str(e)) from e
        except litellm.BadRequestError as e:
            raise LLMRequestFailedError("LLM request failed: Bad request", str(e)) from e
        except litellm.APIError as e:
            raise LLMRequestFailedError("LLM request failed: API error", str(e)) from e
        except litellm.OpenAIError as e:
            raise LLMRequestFailedError("LLM request failed: OpenAI error", str(e)) from e
        except Exception as e:
            raise LLMRequestFailedError(f"LLM request failed: {type(e).__name__}", str(e)) from e

    @property
    def usage_stats(self) -> dict[str, dict[str, int | float]]:
        return {
            "total": self._total_stats.to_dict(),
            "last_request": self._last_request_stats.to_dict(),
        }

    def get_cache_config(self) -> dict[str, bool]:
        return {
            "enabled": self.config.enable_prompt_caching,
            "supported": supports_prompt_caching(self.config.model_name),
        }

    def _should_include_stop_param(self) -> bool:
        if not self.config.model_name:
            return True

        actual_model_name = self.config.model_name.split("/")[-1].lower()
        model_name_lower = self.config.model_name.lower()

        return not any(
            actual_model_name == unsupported_model.lower()
            or model_name_lower == unsupported_model.lower()
            for unsupported_model in MODELS_WITHOUT_STOP_WORDS
        )

    def _should_include_reasoning_effort(self) -> bool:
        if not self.config.model_name:
            return False

        actual_model_name = self.config.model_name.split("/")[-1].lower()
        model_name_lower = self.config.model_name.lower()

        return any(
            actual_model_name == supported_model.lower()
            or model_name_lower == supported_model.lower()
            for supported_model in REASONING_EFFORT_SUPPORTED_MODELS
        )

    async def _make_request(
        self,
        messages: list[dict[str, Any]],
    ) -> ModelResponse:
        completion_args: dict[str, Any] = {
            "model": self.config.model_name,
            "messages": messages,
            "temperature": self.config.temperature,
            "timeout": 180,
        }

        if self._should_include_stop_param():
            completion_args["stop"] = ["</function>"]

        if self._should_include_reasoning_effort():
            completion_args["reasoning_effort"] = "high"

        queue = get_global_queue()
        response = await queue.make_request(completion_args)

        self._total_stats.requests += 1
        self._last_request_stats = RequestStats(requests=1)

        return response

    def _update_usage_stats(self, response: ModelResponse) -> None:
        try:
            if hasattr(response, "usage") and response.usage:
                input_tokens = getattr(response.usage, "prompt_tokens", 0)
                output_tokens = getattr(response.usage, "completion_tokens", 0)

                cached_tokens = 0
                cache_creation_tokens = 0

                if hasattr(response.usage, "prompt_tokens_details"):
                    prompt_details = response.usage.prompt_tokens_details
                    if hasattr(prompt_details, "cached_tokens"):
                        cached_tokens = prompt_details.cached_tokens or 0

                if hasattr(response.usage, "cache_creation_input_tokens"):
                    cache_creation_tokens = response.usage.cache_creation_input_tokens or 0

            else:
                input_tokens = 0
                output_tokens = 0
                cached_tokens = 0
                cache_creation_tokens = 0

            try:
                cost = completion_cost(response) or 0.0
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Failed to calculate cost: {e}")
                cost = 0.0

            self._total_stats.input_tokens += input_tokens
            self._total_stats.output_tokens += output_tokens
            self._total_stats.cached_tokens += cached_tokens
            self._total_stats.cache_creation_tokens += cache_creation_tokens
            self._total_stats.cost += cost

            self._last_request_stats.input_tokens = input_tokens
            self._last_request_stats.output_tokens = output_tokens
            self._last_request_stats.cached_tokens = cached_tokens
            self._last_request_stats.cache_creation_tokens = cache_creation_tokens
            self._last_request_stats.cost = cost

            if cached_tokens > 0:
                logger.info(f"Cache hit: {cached_tokens} cached tokens, {input_tokens} new tokens")
            if cache_creation_tokens > 0:
                logger.info(f"Cache creation: {cache_creation_tokens} tokens written to cache")

            logger.info(f"Usage stats: {self.usage_stats}")
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Failed to update usage stats: {e}")
