import asyncio
import logging
import os
from collections.abc import AsyncIterator
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
from litellm import completion_cost, stream_chunk_builder, supports_reasoning
from litellm.utils import supports_prompt_caching, supports_vision

from strix.llm.config import LLMConfig
from strix.llm.memory_compressor import MemoryCompressor
from strix.llm.request_queue import get_global_queue
from strix.llm.utils import _truncate_to_first_function, parse_tool_invocations
from strix.prompts import load_prompt_modules
from strix.tools import get_tools_prompt


MAX_RETRIES = 5
RETRY_MULTIPLIER = 8
RETRY_MIN = 8
RETRY_MAX = 64


def _should_retry(exception: Exception) -> bool:
    status_code = None
    if hasattr(exception, "status_code"):
        status_code = exception.status_code
    elif hasattr(exception, "response") and hasattr(exception.response, "status_code"):
        status_code = exception.response.status_code
    if status_code is not None:
        return bool(litellm._should_retry(status_code))
    return True


logger = logging.getLogger(__name__)

litellm.drop_params = True
litellm.modify_params = True

_LLM_API_KEY = os.getenv("LLM_API_KEY")
_LLM_API_BASE = (
    os.getenv("LLM_API_BASE")
    or os.getenv("OPENAI_API_BASE")
    or os.getenv("LITELLM_BASE_URL")
    or os.getenv("OLLAMA_API_BASE")
)


class LLMRequestFailedError(Exception):
    def __init__(self, message: str, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details


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
    def __init__(
        self, config: LLMConfig, agent_name: str | None = None, agent_id: str | None = None
    ):
        self.config = config
        self.agent_name = agent_name
        self.agent_id = agent_id
        self._total_stats = RequestStats()
        self._last_request_stats = RequestStats()

        self.memory_compressor = MemoryCompressor(
            model_name=self.config.model_name,
            timeout=self.config.timeout,
        )

        if agent_name:
            prompt_dir = Path(__file__).parent.parent / "agents" / agent_name
            prompts_dir = Path(__file__).parent.parent / "prompts"

            loader = FileSystemLoader([prompt_dir, prompts_dir])
            self.jinja_env = Environment(
                loader=loader,
                autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
            )

            try:
                modules_to_load = list(self.config.prompt_modules or [])
                modules_to_load.append(f"scan_modes/{self.config.scan_mode}")

                prompt_module_content = load_prompt_modules(modules_to_load, self.jinja_env)

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

    def set_agent_identity(self, agent_name: str | None, agent_id: str | None) -> None:
        if agent_name:
            self.agent_name = agent_name
        if agent_id:
            self.agent_id = agent_id

    def _build_identity_message(self) -> dict[str, Any] | None:
        if not (self.agent_name and str(self.agent_name).strip()):
            return None
        identity_name = self.agent_name
        identity_id = self.agent_id
        content = (
            "\n\n"
            "<agent_identity>\n"
            "<meta>Internal metadata: do not echo or reference; "
            "not part of history or tool calls.</meta>\n"
            "<note>You are now assuming the role of this agent. "
            "Act strictly as this agent and maintain self-identity for this step. "
            "Now go answer the next needed step!</note>\n"
            f"<agent_name>{identity_name}</agent_name>\n"
            f"<agent_id>{identity_id}</agent_id>\n"
            "</agent_identity>\n\n"
        )
        return {"role": "user", "content": content}

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

    def _prepare_messages(self, conversation_history: list[dict[str, Any]]) -> list[dict[str, Any]]:
        messages = [{"role": "system", "content": self.system_prompt}]

        identity_message = self._build_identity_message()
        if identity_message:
            messages.append(identity_message)

        compressed_history = list(self.memory_compressor.compress_history(conversation_history))

        conversation_history.clear()
        conversation_history.extend(compressed_history)
        messages.extend(compressed_history)

        return self._prepare_cached_messages(messages)

    async def _stream_and_accumulate(
        self,
        messages: list[dict[str, Any]],
        scan_id: str | None,
        step_number: int,
    ) -> AsyncIterator[LLMResponse]:
        accumulated_content = ""
        chunks: list[Any] = []

        async for chunk in self._stream_request(messages):
            chunks.append(chunk)
            delta = self._extract_chunk_delta(chunk)
            if delta:
                accumulated_content += delta

                if "</function>" in accumulated_content:
                    function_end = accumulated_content.find("</function>") + len("</function>")
                    accumulated_content = accumulated_content[:function_end]

                yield LLMResponse(
                    scan_id=scan_id,
                    step_number=step_number,
                    role=StepRole.AGENT,
                    content=accumulated_content,
                    tool_invocations=None,
                )

        if chunks:
            complete_response = stream_chunk_builder(chunks)
            self._update_usage_stats(complete_response)

        accumulated_content = _truncate_to_first_function(accumulated_content)
        if "</function>" in accumulated_content:
            function_end = accumulated_content.find("</function>") + len("</function>")
            accumulated_content = accumulated_content[:function_end]

        tool_invocations = parse_tool_invocations(accumulated_content)

        yield LLMResponse(
            scan_id=scan_id,
            step_number=step_number,
            role=StepRole.AGENT,
            content=accumulated_content,
            tool_invocations=tool_invocations if tool_invocations else None,
        )

    def _raise_llm_error(self, e: Exception) -> None:
        error_map: list[tuple[type, str]] = [
            (litellm.RateLimitError, "Rate limit exceeded"),
            (litellm.AuthenticationError, "Invalid API key"),
            (litellm.NotFoundError, "Model not found"),
            (litellm.ContextWindowExceededError, "Context too long"),
            (litellm.ContentPolicyViolationError, "Content policy violation"),
            (litellm.ServiceUnavailableError, "Service unavailable"),
            (litellm.Timeout, "Request timed out"),
            (litellm.UnprocessableEntityError, "Unprocessable entity"),
            (litellm.InternalServerError, "Internal server error"),
            (litellm.APIConnectionError, "Connection error"),
            (litellm.UnsupportedParamsError, "Unsupported parameters"),
            (litellm.BudgetExceededError, "Budget exceeded"),
            (litellm.APIResponseValidationError, "Response validation error"),
            (litellm.JSONSchemaValidationError, "JSON schema validation error"),
            (litellm.InvalidRequestError, "Invalid request"),
            (litellm.BadRequestError, "Bad request"),
            (litellm.APIError, "API error"),
            (litellm.OpenAIError, "OpenAI error"),
        ]
        for error_type, message in error_map:
            if isinstance(e, error_type):
                raise LLMRequestFailedError(f"LLM request failed: {message}", str(e)) from e
        raise LLMRequestFailedError(f"LLM request failed: {type(e).__name__}", str(e)) from e

    async def generate(
        self,
        conversation_history: list[dict[str, Any]],
        scan_id: str | None = None,
        step_number: int = 1,
    ) -> AsyncIterator[LLMResponse]:
        messages = self._prepare_messages(conversation_history)

        last_error: Exception | None = None
        for attempt in range(MAX_RETRIES):
            try:
                async for response in self._stream_and_accumulate(messages, scan_id, step_number):
                    yield response
                return  # noqa: TRY300
            except Exception as e:  # noqa: BLE001
                last_error = e
                if not _should_retry(e) or attempt == MAX_RETRIES - 1:
                    break
                wait_time = min(RETRY_MAX, RETRY_MULTIPLIER * (2**attempt))
                wait_time = max(RETRY_MIN, wait_time)
                await asyncio.sleep(wait_time)

        if last_error:
            self._raise_llm_error(last_error)

    def _extract_chunk_delta(self, chunk: Any) -> str:
        if chunk.choices and hasattr(chunk.choices[0], "delta"):
            delta = chunk.choices[0].delta
            return getattr(delta, "content", "") or ""
        return ""

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

    def _should_include_reasoning_effort(self) -> bool:
        if not self.config.model_name:
            return False
        try:
            return bool(supports_reasoning(model=self.config.model_name))
        except Exception:  # noqa: BLE001
            return False

    def _model_supports_vision(self) -> bool:
        if not self.config.model_name:
            return False
        try:
            return bool(supports_vision(model=self.config.model_name))
        except Exception:  # noqa: BLE001
            return False

    def _filter_images_from_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        filtered_messages = []
        for msg in messages:
            content = msg.get("content")
            updated_msg = msg
            if isinstance(content, list):
                filtered_content = []
                for item in content:
                    if isinstance(item, dict):
                        if item.get("type") == "image_url":
                            filtered_content.append(
                                {
                                    "type": "text",
                                    "text": "[Screenshot removed - model does not support "
                                    "vision. Use view_source or execute_js instead.]",
                                }
                            )
                        else:
                            filtered_content.append(item)
                    else:
                        filtered_content.append(item)
                if filtered_content:
                    text_parts = [
                        item.get("text", "") if isinstance(item, dict) else str(item)
                        for item in filtered_content
                    ]
                    all_text = all(
                        isinstance(item, dict) and item.get("type") == "text"
                        for item in filtered_content
                    )
                    if all_text:
                        updated_msg = {**msg, "content": "\n".join(text_parts)}
                    else:
                        updated_msg = {**msg, "content": filtered_content}
                else:
                    updated_msg = {**msg, "content": ""}
            filtered_messages.append(updated_msg)
        return filtered_messages

    async def _stream_request(
        self,
        messages: list[dict[str, Any]],
    ) -> AsyncIterator[Any]:
        if not self._model_supports_vision():
            messages = self._filter_images_from_messages(messages)

        completion_args: dict[str, Any] = {
            "model": self.config.model_name,
            "messages": messages,
            "timeout": self.config.timeout,
            "stream_options": {"include_usage": True},
        }

        if _LLM_API_KEY:
            completion_args["api_key"] = _LLM_API_KEY
        if _LLM_API_BASE:
            completion_args["api_base"] = _LLM_API_BASE

        completion_args["stop"] = ["</function>"]

        if self._should_include_reasoning_effort():
            completion_args["reasoning_effort"] = "high"

        queue = get_global_queue()
        self._total_stats.requests += 1
        self._last_request_stats = RequestStats(requests=1)

        async for chunk in queue.stream_request(completion_args):
            yield chunk

    def _update_usage_stats(self, response: Any) -> None:
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
