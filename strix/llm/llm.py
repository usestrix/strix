import asyncio
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import litellm
from jinja2 import Environment, FileSystemLoader, select_autoescape
from litellm import (
    acompletion,
    aresponses,
    completion_cost,
    stream_chunk_builder,
    supports_reasoning,
)
from litellm.utils import supports_prompt_caching, supports_vision

from strix.config import Config
from strix.llm.config import LLMConfig
from strix.llm.memory_compressor import MemoryCompressor
from strix.llm.utils import (
    _truncate_to_first_function,
    fix_incomplete_tool_call,
    normalize_tool_format,
    parse_tool_invocations,
)
from strix.skills import load_skills
from strix.tools import get_tools_prompt
from strix.utils.resource_paths import get_strix_resource_path


litellm.drop_params = True
litellm.modify_params = True


class LLMRequestFailedError(Exception):
    def __init__(self, message: str, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details


@dataclass
class LLMResponse:
    content: str
    tool_invocations: list[dict[str, Any]] | None = None
    thinking_blocks: list[dict[str, Any]] | None = None


@dataclass
class RequestStats:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    cost: float = 0.0
    requests: int = 0

    def to_dict(self) -> dict[str, int | float]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_tokens": self.cached_tokens,
            "cost": round(self.cost, 4),
            "requests": self.requests,
        }


class ModelHandler(ABC):
    @abstractmethod
    async def call(self, config: LLMConfig, messages: list[dict[str, Any]]) -> Any:
        pass

    @abstractmethod
    def get_chunk_content(self, chunk: Any) -> str:
        pass

    @abstractmethod
    def extract_usage(self, chunks: list[Any], config: LLMConfig) -> tuple[int, int, int, float]:
        pass

    @abstractmethod
    def extract_thinking(self, chunks: list[Any], config: LLMConfig) -> list[dict[str, Any]] | None:
        pass


class CompletionHandler(ModelHandler):
    async def call(self, config: LLMConfig, messages: list[dict[str, Any]]) -> Any:
        args = self._build_args(config, messages)
        return await acompletion(**args, stream=True)

    def _build_args(self, config: LLMConfig, messages: list[dict[str, Any]]) -> dict[str, Any]:
        args: dict[str, Any] = {
            "model": config.litellm_model,
            "messages": messages,
            "timeout": config.timeout,
            "stream_options": {"include_usage": True},
        }
        if config.api_key:
            args["api_key"] = config.api_key
        if config.api_base:
            args["api_base"] = config.api_base
        return args

    def get_chunk_content(self, chunk: Any) -> str:
        if hasattr(chunk, "choices") and chunk.choices and hasattr(chunk.choices[0], "delta"):
            return getattr(chunk.choices[0].delta, "content", "") or ""
        return ""

    def extract_usage(self, chunks: list[Any], config: LLMConfig) -> tuple[int, int, int, float]:
        try:
            response = stream_chunk_builder(chunks)
            if not hasattr(response, "usage") or not response.usage:
                return 0, 0, 0, 0.0

            input_tokens = (
                getattr(response.usage, "prompt_tokens", 0)
                or getattr(response.usage, "input_tokens", 0)
                or 0
            )
            output_tokens = (
                getattr(response.usage, "completion_tokens", 0)
                or getattr(response.usage, "output_tokens", 0)
                or 0
            )

            cached_tokens = 0
            if hasattr(response.usage, "prompt_tokens_details"):
                details = response.usage.prompt_tokens_details
                if hasattr(details, "cached_tokens"):
                    cached_tokens = details.cached_tokens or 0

            cost = self._extract_cost(response, chunks, config)
        except Exception:  # noqa: BLE001
            return 0, 0, 0, 0.0
        else:
            return input_tokens, output_tokens, cached_tokens, cost

    def _extract_cost(self, response: Any, chunks: list[Any], config: LLMConfig) -> float:
        if hasattr(response, "usage") and response.usage:
            direct_cost = getattr(response.usage, "cost", None)
            if direct_cost is not None:
                return float(direct_cost)
        if chunks:
            last_chunk = chunks[-1]
            if hasattr(last_chunk, "usage") and last_chunk.usage:
                cost = getattr(last_chunk.usage, "cost", None)
                if cost is not None:
                    return float(cost)
        try:
            if hasattr(response, "_hidden_params"):
                response._hidden_params.pop("custom_llm_provider", None)
            return completion_cost(response, model=config.canonical_model) or 0.0
        except Exception:  # noqa: BLE001
            return 0.0

    def extract_thinking(self, chunks: list[Any], config: LLMConfig) -> list[dict[str, Any]] | None:
        if not chunks:
            return None
        try:
            if not supports_reasoning(model=config.canonical_model):
                return None
            resp = stream_chunk_builder(chunks)
            if resp.choices and hasattr(resp.choices[0].message, "thinking_blocks"):
                blocks: list[dict[str, Any]] = resp.choices[0].message.thinking_blocks
                return blocks
        except Exception:  # noqa: BLE001, S110  # nosec B110
            pass
        return None


class ResponsesHandler(ModelHandler):
    async def call(self, config: LLMConfig, messages: list[dict[str, Any]]) -> Any:
        args = self._build_args(config, messages)
        return await aresponses(**args, stream=True)

    def _build_args(self, config: LLMConfig, messages: list[dict[str, Any]]) -> dict[str, Any]:
        args: dict[str, Any] = {
            "model": config.litellm_model,
            "input": self._messages_to_input(messages),
        }
        if config.api_key:
            args["api_key"] = config.api_key
        if config.api_base:
            args["api_base"] = config.api_base
        return args

    def _messages_to_input(self, messages: list[dict[str, Any]]) -> str:
        parts = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if isinstance(content, list):
                content = " ".join(
                    item.get("text", "") for item in content if item.get("type") == "text"
                )
            if role == "system":
                parts.append(f"[System]\n{content}")
            elif role == "assistant":
                parts.append(f"[Assistant]\n{content}")
            else:
                parts.append(content)
        return "\n\n".join(parts)

    def get_chunk_content(self, chunk: Any) -> str:
        chunk_type = getattr(chunk, "type", "")
        if chunk_type == "response.output_text.delta":
            return getattr(chunk, "delta", "") or ""
        if hasattr(chunk, "delta") and isinstance(chunk.delta, str):
            return chunk.delta
        return ""

    def extract_usage(
        self,
        chunks: list[Any],
        config: LLMConfig,  # noqa: ARG002
    ) -> tuple[int, int, int, float]:
        try:
            for chunk in reversed(chunks):
                usage = None
                if hasattr(chunk, "response") and chunk.response:
                    usage = getattr(chunk.response, "usage", None)
                elif hasattr(chunk, "usage"):
                    usage = chunk.usage

                if usage:
                    input_tokens = getattr(usage, "input_tokens", 0) or 0
                    output_tokens = getattr(usage, "output_tokens", 0) or 0
                    cost = getattr(usage, "cost", 0.0) or 0.0
                    return input_tokens, output_tokens, 0, cost
        except Exception:  # noqa: BLE001, S110  # nosec B110
            pass
        return 0, 0, 0, 0.0

    def extract_thinking(
        self,
        chunks: list[Any],  # noqa: ARG002
        config: LLMConfig,  # noqa: ARG002
    ) -> list[dict[str, Any]] | None:
        return None


def get_handler(model_name: str | None) -> ModelHandler:
    if model_name and "-codex" in model_name.lower():
        return ResponsesHandler()
    return CompletionHandler()


class LLM:
    def __init__(self, config: LLMConfig, agent_name: str | None = None):
        self.config = config
        self.agent_name = agent_name
        self.agent_id: str | None = None
        self._total_stats = RequestStats()
        self.memory_compressor = MemoryCompressor(model_name=config.litellm_model)
        self.system_prompt = self._load_system_prompt(agent_name)
        self._handler = get_handler(config.model_name)

        reasoning = Config.get("strix_reasoning_effort")
        if reasoning:
            self._reasoning_effort = reasoning
        elif config.scan_mode == "quick":
            self._reasoning_effort = "medium"
        else:
            self._reasoning_effort = "high"

    def _load_system_prompt(self, agent_name: str | None) -> str:
        if not agent_name:
            return ""

        try:
            prompt_dir = get_strix_resource_path("agents", agent_name)
            skills_dir = get_strix_resource_path("skills")
            env = Environment(
                loader=FileSystemLoader([prompt_dir, skills_dir]),
                autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
            )

            skills_to_load = [
                *list(self.config.skills or []),
                f"scan_modes/{self.config.scan_mode}",
            ]
            skill_content = load_skills(skills_to_load)
            env.globals["get_skill"] = lambda name: skill_content.get(name, "")

            result = env.get_template("system_prompt.jinja").render(
                get_tools_prompt=get_tools_prompt,
                loaded_skill_names=list(skill_content.keys()),
                **skill_content,
            )
            return str(result)
        except Exception:  # noqa: BLE001
            return ""

    def set_agent_identity(self, agent_name: str | None, agent_id: str | None) -> None:
        if agent_name:
            self.agent_name = agent_name
        if agent_id:
            self.agent_id = agent_id

    async def generate(
        self, conversation_history: list[dict[str, Any]]
    ) -> AsyncIterator[LLMResponse]:
        messages = self._prepare_messages(conversation_history)
        max_retries = int(Config.get("strix_llm_max_retries") or "5")

        for attempt in range(max_retries + 1):
            try:
                async for response in self._stream(messages):
                    yield response
                return  # noqa: TRY300
            except Exception as e:  # noqa: BLE001
                if attempt >= max_retries or not self._should_retry(e):
                    self._raise_error(e)
                wait = min(10, 2 * (2**attempt))
                await asyncio.sleep(wait)

    async def _stream(self, messages: list[dict[str, Any]]) -> AsyncIterator[LLMResponse]:
        accumulated = ""
        chunks: list[Any] = []
        done_streaming = 0

        self._total_stats.requests += 1

        if not self._supports_vision():
            messages = self._strip_images(messages)

        if isinstance(self._handler, CompletionHandler) and self._supports_reasoning():
            args = self._handler._build_args(self.config, messages)
            args["reasoning_effort"] = self._reasoning_effort
            response = await acompletion(**args, stream=True)
        else:
            response = await self._handler.call(self.config, messages)

        async for chunk in response:
            chunks.append(chunk)
            if done_streaming:
                done_streaming += 1
                if getattr(chunk, "usage", None) or done_streaming > 5:
                    break
                continue
            delta = self._handler.get_chunk_content(chunk)
            if delta:
                accumulated += delta
                if "</function>" in accumulated or "</invoke>" in accumulated:
                    end_tag = "</function>" if "</function>" in accumulated else "</invoke>"
                    pos = accumulated.find(end_tag)
                    accumulated = accumulated[: pos + len(end_tag)]
                    yield LLMResponse(content=accumulated)
                    done_streaming = 1
                    continue
                yield LLMResponse(content=accumulated)

        if chunks:
            inp, out, cached, cost = self._handler.extract_usage(chunks, self.config)
            self._total_stats.input_tokens += inp
            self._total_stats.output_tokens += out
            self._total_stats.cached_tokens += cached
            self._total_stats.cost += cost

        accumulated = normalize_tool_format(accumulated)
        accumulated = fix_incomplete_tool_call(_truncate_to_first_function(accumulated))
        yield LLMResponse(
            content=accumulated,
            tool_invocations=parse_tool_invocations(accumulated),
            thinking_blocks=self._handler.extract_thinking(chunks, self.config),
        )

    def _prepare_messages(self, conversation_history: list[dict[str, Any]]) -> list[dict[str, Any]]:
        messages = [{"role": "system", "content": self.system_prompt}]

        if self.agent_name:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"\n\n<agent_identity>\n"
                        f"<meta>Internal metadata: do not echo or reference.</meta>\n"
                        f"<agent_name>{self.agent_name}</agent_name>\n"
                        f"<agent_id>{self.agent_id}</agent_id>\n"
                        f"</agent_identity>\n\n"
                    ),
                }
            )

        compressed = list(self.memory_compressor.compress_history(conversation_history))
        conversation_history.clear()
        conversation_history.extend(compressed)
        messages.extend(compressed)

        if messages[-1].get("role") == "assistant":
            messages.append({"role": "user", "content": "<meta>Continue the task.</meta>"})

        if self._is_anthropic() and self.config.enable_prompt_caching:
            messages = self._add_cache_control(messages)

        return messages

    def _should_retry(self, e: Exception) -> bool:
        code = getattr(e, "status_code", None) or getattr(
            getattr(e, "response", None), "status_code", None
        )
        return code is None or litellm._should_retry(code)

    def _raise_error(self, e: Exception) -> None:
        from strix.telemetry import posthog

        posthog.error("llm_error", type(e).__name__)
        raise LLMRequestFailedError(f"LLM request failed: {type(e).__name__}", str(e)) from e

    def _is_anthropic(self) -> bool:
        if not self.config.model_name:
            return False
        return any(p in self.config.model_name.lower() for p in ["anthropic/", "claude"])

    def _supports_vision(self) -> bool:
        try:
            return bool(supports_vision(model=self.config.canonical_model))
        except Exception:  # noqa: BLE001
            return False

    def _supports_reasoning(self) -> bool:
        try:
            return bool(supports_reasoning(model=self.config.canonical_model))
        except Exception:  # noqa: BLE001
            return False

    def _strip_images(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result = []
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, list):
                text_parts = []
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text_parts.append(item.get("text", ""))
                    elif isinstance(item, dict) and item.get("type") == "image_url":
                        text_parts.append("[Image removed - model doesn't support vision]")
                result.append({**msg, "content": "\n".join(text_parts)})
            else:
                result.append(msg)
        return result

    def _add_cache_control(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not messages or not supports_prompt_caching(self.config.canonical_model):
            return messages

        result = list(messages)

        if result[0].get("role") == "system":
            content = result[0]["content"]
            result[0] = {
                **result[0],
                "content": [
                    {"type": "text", "text": content, "cache_control": {"type": "ephemeral"}}
                ]
                if isinstance(content, str)
                else content,
            }
        return result
