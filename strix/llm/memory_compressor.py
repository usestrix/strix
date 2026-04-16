import logging
from typing import Any

import litellm

from strix.config.config import Config, resolve_llm_config


logger = logging.getLogger(__name__)


DEFAULT_MAX_TOTAL_TOKENS = 100_000
DEFAULT_MIN_RECENT_MESSAGES = 15
DEFAULT_MAX_TOOL_OUTPUT_CHARS = 0  # 0 = no truncation (backwards compatible)

TOOL_TRUNCATION_NOTICE = (
    "\n\n[Output truncated: showing first {head_len} and last {tail_len} characters "
    "of {original_len}-character output (limit: {max_len}). "
    "The middle portion has been permanently removed.]"
)

SUMMARY_PROMPT_TEMPLATE = """You are an agent performing context
condensation for a security agent. Your job is to compress scan data while preserving
ALL operationally critical information for continuing the security assessment.

CRITICAL ELEMENTS TO PRESERVE:
- Discovered vulnerabilities and potential attack vectors
- Scan results and tool outputs (compressed but maintaining key findings)
- Access credentials, tokens, or authentication details found
- System architecture insights and potential weak points
- Progress made in the assessment
- Failed attempts and dead ends (to avoid duplication)
- Any decisions made about the testing approach

COMPRESSION GUIDELINES:
- Preserve exact technical details (URLs, paths, parameters, payloads)
- Summarize verbose tool outputs while keeping critical findings
- Maintain version numbers, specific technologies identified
- Keep exact error messages that might indicate vulnerabilities
- Compress repetitive or similar findings into consolidated form

Remember: Another security agent will use this summary to continue the assessment.
They must be able to pick up exactly where you left off without losing any
operational advantage or context needed to find vulnerabilities.

CONVERSATION SEGMENT TO SUMMARIZE:
{conversation}

Provide a technically precise summary that preserves all operational security context while
keeping the summary concise and to the point."""


def _count_tokens(text: str, model: str) -> int:
    try:
        count = litellm.token_counter(model=model, text=text)
        return int(count)
    except Exception:
        logger.exception("Failed to count tokens")
        return len(text) // 4  # Rough estimate


def _get_message_tokens(msg: dict[str, Any], model: str) -> int:
    content = msg.get("content", "")
    if isinstance(content, str):
        return _count_tokens(content, model)
    if isinstance(content, list):
        return sum(
            _count_tokens(item.get("text", ""), model)
            for item in content
            if isinstance(item, dict) and item.get("type") == "text"
        )
    return 0


def _extract_message_text(msg: dict[str, Any]) -> str:
    content = msg.get("content", "")
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(item.get("text", ""))
                elif item.get("type") == "image_url":
                    parts.append("[IMAGE]")
        return " ".join(parts)

    return str(content)


def _summarize_messages(
    messages: list[dict[str, Any]],
    model: str,
    timeout: int = 30,
) -> dict[str, Any]:
    if not messages:
        empty_summary = "<context_summary message_count='0'>{text}</context_summary>"
        return {
            "role": "user",
            "content": empty_summary.format(text="No messages to summarize"),
        }

    formatted = []
    for msg in messages:
        role = msg.get("role", "unknown")
        text = _extract_message_text(msg)
        formatted.append(f"{role}: {text}")

    conversation = "\n".join(formatted)
    prompt = SUMMARY_PROMPT_TEMPLATE.format(conversation=conversation)

    _, api_key, api_base = resolve_llm_config()

    try:
        completion_args: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "timeout": timeout,
        }
        if api_key:
            completion_args["api_key"] = api_key
        if api_base:
            completion_args["api_base"] = api_base

        response = litellm.completion(**completion_args)
        summary = response.choices[0].message.content or ""
        if not summary.strip():
            return messages[0]
        summary_msg = "<context_summary message_count='{count}'>{text}</context_summary>"
        return {
            "role": "user",
            "content": summary_msg.format(count=len(messages), text=summary),
        }
    except Exception:
        logger.exception("Failed to summarize messages")
        return messages[0]


def _truncate_tool_output(text: str, max_chars: int) -> str:
    """Truncate large tool outputs while preserving the beginning and end.

    Keeps the first 60% and last 40% of the allowed length so that both
    the command/header and the tail of the output (often containing summaries
    or error messages) are preserved.
    """
    if max_chars <= 0 or len(text) <= max_chars:
        return text

    head_len = int(max_chars * 0.6)
    tail_len = max_chars - head_len
    notice = TOOL_TRUNCATION_NOTICE.format(
        original_len=len(text), max_len=max_chars, head_len=head_len, tail_len=tail_len
    )
    return text[:head_len] + notice + text[-tail_len:]


def _handle_images(messages: list[dict[str, Any]], max_images: int) -> None:
    image_count = 0
    for msg in reversed(messages):
        content = msg.get("content", [])
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "image_url":
                    if image_count >= max_images:
                        item.update(
                            {
                                "type": "text",
                                "text": "[Previously attached image removed to preserve context]",
                            }
                        )
                    else:
                        image_count += 1


class MemoryCompressor:
    def __init__(
        self,
        max_images: int = 3,
        model_name: str | None = None,
        timeout: int | None = None,
    ):
        self.max_images = max_images
        self.model_name = model_name or Config.get("strix_llm")
        self.timeout = timeout or int(Config.get("strix_memory_compressor_timeout") or "120")

        self.max_total_tokens = int(
            Config.get("strix_max_context_tokens") or str(DEFAULT_MAX_TOTAL_TOKENS)
        )
        self.min_recent_messages = int(
            Config.get("strix_min_recent_messages") or str(DEFAULT_MIN_RECENT_MESSAGES)
        )
        self.max_tool_output_chars = int(
            Config.get("strix_max_tool_output_chars") or str(DEFAULT_MAX_TOOL_OUTPUT_CHARS)
        )

        if not self.model_name:
            raise ValueError("STRIX_LLM environment variable must be set and not empty")

    def truncate_tool_outputs(self, messages: list[dict[str, Any]]) -> None:
        """Truncate large tool output messages in-place.

        This prevents oversized tool results (nmap scans, file contents, etc.)
        from accumulating in the conversation history and being resent on every
        subsequent LLM call. Applied at ingestion time before the history grows.

        Only truncates tool-role messages and tool_result content blocks to
        avoid corrupting system prompts or user/assistant messages.
        """
        if self.max_tool_output_chars <= 0:
            return

        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")

            # Direct tool-role messages (string content)
            if role == "tool" and isinstance(content, str) and len(content) > self.max_tool_output_chars:
                msg["content"] = _truncate_tool_output(content, self.max_tool_output_chars)
            # Anthropic-style: tool_result blocks embedded in user messages
            elif isinstance(content, list):
                for item in content:
                    if not isinstance(item, dict):
                        continue
                    if (
                        item.get("type") == "tool_result"
                        and isinstance(item.get("content"), str)
                        and len(item["content"]) > self.max_tool_output_chars
                    ):
                        item["content"] = _truncate_tool_output(
                            item["content"], self.max_tool_output_chars
                        )
                    elif (
                        item.get("type") == "tool_result"
                        and isinstance(item.get("content"), list)
                    ):
                        for sub in item["content"]:
                            if (
                                isinstance(sub, dict)
                                and sub.get("type") == "text"
                                and len(sub.get("text", "")) > self.max_tool_output_chars
                            ):
                                sub["text"] = _truncate_tool_output(
                                    sub["text"], self.max_tool_output_chars
                                )

    def compress_history(
        self,
        messages: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Compress conversation history to stay within token limits.

        Strategy:
        1. Truncate oversized tool outputs first
        2. Handle image limits
        3. Keep all system messages
        4. Keep minimum recent messages
        5. Summarize older messages when total tokens exceed limit

        The compression preserves:
        - All system messages unchanged
        - Most recent messages intact
        - Critical security context in summaries
        - Recent images for visual context
        - Technical details and findings
        """
        if not messages:
            return messages

        self.truncate_tool_outputs(messages)
        _handle_images(messages, self.max_images)

        system_msgs = []
        regular_msgs = []
        for msg in messages:
            if msg.get("role") == "system":
                system_msgs.append(msg)
            else:
                regular_msgs.append(msg)

        recent_msgs = regular_msgs[-self.min_recent_messages:]
        old_msgs = regular_msgs[:-self.min_recent_messages]

        # Type assertion since we ensure model_name is not None in __init__
        model_name: str = self.model_name  # type: ignore[assignment]

        total_tokens = sum(
            _get_message_tokens(msg, model_name) for msg in system_msgs + regular_msgs
        )

        if total_tokens <= self.max_total_tokens * 0.9:
            return messages

        compressed = []
        chunk_size = 10
        for i in range(0, len(old_msgs), chunk_size):
            chunk = old_msgs[i : i + chunk_size]
            summary = _summarize_messages(chunk, model_name, self.timeout)
            if summary:
                compressed.append(summary)

        return system_msgs + compressed + recent_msgs
