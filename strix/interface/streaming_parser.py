import html
import re
from dataclasses import dataclass
from typing import Literal


_FUNCTION_TAG_PREFIX = "<function="


def _get_safe_content(content: str) -> tuple[str, str]:
    if not content:
        return "", ""

    last_lt = content.rfind("<")
    if last_lt == -1:
        return content, ""

    suffix = content[last_lt:]
    target = _FUNCTION_TAG_PREFIX  # "<function="

    if target.startswith(suffix):
        return content[:last_lt], suffix

    return content, ""


@dataclass
class StreamSegment:
    type: Literal["text", "tool"]
    content: str
    tool_name: str | None = None
    args: dict[str, str] | None = None
    is_complete: bool = False


def parse_streaming_content(content: str) -> list[StreamSegment]:
    if not content:
        return []

    segments: list[StreamSegment] = []

    func_pattern = r"<function=([^>]+)>"
    func_matches = list(re.finditer(func_pattern, content))

    if not func_matches:
        safe_content, _ = _get_safe_content(content)
        text = safe_content.strip()
        if text:
            segments.append(StreamSegment(type="text", content=text))
        return segments

    first_func_start = func_matches[0].start()
    if first_func_start > 0:
        text_before = content[:first_func_start].strip()
        if text_before:
            segments.append(StreamSegment(type="text", content=text_before))

    for i, match in enumerate(func_matches):
        tool_name = match.group(1)
        func_start = match.end()

        func_end_match = re.search(r"</function>", content[func_start:])

        if func_end_match:
            func_body = content[func_start : func_start + func_end_match.start()]
            is_complete = True
            end_pos = func_start + func_end_match.end()
        else:
            if i + 1 < len(func_matches):
                next_func_start = func_matches[i + 1].start()
                func_body = content[func_start:next_func_start]
            else:
                func_body = content[func_start:]
            is_complete = False
            end_pos = len(content)

        args = _parse_streaming_params(func_body)

        segments.append(
            StreamSegment(
                type="tool",
                content=func_body,
                tool_name=tool_name,
                args=args,
                is_complete=is_complete,
            )
        )

        if is_complete and i + 1 < len(func_matches):
            next_start = func_matches[i + 1].start()
            text_between = content[end_pos:next_start].strip()
            if text_between:
                segments.append(StreamSegment(type="text", content=text_between))

    return segments


def _parse_streaming_params(func_body: str) -> dict[str, str]:
    args: dict[str, str] = {}

    complete_pattern = r"<parameter=([^>]+)>(.*?)</parameter>"
    complete_matches = list(re.finditer(complete_pattern, func_body, re.DOTALL))
    complete_end_pos = 0

    for match in complete_matches:
        param_name = match.group(1)
        param_value = html.unescape(match.group(2).strip())
        args[param_name] = param_value
        complete_end_pos = max(complete_end_pos, match.end())

    remaining = func_body[complete_end_pos:]
    incomplete_pattern = r"<parameter=([^>]+)>(.*)$"
    incomplete_match = re.search(incomplete_pattern, remaining, re.DOTALL)
    if incomplete_match:
        param_name = incomplete_match.group(1)
        param_value = html.unescape(incomplete_match.group(2).strip())
        args[param_name] = param_value

    return args
