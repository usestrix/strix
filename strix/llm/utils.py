import html
import json
import re
from typing import Any


_INVOKE_OPEN = re.compile(
    r'<(?:invoke|function|tool_call|tool)\s+name=["\']([^"\']+)["\'][^>]*>',
    re.IGNORECASE,
)
_PARAM_NAME_ATTR = re.compile(r'<parameter\s+name=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
_WRAPPER_TAG = re.compile(r"</?(?:function_calls|tool_calls)(?:\s[^>]*)?>", re.IGNORECASE)
_MINIMAX_TOOL_CALL_TAG = re.compile(r"</?minimax:tool_call(?:\s[^>]*)?>", re.IGNORECASE)
_STRIP_TAG_QUOTES = re.compile(r"<(function|parameter)\s*=\s*([^>]*?)>", re.IGNORECASE)
_JSON_TOOL_CALL_BLOCK = re.compile(
    r"<tool_call(?:\s[^>]*)?>(.*?)</tool_call>",
    re.DOTALL | re.IGNORECASE,
)
_STRUCTURED_TOOL_CALL_BLOCK = re.compile(
    r"<tool_call(?:\s[^>]*)?>(.*?)</tool_call>",
    re.DOTALL | re.IGNORECASE,
)
_TOOL_NAME_TAG = re.compile(
    r"<(?:tool_name|name|function)>(.*?)</(?:tool_name|name|function)>",
    re.DOTALL | re.IGNORECASE,
)
_PARAMETERS_TAG = re.compile(r"<parameters(?:\s[^>]*)?>(.*?)</parameters>", re.DOTALL | re.IGNORECASE)
_SIMPLE_XML_FIELD = re.compile(r"<([A-Za-z_][\w.-]*)>(.*?)</\1>", re.DOTALL)


def normalize_tool_format(content: str) -> str:
    """Convert alternative tool-call XML formats to the expected one.

    Handles:
      <minimax:tool_call>...</minimax:tool_call>  → stripped
      <function_calls>...</function_calls>  → stripped
      <tool_calls>...</tool_calls>          → stripped
      <invoke name="X">                     → <function=X>
      <function name="X">                   → <function=X>
      <tool_call name="X">                  → <function=X>
      <parameter name="X">                  → <parameter=X>
      </invoke> / </tool_call>              → </function>
      <function="X">                        → <function=X>
      <parameter="X">                       → <parameter=X>
    """
    named_tool_call = bool(re.search(r"<tool_call\s+name=", content, re.IGNORECASE))
    content = _MINIMAX_TOOL_CALL_TAG.sub("", content)
    content = _WRAPPER_TAG.sub("", content)
    content = _INVOKE_OPEN.sub(r"<function=\1>", content)
    content = _PARAM_NAME_ATTR.sub(r"<parameter=\1>", content)
    content = re.sub(r"</(?:invoke|tool)>", "</function>", content, flags=re.IGNORECASE)
    if named_tool_call:
        content = re.sub(r"</tool_call>", "</function>", content, flags=re.IGNORECASE)

    return _STRIP_TAG_QUOTES.sub(
        lambda m: f"<{m.group(1)}={m.group(2).strip().strip(chr(34) + chr(39))}>", content
    )


STRIX_MODEL_MAP: dict[str, str] = {
    "claude-sonnet-4.6": "anthropic/claude-sonnet-4-6",
    "claude-opus-4.6": "anthropic/claude-opus-4-6",
    "gpt-5.2": "openai/gpt-5.2",
    "gpt-5.1": "openai/gpt-5.1",
    "gpt-5.4": "openai/gpt-5.4",
    "gemini-3-pro-preview": "gemini/gemini-3-pro-preview",
    "gemini-3-flash-preview": "gemini/gemini-3-flash-preview",
    "glm-5": "openrouter/z-ai/glm-5",
    "glm-4.7": "openrouter/z-ai/glm-4.7",
}


def resolve_strix_model(model_name: str | None) -> tuple[str | None, str | None]:
    """Resolve a strix/ model into names for API calls and capability lookups.

    Returns (api_model, canonical_model):
    - api_model: openai/<base> for API calls (Strix API is OpenAI-compatible)
    - canonical_model: actual provider model name for litellm capability lookups
    Non-strix models return the same name for both.
    """
    if not model_name or not model_name.startswith("strix/"):
        return model_name, model_name

    base_model = model_name[6:]
    api_model = f"openai/{base_model}"
    canonical_model = STRIX_MODEL_MAP.get(base_model, api_model)
    return api_model, canonical_model


def _truncate_to_first_function(content: str) -> str:
    if not content:
        return content

    function_starts = [
        match.start()
        for match in re.finditer(
            r"<function=|<invoke\s+name=|<tool_call\s+name=", content, re.IGNORECASE
        )
    ]

    if len(function_starts) >= 2:
        second_function_start = function_starts[1]

        return content[:second_function_start].rstrip()

    return content


def parse_tool_invocations(content: str) -> list[dict[str, Any]] | None:
    content = normalize_tool_format(content)
    content = fix_incomplete_tool_call(content)

    tool_invocations: list[dict[str, Any]] = []

    fn_regex_pattern = r"<function=([^>]+)>\n?(.*?)</function>"
    fn_param_regex_pattern = r"<parameter=([^>]+)>(.*?)</parameter>"

    fn_matches = re.finditer(fn_regex_pattern, content, re.DOTALL)

    for fn_match in fn_matches:
        fn_name = fn_match.group(1)
        fn_body = fn_match.group(2)

        param_matches = re.finditer(fn_param_regex_pattern, fn_body, re.DOTALL)

        args = {}
        for param_match in param_matches:
            param_name = param_match.group(1)
            param_value = param_match.group(2).strip()

            param_value = html.unescape(param_value)
            args[param_name] = param_value

        if not args:
            body_stripped = html.unescape(fn_body.strip())
            if body_stripped.startswith("{"):
                try:
                    parsed = json.loads(body_stripped)
                    if isinstance(parsed, dict):
                        args = {
                            k: v if isinstance(v, str) else json.dumps(v)
                            for k, v in parsed.items()
                        }
                except (json.JSONDecodeError, ValueError):
                    pass

        tool_invocations.append({"toolName": fn_name, "args": args})

    if tool_invocations:
        return tool_invocations

    tool_invocations = _parse_json_tool_call_blocks(content)
    if tool_invocations:
        return tool_invocations

    tool_invocations = _parse_structured_tool_call_blocks(content)
    return tool_invocations if tool_invocations else None


def _json_to_args(arguments: Any) -> dict[str, Any]:
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except (json.JSONDecodeError, ValueError):
            return {}

    if not isinstance(arguments, dict):
        return {}

    return {k: v if isinstance(v, str) else json.dumps(v) for k, v in arguments.items()}


def _parse_json_tool_call_blocks(content: str) -> list[dict[str, Any]]:
    tool_invocations: list[dict[str, Any]] = []

    for block_match in _JSON_TOOL_CALL_BLOCK.finditer(content):
        body = html.unescape(block_match.group(1).strip())
        if not body.startswith("{"):
            continue

        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            continue

        if not isinstance(parsed, dict):
            continue

        fn_name = parsed.get("name") or parsed.get("toolName") or parsed.get("tool_name")
        if not isinstance(fn_name, str) or not fn_name.strip():
            continue

        arguments = parsed.get("arguments", parsed.get("args", {}))
        tool_invocations.append({"toolName": fn_name.strip(), "args": _json_to_args(arguments)})

    return tool_invocations


def _parse_structured_tool_call_blocks(content: str) -> list[dict[str, Any]]:
    tool_invocations: list[dict[str, Any]] = []

    for block_match in _STRUCTURED_TOOL_CALL_BLOCK.finditer(content):
        body = block_match.group(1)
        name_match = _TOOL_NAME_TAG.search(body)
        if not name_match:
            continue

        fn_name = html.unescape(name_match.group(1).strip())
        if not fn_name:
            continue

        params_body_match = _PARAMETERS_TAG.search(body)
        params_body = params_body_match.group(1) if params_body_match else body
        excluded_fields = {"tool_name", "function", "parameters"}
        if params_body_match is None:
            excluded_fields.add("name")

        args = {}
        for param_match in _SIMPLE_XML_FIELD.finditer(params_body):
            param_name = param_match.group(1)
            if param_name.lower() in excluded_fields:
                continue
            args[param_name] = html.unescape(param_match.group(2).strip())

        tool_invocations.append({"toolName": fn_name, "args": args})

    return tool_invocations


def fix_incomplete_tool_call(content: str) -> str:
    """Fix incomplete tool calls by adding missing closing tag.

    Handles both ``<function=…>`` and ``<invoke name="…">`` formats.
    """
    has_open = bool(re.search(r"<(?:function=|invoke |tool_call )", content, re.IGNORECASE))
    count_open = len(re.findall(r"<(?:function=|invoke |tool_call )", content, re.IGNORECASE))
    has_close = bool(re.search(r"</(?:function|invoke|tool_call)>", content, re.IGNORECASE))
    if has_open and count_open == 1 and not has_close:
        content = content.rstrip()
        content = content + "function>" if content.endswith("</") else content + "\n</function>"
    return content


def format_tool_call(tool_name: str, args: dict[str, Any]) -> str:
    xml_parts = [f"<function={tool_name}>"]

    for key, value in args.items():
        xml_parts.append(f"<parameter={key}>{value}</parameter>")

    xml_parts.append("</function>")

    return "\n".join(xml_parts)


def clean_content(content: str) -> str:
    if not content:
        return ""

    content = normalize_tool_format(content)
    content = fix_incomplete_tool_call(content)

    tool_pattern = r"<function=[^>]+>.*?</function>"
    cleaned = re.sub(tool_pattern, "", content, flags=re.DOTALL)

    incomplete_tool_pattern = r"<function=[^>]+>.*$"
    cleaned = re.sub(incomplete_tool_pattern, "", cleaned, flags=re.DOTALL)

    partial_tag_pattern = r"<f(?:u(?:n(?:c(?:t(?:i(?:o(?:n(?:=(?:[^>]*)?)?)?)?)?)?)?)?)?$"
    cleaned = re.sub(partial_tag_pattern, "", cleaned)

    hidden_xml_patterns = [
        r"<inter_agent_message>.*?</inter_agent_message>",
        r"<agent_completion_report>.*?</agent_completion_report>",
    ]
    for pattern in hidden_xml_patterns:
        cleaned = re.sub(pattern, "", cleaned, flags=re.DOTALL | re.IGNORECASE)

    cleaned = re.sub(r"\n\s*\n", "\n\n", cleaned)

    return cleaned.strip()
