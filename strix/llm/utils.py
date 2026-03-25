import html
import re
from typing import Any


_INVOKE_OPEN = re.compile(r'<invoke\s+name=["\']([^"\']+)["\']>')
_PARAM_NAME_ATTR = re.compile(r'<parameter\s+name=["\']([^"\']+)["\']>')
_FUNCTION_CALLS_TAG = re.compile(r"</?function_calls>")
_STRIP_TAG_QUOTES = re.compile(r"<(function|parameter)\s*=\s*([^>]*?)>")


def normalize_tool_format(content: str) -> str:
    """Convert alternative tool-call XML formats to the expected one.

    Handles:
      <function_calls>...</function_calls>  → stripped
      <invoke name="X">                     → <function=X>
      <parameter name="X">                  → <parameter=X>
      </invoke>                             → </function>
      <function="X">                        → <function=X>
      <parameter="X">                       → <parameter=X>
    """
    if "<invoke" in content or "<function_calls" in content:
        content = _FUNCTION_CALLS_TAG.sub("", content)
        content = _INVOKE_OPEN.sub(r"<function=\1>", content)
        content = _PARAM_NAME_ATTR.sub(r"<parameter=\1>", content)
        content = content.replace("</invoke>", "</function>")

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

KNOWN_PROVIDER_PREFIXES: set[str] = {
    "anthropic",
    "azure",
    "azure_ai",
    "bedrock",
    "cerebras",
    "claude",
    "cohere",
    "deepseek",
    "fireworks_ai",
    "gemini",
    "github",
    "google",
    "groq",
    "huggingface",
    "mistral",
    "ollama",
    "openai",
    "openrouter",
    "perplexity",
    "replicate",
    "sambanova",
    "vertex_ai",
    "voyage",
    "watsonx",
    "xai",
}


def resolve_strix_model(
    model_name: str | None,
    api_base: str | None = None,
    openai_compatible_provider: str | None = None,
) -> tuple[str | None, str | None]:
    """Resolve a strix/ model into names for API calls and capability lookups.

    Returns (api_model, canonical_model):
    - api_model: openai/<base> for API calls (Strix API is OpenAI-compatible)
    - canonical_model: actual provider model name for litellm capability lookups
    Non-strix models return the same name for both.
    """
    if not model_name:
        return None, None

    if not model_name.startswith("strix/"):
        if api_base and openai_compatible_provider:
            provider_model = _apply_openai_compatible_provider(
                model_name,
                openai_compatible_provider,
            )
            if _register_openai_compatible_provider(provider_model, api_base):
                return provider_model, provider_model
            return f"openai/{provider_model}", provider_model

        if api_base and _looks_like_openai_compatible_model(model_name):
            inferred_provider_model = model_name
            if _register_openai_compatible_provider(inferred_provider_model, api_base):
                return inferred_provider_model, inferred_provider_model
            return f"openai/{model_name}", model_name
        return model_name, model_name

    base_model = model_name[6:]
    api_model = f"openai/{base_model}"
    canonical_model = STRIX_MODEL_MAP.get(base_model, api_model)
    return api_model, canonical_model


def _looks_like_openai_compatible_model(model_name: str) -> bool:
    if "/" not in model_name or model_name.startswith("openai/"):
        return False

    provider_prefix = model_name.split("/", 1)[0].lower()
    return provider_prefix not in KNOWN_PROVIDER_PREFIXES


def _apply_openai_compatible_provider(model_name: str, provider_name: str) -> str:
    normalized_provider = provider_name.strip()
    normalized_model = model_name.strip()
    if not normalized_provider or not normalized_model:
        return model_name

    if "/" not in normalized_model:
        return f"{normalized_provider}/{normalized_model}"

    existing_provider, provider_model = normalized_model.split("/", 1)
    if existing_provider.lower() == normalized_provider.lower():
        return f"{normalized_provider}/{provider_model}"

    if existing_provider.lower() in KNOWN_PROVIDER_PREFIXES:
        return normalized_model

    return f"{normalized_provider}/{normalized_model}"


def _register_openai_compatible_provider(model_name: str, api_base: str) -> bool:
    provider_slug = model_name.split("/", 1)[0].strip()
    normalized_base = api_base.strip()
    if not provider_slug or not normalized_base:
        return False

    try:
        from litellm.llms.openai_like.json_loader import JSONProviderRegistry, SimpleProviderConfig
    except Exception:  # noqa: BLE001
        return False

    provider_data = {
        "base_url": normalized_base,
        # LiteLLM requires this field for JSON providers, but Strix passes api_key directly.
        "api_key_env": _provider_api_key_env(provider_slug),
        "base_class": "openai_gpt",
    }

    aliases = {provider_slug, provider_slug.lower()}
    for alias in aliases:
        existing = JSONProviderRegistry.get(alias)
        if existing and existing.base_url == normalized_base:
            continue
        JSONProviderRegistry._providers[alias] = SimpleProviderConfig(alias, provider_data)

    JSONProviderRegistry._loaded = True
    return True


def _provider_api_key_env(provider_slug: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9]+", "_", provider_slug).strip("_")
    return f"{sanitized.upper()}_API_KEY" if sanitized else "STRIX_OPENAI_COMPATIBLE_API_KEY"


def _truncate_to_first_function(content: str) -> str:
    if not content:
        return content

    function_starts = [
        match.start() for match in re.finditer(r"<function=|<invoke\s+name=", content)
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

        tool_invocations.append({"toolName": fn_name, "args": args})

    return tool_invocations if tool_invocations else None


def fix_incomplete_tool_call(content: str) -> str:
    """Fix incomplete tool calls by adding missing closing tag.

    Handles both ``<function=…>`` and ``<invoke name="…">`` formats.
    """
    has_open = "<function=" in content or "<invoke " in content
    count_open = content.count("<function=") + content.count("<invoke ")
    has_close = "</function>" in content or "</invoke>" in content
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
