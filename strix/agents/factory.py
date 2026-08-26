"""Build SandboxAgents for root + child Strix runs."""

from __future__ import annotations

import dataclasses
import inspect
import json
import logging
import re
from typing import TYPE_CHECKING, Any

from agents.agent import ToolsToFinalOutputResult
from agents.sandbox import SandboxAgent
from agents.sandbox.capabilities import Filesystem, Shell
from agents.sandbox.errors import InvalidManifestPathError
from agents.tool import CustomTool, FunctionTool, Tool
from pydantic import ValidationError

from strix.agents.prompt import render_system_prompt
from strix.config import load_settings
from strix.tools.agents_graph.tools import (
    agent_finish,
    create_agent,
    send_message_to_agent,
    stop_agent,
    view_agent_graph,
    wait_for_agents,
)
from strix.tools.coverage.tools import list_coverage, record_coverage, update_coverage
from strix.tools.finish.tool import finish_scan
from strix.tools.load_skill.tool import load_skill
from strix.tools.notes.tools import (
    create_note,
    delete_note,
    get_note,
    list_notes,
    update_note,
)
from strix.tools.nullish import is_nullish
from strix.tools.output_store import bound_and_store, bound_text
from strix.tools.proxy.tools import (
    list_requests,
    list_sitemap,
    repeat_request,
    scope_rules,
    view_request,
    view_sitemap_entry,
)
from strix.tools.reporting.tool import (
    create_dependency_report,
    create_vulnerability_report,
    get_report,
    list_reports,
)
from strix.tools.respond.tool import respond_to_user
from strix.tools.thinking.tool import think
from strix.tools.threat_model.tools import (
    amend_threat_model,
    get_threat_model,
    save_threat_model,
)
from strix.tools.todo.tools import (
    create_todo,
    delete_todo,
    list_todos,
    mark_todo_done,
    mark_todo_pending,
    update_todo,
)
from strix.tools.web_search.tool import web_search


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from agents import RunContextWrapper
    from agents.tool import FunctionToolResult


logger = logging.getLogger(__name__)


_CUSTOM_TOOL_INPUT_FIELD_BY_NAME = {
    "apply_patch": "patch",
}
_DEFAULT_CUSTOM_TOOL_INPUT_FIELD = "input"


def _custom_tool_input_field(tool: CustomTool) -> str:
    return _CUSTOM_TOOL_INPUT_FIELD_BY_NAME.get(tool.name, _DEFAULT_CUSTOM_TOOL_INPUT_FIELD)


def _raw_input_schema(tool: CustomTool) -> dict[str, Any]:
    input_field = _custom_tool_input_field(tool)
    return {
        "type": "object",
        "properties": {
            input_field: {
                "type": "string",
                "description": (
                    f"Complete `{tool.name}` payload. Follow the tool description exactly."
                ),
            },
        },
        "required": [input_field],
        "additionalProperties": False,
    }


def _extract_custom_input(tool: CustomTool, raw_input: str | dict[str, Any]) -> str:
    if isinstance(raw_input, str):
        try:
            parsed = json.loads(raw_input)
        except json.JSONDecodeError:
            return ""
    else:
        parsed = raw_input
    value = parsed.get(_custom_tool_input_field(tool))
    return value if isinstance(value, str) else ""


def _tool_output_limits() -> tuple[int, int]:
    context = load_settings().context
    return context.tool_output_max_lines, context.tool_output_max_bytes


async def _bound_result(result: Any) -> Any:
    if not isinstance(result, str):
        return result
    max_lines, max_bytes = _tool_output_limits()
    return await bound_and_store(result, max_lines=max_lines, max_bytes=max_bytes)


def _format_tool_error(exc: Exception) -> str:
    message = str(exc) or exc.__class__.__name__
    max_lines, max_bytes = _tool_output_limits()
    return bound_text(message, max_lines=max_lines, max_bytes=max_bytes)


def _with_bounded_result(tool: FunctionTool) -> FunctionTool:
    """Cap a tool's result size before it enters history (idempotent)."""
    if getattr(tool, "_strix_bounded", False):
        return tool
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        return await _bound_result(await invoke_tool(ctx, raw_input))

    tool.on_invoke_tool = invoke
    tool._strix_bounded = True  # type: ignore[attr-defined]
    return tool


def _schema_types(spec: dict[str, Any]) -> set[str]:
    types: set[str] = set()
    raw = spec.get("type")
    if isinstance(raw, str):
        types.add(raw)
    elif isinstance(raw, list):
        types.update(t for t in raw if isinstance(t, str))
    for variant in spec.get("anyOf") or ():
        if isinstance(variant, dict):
            types |= _schema_types(variant)
    types.discard("null")
    return types


def _allows_null(spec: dict[str, Any]) -> bool:
    raw = spec.get("type")
    if raw == "null" or (isinstance(raw, list) and "null" in raw):
        return True
    return any(
        isinstance(variant, dict) and _allows_null(variant) for variant in spec.get("anyOf") or ()
    )


def _is_nullable(key: str, spec: dict[str, Any], schema: dict[str, Any]) -> bool:
    """Whether ``key`` may be ``None``.

    Strict schemas list every property as required, so nullability shows up as a
    ``null`` type variant; without a declared one, fall back to the property
    being absent from a declared ``required`` list.
    """
    if _allows_null(spec):
        return True
    required = schema.get("required")
    return isinstance(required, list) and key not in required


def _decode_structured(value: str, types: set[str]) -> Any:
    stripped = value.strip()
    if not stripped:
        # An empty string is the model's "no value" for a list/dict param; give it
        # the empty container so it validates instead of failing the type check.
        return [] if "array" in types else {}
    try:
        decoded = json.loads(stripped)
    except json.JSONDecodeError:
        return value
    wanted = list if "array" in types else dict
    return decoded if isinstance(decoded, wanted) else value


def _coerce_argument(value: Any, spec: dict[str, Any], *, nullable: bool = False) -> Any:
    if value is None:
        return value
    if nullable and is_nullish(value):
        # The model's stand-in for "no value"; as a filter it matches nothing.
        return None
    types = _schema_types(spec)
    if not types:
        return value
    if isinstance(value, list | dict) and "string" in types and not types & {"array", "object"}:
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, str) and types & {"array", "object"} and "string" not in types:
        return _decode_structured(value, types)
    return value


# Only query tools get nullish coercion: there a literal "null" is a filter that
# matches nothing, while a tool that writes may well be given it as real content.
_QUERY_TOOL_PREFIXES = ("list_", "search_", "view_", "get_")


def _coerce_arguments(raw_input: str, schema: dict[str, Any], *, nullish: bool = False) -> str:
    properties = schema.get("properties")
    if not isinstance(properties, dict) or not properties:
        return raw_input
    try:
        payload = json.loads(raw_input) if raw_input else None
    except json.JSONDecodeError:
        return raw_input
    if not isinstance(payload, dict):
        return raw_input

    changed = False
    for key, value in payload.items():
        spec = properties.get(key)
        if not isinstance(spec, dict):
            continue
        coerced = _coerce_argument(
            value, spec, nullable=nullish and _is_nullable(key, spec, schema)
        )
        if coerced is not value:
            payload[key] = coerced
            changed = True

    if not changed:
        return raw_input
    return json.dumps(payload, ensure_ascii=False)


def _with_coerced_arguments(tool: FunctionTool) -> FunctionTool:
    if getattr(tool, "_strix_coerced", False):
        return tool
    invoke_tool = tool.on_invoke_tool
    schema = tool.params_json_schema
    nullish = tool.name.startswith(_QUERY_TOOL_PREFIXES)

    async def invoke(ctx: Any, raw_input: str) -> Any:
        return await invoke_tool(ctx, _coerce_arguments(raw_input, schema, nullish=nullish))

    tool.on_invoke_tool = invoke
    tool._strix_coerced = True  # type: ignore[attr-defined]
    return tool


def _with_strictness(tool: FunctionTool, strict_schemas: bool) -> FunctionTool:
    """Drop strict JSON-schema mode when the route can't take it (see
    ``supports_strict_tool_schemas``); the tool stays functionally identical.

    Returns a copy so the shared tool singletons keep their declared mode.
    """
    if strict_schemas or not tool.strict_json_schema:
        return tool
    return dataclasses.replace(tool, strict_json_schema=False)


def _function_tool_with_error_result(tool: FunctionTool) -> FunctionTool:
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        try:
            return await _bound_result(await invoke_tool(ctx, raw_input))
        except Exception as exc:  # noqa: BLE001 - tool errors should be model-visible results.
            logger.debug("Tool %s failed; returning error as result", tool.name, exc_info=True)
            return _format_tool_error(exc)

    tool.on_invoke_tool = invoke
    return tool


def _custom_tool_as_function_tool(tool: CustomTool) -> FunctionTool:
    async def invoke(ctx: Any, raw_input: str) -> Any:
        custom_input = _extract_custom_input(tool, raw_input)
        if not custom_input:
            return f"`{_custom_tool_input_field(tool)}` must be a non-empty string."
        try:
            return await _bound_result(await tool.on_invoke_tool(ctx, custom_input))
        except Exception as exc:  # noqa: BLE001 - matches SDK CustomTool error-as-result behavior.
            logger.debug("Tool %s failed; returning error as result", tool.name, exc_info=True)
            return _format_tool_error(exc)

    needs_approval = tool.runtime_needs_approval()
    function_needs_approval: bool | Callable[[Any, dict[str, Any], str], Awaitable[bool]]
    if callable(needs_approval):

        async def approve(ctx: Any, args: dict[str, Any], call_id: str) -> bool:
            result = needs_approval(ctx, _extract_custom_input(tool, args), call_id)
            if inspect.isawaitable(result):
                result = await result
            return bool(result)

        function_needs_approval = approve
    else:
        function_needs_approval = needs_approval

    return FunctionTool(
        name=tool.name,
        description=(
            f"{tool.description}\n\n"
            f"Pass the complete `{tool.name}` payload in `{_custom_tool_input_field(tool)}`."
        ),
        params_json_schema=_raw_input_schema(tool),
        on_invoke_tool=invoke,
        strict_json_schema=False,
        needs_approval=function_needs_approval,
    )


def _bound_custom_tool(tool: CustomTool) -> CustomTool:
    """Bound a native ``CustomTool`` result in place (Responses path)."""
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        return await _bound_result(await invoke_tool(ctx, raw_input))

    tool.on_invoke_tool = invoke
    return tool


def _configure_filesystem_tools(
    toolset: Any, *, chat_completions: bool, strict_schemas: bool = True
) -> None:
    for name, tool in vars(toolset).items():
        if chat_completions:
            if isinstance(tool, CustomTool):
                setattr(toolset, name, _custom_tool_as_function_tool(tool))
            elif isinstance(tool, FunctionTool):
                setattr(
                    toolset,
                    name,
                    _function_tool_with_error_result(
                        _with_strictness(_with_coerced_arguments(tool), strict_schemas)
                    ),
                )
        elif isinstance(tool, CustomTool):
            setattr(toolset, name, _bound_custom_tool(tool))
        elif isinstance(tool, FunctionTool):
            setattr(
                toolset,
                name,
                _with_bounded_result(
                    _with_strictness(_with_coerced_arguments(tool), strict_schemas)
                ),
            )


def _make_filesystem_configurator(*, chat_completions: bool, strict_schemas: bool) -> Any:
    def configure(toolset: Any) -> None:
        _configure_filesystem_tools(
            toolset, chat_completions=chat_completions, strict_schemas=strict_schemas
        )

    return configure


_CHARS_ESCAPE_RE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0abtnvfr\\])")
_CHARS_ESCAPE_MAP = {
    "\\\\": "\\",
    "\\n": "\n",
    "\\t": "\t",
    "\\r": "\r",
    "\\0": "\x00",
    "\\a": "\x07",
    "\\b": "\x08",
    "\\v": "\x0b",
    "\\f": "\x0c",
}


def _decode_chars_escape(s: str) -> str:
    if "\\" not in s:
        return s

    def sub(match: re.Match[str]) -> str:
        token = match.group(0)
        if token in _CHARS_ESCAPE_MAP:
            return _CHARS_ESCAPE_MAP[token]
        if token.startswith(("\\u", "\\x")):
            return chr(int(token[2:], 16))
        return token

    return _CHARS_ESCAPE_RE.sub(sub, s)


def _format_validation_error(tool_name: str, exc: ValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err.get("loc", ()))
        msg = err.get("msg", "invalid")
        parts.append(f"{loc}: {msg}" if loc else msg)
    return f"{tool_name}: invalid arguments — " + "; ".join(parts)


def _apply_shell_output_cap(parsed: dict[str, Any]) -> None:
    """Clamp the SDK shell tools' ``max_output_tokens`` to the configured
    ceiling; a smaller explicit value is respected."""
    ceiling = load_settings().context.tool_output_max_tokens
    requested = parsed.get("max_output_tokens")
    parsed["max_output_tokens"] = (
        ceiling if not isinstance(requested, int) or requested > ceiling else requested
    )


def _wrap_exec_command(tool: FunctionTool) -> FunctionTool:
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        try:
            parsed = json.loads(raw_input)
        except (json.JSONDecodeError, TypeError):
            parsed = None
        if isinstance(parsed, dict):
            if "shell" not in parsed:
                parsed["shell"] = "bash"
            _apply_shell_output_cap(parsed)
            raw_input = json.dumps(parsed)
        try:
            return await invoke_tool(ctx, raw_input)
        except ValidationError as exc:
            return _format_validation_error(tool.name, exc)
        except InvalidManifestPathError as exc:
            rel = exc.context.get("rel", "?")
            return (
                "exec_command: workdir must be a path inside /workspace "
                "(or omitted to use the turn's cwd). "
                f"Got: {rel!r}."
            )

    tool.on_invoke_tool = invoke
    return tool


def _wrap_write_stdin(tool: FunctionTool) -> FunctionTool:
    invoke_tool = tool.on_invoke_tool

    async def invoke(ctx: Any, raw_input: str) -> Any:
        try:
            parsed = json.loads(raw_input)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            if isinstance(parsed.get("chars"), str):
                parsed["chars"] = _decode_chars_escape(parsed["chars"])
            _apply_shell_output_cap(parsed)
            raw_input = json.dumps(parsed)
        try:
            return await invoke_tool(ctx, raw_input)
        except ValidationError as exc:
            return _format_validation_error(tool.name, exc)

    tool.on_invoke_tool = invoke
    return tool


def _configure_shell_tools(
    toolset: Any, *, chat_completions: bool, strict_schemas: bool = True
) -> None:
    for name, tool in vars(toolset).items():
        if not isinstance(tool, FunctionTool):
            continue
        wrapped = _with_strictness(_with_coerced_arguments(tool), strict_schemas)
        if tool.name == "exec_command":
            wrapped = _wrap_exec_command(wrapped)
        elif tool.name == "write_stdin":
            wrapped = _wrap_write_stdin(wrapped)
        if chat_completions:
            wrapped = _function_tool_with_error_result(wrapped)
        setattr(toolset, name, wrapped)


def _make_shell_configurator(*, chat_completions: bool, strict_schemas: bool) -> Any:
    def configure(toolset: Any) -> None:
        _configure_shell_tools(
            toolset, chat_completions=chat_completions, strict_schemas=strict_schemas
        )

    return configure


# Tools that hand control away by parking the agent rather than ending the scan.
_PARKING_TOOLS: frozenset[str] = frozenset({"respond_to_user", "wait_for_agents"})


def _lifecycle_tool_completed(tool_name: str, output: Any) -> bool:
    if tool_name == "agent_finish":
        completion_key = "agent_completed"
    elif tool_name == "finish_scan":
        completion_key = "scan_completed"
    else:
        return False

    if not isinstance(output, str):
        return False
    try:
        parsed = json.loads(output)
    except (TypeError, ValueError):
        return False
    return bool(isinstance(parsed, dict) and parsed.get("success") and parsed.get(completion_key))


def _wait_tool_parked(tool_name: str, output: Any) -> bool:
    if tool_name not in _PARKING_TOOLS or not isinstance(output, str):
        return False
    try:
        parsed = json.loads(output)
    except (TypeError, ValueError):
        return False
    return bool(
        isinstance(parsed, dict)
        and parsed.get("success")
        and parsed.get("wait_outcome") == "waiting"
    )


def _finish_tool_use_behavior(
    ctx: RunContextWrapper[Any],
    tool_results: list[FunctionToolResult],
) -> ToolsToFinalOutputResult:
    """Stop only after a lifecycle tool reports successful completion."""
    interactive = (
        bool(ctx.context.get("interactive", False)) if isinstance(ctx.context, dict) else False
    )
    for tool_result in tool_results:
        if _lifecycle_tool_completed(tool_result.tool.name, tool_result.output):
            return ToolsToFinalOutputResult(
                is_final_output=True,
                final_output=tool_result.output,
            )
        if interactive and _wait_tool_parked(tool_result.tool.name, tool_result.output):
            return ToolsToFinalOutputResult(
                is_final_output=True,
                final_output=tool_result.output,
            )
    return ToolsToFinalOutputResult(is_final_output=False, final_output=None)


_BASE_TOOLS: tuple[Tool, ...] = (
    think,
    load_skill,
    create_todo,
    list_todos,
    update_todo,
    mark_todo_done,
    mark_todo_pending,
    delete_todo,
    create_note,
    list_notes,
    get_note,
    update_note,
    delete_note,
    record_coverage,
    update_coverage,
    list_coverage,
    get_threat_model,
    save_threat_model,
    amend_threat_model,
    web_search,
    create_vulnerability_report,
    create_dependency_report,
    list_reports,
    get_report,
    list_requests,
    view_request,
    repeat_request,
    list_sitemap,
    view_sitemap_entry,
    scope_rules,
    view_agent_graph,
    send_message_to_agent,
    wait_for_agents,
    create_agent,
    stop_agent,
)


# Extra tools registered for scan agents. Mirrors
# ``strix.runtime.backends.register_backend``: register before the first
# ``build_strix_agent`` call and every agent (root + children) gets them.
_EXTRA_TOOLS: list[Tool] = []


def _ensure_unique_tool_names(tools: Sequence[Tool]) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for tool in tools:
        if tool.name in seen:
            duplicates.add(tool.name)
        seen.add(tool.name)
    if duplicates:
        msg = f"Agent tools must have unique names: {sorted(duplicates)}"
        raise ValueError(msg)


def register_agent_tools(*tools: Tool) -> None:
    """Register tools for every scan agent built afterwards.

    Tools are added to both root and child agents, after the base set and
    before the lifecycle tool (``finish_scan`` / ``agent_finish``). Duplicate
    tool objects are ignored so repeated imports don't double-register.
    """
    new_tools: list[Tool] = []
    for tool in tools:
        if tool not in _EXTRA_TOOLS and tool not in new_tools:
            new_tools.append(tool)

    _ensure_unique_tool_names([*_BASE_TOOLS, *_EXTRA_TOOLS, *new_tools, finish_scan, agent_finish])

    for tool in new_tools:
        _EXTRA_TOOLS.append(tool)
        logger.info("Registered extra agent tool: %s", getattr(tool, "name", tool))


def registered_agent_tools() -> tuple[Tool, ...]:
    """Return the currently registered scan-agent tools."""
    return tuple(_EXTRA_TOOLS)


def build_strix_agent(
    *,
    name: str = "agent",
    skills: list[str] | None = None,
    is_root: bool,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_diff_scoped: bool = False,
    interactive: bool = False,
    chat_completions_tools: bool = False,
    strict_tool_schemas: bool = True,
    system_prompt_context: dict[str, Any] | None = None,
    extra_tools: Sequence[Tool] | None = None,
    instructions_override: str | None = None,
) -> SandboxAgent[Any]:
    """Build a SandboxAgent for either root or child use.

    Args:
        chat_completions_tools: Wrap SDK custom tools as function tools
            when the selected backend cannot accept Responses custom tools.
        strict_tool_schemas: Send function tools as strict-schema tools. Off
            for routes that reject a toolset this size as strict.
        extra_tools: Additional tools for this scan agent only, on top of any
            registered via ``register_agent_tools``.
        instructions_override: Use this verbatim as the system prompt instead
            of rendering the built-in scan prompt.
    """
    if instructions_override is not None:
        instructions = instructions_override
    else:
        instructions = render_system_prompt(
            skills=skills,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_root=is_root,
            is_diff_scoped=is_diff_scoped,
            interactive=interactive,
            system_prompt_context=system_prompt_context,
        )

    agent_tools = [*_EXTRA_TOOLS, *(extra_tools or [])]
    if interactive:
        # Yielding to the user is only meaningful when one is attached.
        agent_tools.append(respond_to_user)
    if is_root:
        tools: list[Tool] = [*_BASE_TOOLS, *agent_tools, finish_scan]
    else:
        tools = [*_BASE_TOOLS, *agent_tools, agent_finish]
    _ensure_unique_tool_names(tools)
    tools = [
        _with_bounded_result(_with_strictness(_with_coerced_arguments(tool), strict_tool_schemas))
        if isinstance(tool, FunctionTool)
        else tool
        for tool in tools
    ]

    logger.info(
        "Built %s agent '%s' (skills=%d, tools=%d, scan_mode=%s, whitebox=%s)",
        "root" if is_root else "child",
        name,
        len(skills or []),
        len(tools),
        scan_mode,
        is_whitebox,
    )

    return SandboxAgent(
        name=name,
        instructions=instructions,
        tools=tools,
        tool_use_behavior=_finish_tool_use_behavior,
        model=None,
        capabilities=[
            Filesystem(
                configure_tools=_make_filesystem_configurator(
                    chat_completions=chat_completions_tools,
                    strict_schemas=strict_tool_schemas,
                ),
            ),
            Shell(
                configure_tools=_make_shell_configurator(
                    chat_completions=chat_completions_tools,
                    strict_schemas=strict_tool_schemas,
                ),
            ),
        ],
    )


def make_child_factory(
    *,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_diff_scoped: bool = False,
    interactive: bool = False,
    chat_completions_tools: bool = False,
    strict_tool_schemas: bool = True,
    system_prompt_context: dict[str, Any] | None = None,
) -> Any:
    """Return the runner-owned builder used by ``spawn_child_agent``.

    Run-level arguments (``scan_mode``, ``is_whitebox``, etc.) are
    captured in a closure so each child inherits scan-level configuration
    without the graph tool knowing about runner internals.
    """

    def _factory(*, name: str, skills: list[str]) -> SandboxAgent[Any]:
        return build_strix_agent(
            name=name,
            skills=skills,
            is_root=False,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_diff_scoped=is_diff_scoped,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            strict_tool_schemas=strict_tool_schemas,
            system_prompt_context=system_prompt_context,
        )

    return _factory
