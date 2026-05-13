from strix.llm.utils import normalize_tool_format, parse_tool_invocations


def test_parse_anthropic_invoke_inside_function_calls_with_attributes() -> None:
    content = """
<function_calls status="ok">
<invoke name="create_agent">
<parameter name="task">Run recon</parameter>
<parameter name="name">Recon Agent</parameter>
</invoke>
</function_calls>
"""

    assert parse_tool_invocations(content) == [
        {"toolName": "create_agent", "args": {"task": "Run recon", "name": "Recon Agent"}}
    ]


def test_parse_function_name_attribute_format() -> None:
    content = """
<function name="create_agent">
<parameter name="task">Check auth</parameter>
<parameter name="name">Auth Agent</parameter>
</function>
"""

    assert parse_tool_invocations(content) == [
        {"toolName": "create_agent", "args": {"task": "Check auth", "name": "Auth Agent"}}
    ]


def test_parse_named_tool_call_format() -> None:
    content = """
<tool_call name="create_agent">
<parameter name="task">Check XSS</parameter>
<parameter name="name">XSS Agent</parameter>
</tool_call>
"""

    assert parse_tool_invocations(content) == [
        {"toolName": "create_agent", "args": {"task": "Check XSS", "name": "XSS Agent"}}
    ]


def test_parse_json_tool_call_block() -> None:
    content = """
<tool_call>
{"name": "create_agent", "arguments": {"task": "Map endpoints", "name": "API Agent"}}
</tool_call>
"""

    assert parse_tool_invocations(content) == [
        {"toolName": "create_agent", "args": {"task": "Map endpoints", "name": "API Agent"}}
    ]


def test_parse_structured_tool_call_block() -> None:
    content = """
<tool_call>
  <tool_name>create_agent</tool_name>
  <parameters>
    <task>Validate SSRF</task>
    <name>SSRF Agent</name>
  </parameters>
</tool_call>
"""

    assert parse_tool_invocations(content) == [
        {"toolName": "create_agent", "args": {"task": "Validate SSRF", "name": "SSRF Agent"}}
    ]


def test_normalize_tool_calls_wrapper() -> None:
    content = """
<tool_calls>
<function name="wait_for_message">
<parameter name="reason">Waiting for child agent</parameter>
</function>
</tool_calls>
"""

    assert "<tool_calls>" not in normalize_tool_format(content)
    assert parse_tool_invocations(content) == [
        {"toolName": "wait_for_message", "args": {"reason": "Waiting for child agent"}}
    ]
