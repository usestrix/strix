from strix.llm.utils import normalize_tool_format, parse_tool_invocations


def test_parse_tool_invocations_ignores_prose_examples() -> None:
    content = "Use `<function>search>` syntax in docs, but do not execute it."

    assert normalize_tool_format(content) == content
    assert parse_tool_invocations(content) is None


def test_parse_tool_invocations_accepts_malformed_function_open_tag() -> None:
    content = (
        "<function>search>\n"
        "<parameter=query>latest docs</parameter>\n"
        "</function>"
    )

    assert parse_tool_invocations(content) == [
        {"toolName": "search", "args": {"query": "latest docs"}}
    ]
