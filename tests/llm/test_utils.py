import pytest

from strix.llm.utils import (
    _fix_stopword,
    _truncate_to_first_function,
    clean_content,
    format_tool_call,
    parse_tool_invocations,
)


class TestParseToolInvocations:
    """Tests for parse_tool_invocations function."""

    def test_single_function_with_params(self) -> None:
        content = """<function=test_tool>
<parameter=arg1>value1</parameter>
<parameter=arg2>value2</parameter>
</function>"""
        result = parse_tool_invocations(content)
        assert result == [{"toolName": "test_tool", "args": {"arg1": "value1", "arg2": "value2"}}]

    def test_multiple_functions(self) -> None:
        content = """<function=tool1>
<parameter=a>1</parameter>
</function>
<function=tool2>
<parameter=b>2</parameter>
</function>"""
        result = parse_tool_invocations(content)
        assert result is not None
        assert len(result) == 2
        assert result[0]["toolName"] == "tool1"
        assert result[1]["toolName"] == "tool2"

    def test_html_entities_unescaped(self) -> None:
        content = """<function=test>
<parameter=code>&lt;div&gt;hello&lt;/div&gt;</parameter>
</function>"""
        result = parse_tool_invocations(content)
        assert result is not None
        assert result[0]["args"]["code"] == "<div>hello</div>"

    def test_empty_content_returns_none(self) -> None:
        assert parse_tool_invocations("") is None

    def test_no_functions_returns_none(self) -> None:
        assert parse_tool_invocations("just some text without functions") is None

    def test_function_without_params(self) -> None:
        content = "<function=no_args></function>"
        result = parse_tool_invocations(content)
        assert result == [{"toolName": "no_args", "args": {}}]

    def test_multiline_param_value(self) -> None:
        content = """<function=write>
<parameter=content>line 1
line 2
line 3</parameter>
</function>"""
        result = parse_tool_invocations(content)
        assert result is not None
        assert "line 1\nline 2\nline 3" == result[0]["args"]["content"]

    def test_ampersand_entity(self) -> None:
        content = """<function=test>
<parameter=query>foo &amp; bar</parameter>
</function>"""
        result = parse_tool_invocations(content)
        assert result is not None
        assert result[0]["args"]["query"] == "foo & bar"


class TestFixStopword:
    """Tests for _fix_stopword function."""

    def test_complete_function_unchanged(self) -> None:
        content = "<function=test>\n<parameter=x>1</parameter>\n</function>"
        assert _fix_stopword(content) == content

    def test_ending_with_incomplete_slash(self) -> None:
        content = "<function=test>\n<parameter=x>1</parameter>\n</"
        result = _fix_stopword(content)
        assert result.endswith("</function>")

    def test_missing_closing_tag(self) -> None:
        content = "<function=test>\n<parameter=x>1</parameter>"
        result = _fix_stopword(content)
        assert result.endswith("</function>")

    def test_multiple_functions_no_fix(self) -> None:
        content = "<function=a></function><function=b></function>"
        assert _fix_stopword(content) == content


class TestFormatToolCall:
    """Tests for format_tool_call function."""

    def test_basic_formatting(self) -> None:
        result = format_tool_call("my_tool", {"arg": "value"})
        assert "<function=my_tool>" in result
        assert "<parameter=arg>value</parameter>" in result
        assert "</function>" in result

    def test_multiple_params(self) -> None:
        result = format_tool_call("tool", {"a": "1", "b": "2"})
        assert "<parameter=a>1</parameter>" in result
        assert "<parameter=b>2</parameter>" in result

    def test_empty_args(self) -> None:
        result = format_tool_call("empty", {})
        assert result == "<function=empty>\n</function>"

    def test_preserves_newlines_in_value(self) -> None:
        result = format_tool_call("tool", {"code": "line1\nline2"})
        assert "line1\nline2" in result


class TestCleanContent:
    """Tests for clean_content function."""

    def test_remove_function_tags(self) -> None:
        content = "Hello <function=test><parameter=x>1</parameter></function> World"
        result = clean_content(content)
        assert "<function" not in result
        assert "Hello" in result
        assert "World" in result

    def test_remove_inter_agent_message(self) -> None:
        content = "Start <inter_agent_message>hidden</inter_agent_message> End"
        result = clean_content(content)
        assert "inter_agent_message" not in result
        assert "hidden" not in result

    def test_remove_agent_completion_report(self) -> None:
        content = "Begin <agent_completion_report>done</agent_completion_report> Finish"
        result = clean_content(content)
        assert "agent_completion_report" not in result
        assert "done" not in result

    def test_preserve_normal_content(self) -> None:
        content = "This is normal text with no special tags."
        assert clean_content(content) == content

    def test_empty_content(self) -> None:
        assert clean_content("") == ""
        assert clean_content(None) == ""  # type: ignore[arg-type]

    def test_collapse_multiple_newlines(self) -> None:
        content = "line1\n\n\n\nline2"
        result = clean_content(content)
        assert "\n\n\n" not in result


class TestTruncateToFirstFunction:
    """Tests for _truncate_to_first_function function."""

    def test_single_function_unchanged(self) -> None:
        content = "text <function=test></function> more"
        assert _truncate_to_first_function(content) == content

    def test_multiple_functions_keeps_first(self) -> None:
        content = "start <function=first></function> middle <function=second></function> end"
        result = _truncate_to_first_function(content)
        assert "<function=first>" in result
        assert "<function=second>" not in result

    def test_no_functions_unchanged(self) -> None:
        content = "no functions here"
        assert _truncate_to_first_function(content) == content

    def test_empty_content(self) -> None:
        assert _truncate_to_first_function("") == ""
