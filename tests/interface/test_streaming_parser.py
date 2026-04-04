"""Tests for streaming_parser._get_safe_content.

In particular, tests for the edge case where the LLM has streamed enough characters
that the suffix goes *past* the tag prefix (e.g. '<function=terminal') but hasn't
emitted the closing '>' yet.  Before the fix, _get_safe_content would treat such a
suffix as safe text and expose the partial tag in the TUI.
"""

import importlib.util
from pathlib import Path


def _load_streaming_parser():
    module_path = (
        Path(__file__).resolve().parents[2]
        / "strix"
        / "interface"
        / "streaming_parser.py"
    )
    spec = importlib.util.spec_from_file_location("streaming_parser_test", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to load streaming_parser for tests")
    module = importlib.util.module_from_spec(spec)

    # streaming_parser imports normalize_tool_format; provide a minimal stub so
    # the module can be loaded without the full strix package installed.
    import types, sys

    fake_llm_utils = types.ModuleType("strix.llm.utils")
    fake_llm_utils.normalize_tool_format = lambda s: s  # type: ignore[attr-defined]
    sys.modules.setdefault("strix", types.ModuleType("strix"))
    sys.modules.setdefault("strix.llm", types.ModuleType("strix.llm"))
    _original_llm_utils = sys.modules.get("strix.llm.utils")
    sys.modules["strix.llm.utils"] = fake_llm_utils

    try:
        spec.loader.exec_module(module)
    finally:
        if _original_llm_utils is None:
            sys.modules.pop("strix.llm.utils", None)
        else:
            sys.modules["strix.llm.utils"] = _original_llm_utils
    return module


_mod = _load_streaming_parser()
_get_safe_content = _mod._get_safe_content


class TestGetSafeContentEmptyAndNoTag:
    def test_empty_string(self):
        assert _get_safe_content("") == ("", "")

    def test_no_angle_bracket(self):
        assert _get_safe_content("hello world") == ("hello world", "")

    def test_non_function_tag(self):
        # A regular XML tag that is NOT a function/invoke tag must pass through.
        assert _get_safe_content("text<other") == ("text<other", "")

    def test_math_less_than(self):
        # A bare '<' that is not the start of any known tag must pass through.
        assert _get_safe_content("a < b") == ("a < b", "")


class TestGetSafeContentShortPrefixes:
    """Suffixes that are strict prefixes of '<function=' or '<invoke '."""

    def test_angle_bracket_only(self):
        safe, pending = _get_safe_content("text<")
        assert safe == "text"
        assert pending == "<"

    def test_f(self):
        safe, pending = _get_safe_content("text<f")
        assert safe == "text"
        assert pending == "<f"

    def test_func(self):
        safe, pending = _get_safe_content("text<func")
        assert safe == "text"
        assert pending == "<func"

    def test_function_no_equals(self):
        safe, pending = _get_safe_content("text<function")
        assert safe == "text"
        assert pending == "<function"

    def test_function_equals(self):
        safe, pending = _get_safe_content("text<function=")
        assert safe == "text"
        assert pending == "<function="

    def test_inv(self):
        safe, pending = _get_safe_content("text<inv")
        assert safe == "text"
        assert pending == "<inv"

    def test_invoke_no_space(self):
        safe, pending = _get_safe_content("text<invoke")
        assert safe == "text"
        assert pending == "<invoke"

    def test_invoke_with_space(self):
        safe, pending = _get_safe_content("text<invoke ")
        assert safe == "text"
        assert pending == "<invoke "


class TestGetSafeContentLongPartialTags:
    """
    Suffixes that have gone *past* the tag prefix but have not yet received '>'.

    This is the regression case: previously _FUNCTION_TAG_PREFIX.startswith(suffix)
    returned False for these (the suffix is longer than the prefix), so the partial
    tag leaked into the 'safe' portion of the content.
    """

    def test_partial_function_name(self):
        """'<function=termin' must be held as pending, not shown as text."""
        safe, pending = _get_safe_content("Analyzing...\n<function=termin")
        assert safe == "Analyzing...\n"
        assert pending == "<function=termin"

    def test_full_function_name_no_close(self):
        """'<function=terminal_execute' (without '>') must still be held as pending."""
        safe, pending = _get_safe_content("text<function=terminal_execute")
        assert safe == "text"
        assert pending == "<function=terminal_execute"

    def test_partial_invoke_name(self):
        """'<invoke name=cmd' (without '>') must be held as pending."""
        safe, pending = _get_safe_content("text<invoke name=cmd")
        assert safe == "text"
        assert pending == "<invoke name=cmd"

    def test_partial_invoke_with_more_attrs(self):
        """'<invoke name=terminal_execute' (without '>') must be held."""
        safe, pending = _get_safe_content("text<invoke name=terminal_execute")
        assert safe == "text"
        assert pending == "<invoke name=terminal_execute"


class TestGetSafeContentCompleteTags:
    """When a complete tag (including '>') is present, it is safe text — not pending."""

    def test_complete_function_tag(self):
        """A complete '<function=name>' must NOT be held as pending."""
        content = "text<function=terminal_execute>"
        safe, pending = _get_safe_content(content)
        assert safe == content
        assert pending == ""

    def test_complete_invoke_tag(self):
        """A complete '<invoke name=cmd>' must NOT be held as pending."""
        content = "text<invoke name=cmd>"
        safe, pending = _get_safe_content(content)
        assert safe == content
        assert pending == ""


class TestGetSafeContentMultipleTags:
    """Content that already contains a complete function tag followed by a partial one."""

    def test_complete_then_partial(self):
        content = "pre<function=x> more text<function=y"
        safe, pending = _get_safe_content(content)
        assert safe == "pre<function=x> more text"
        assert pending == "<function=y"

    def test_complete_then_partial_invoke(self):
        content = "pre<function=x> text<invoke name=b"
        safe, pending = _get_safe_content(content)
        assert safe == "pre<function=x> text"
        assert pending == "<invoke name=b"
