"""Tests for stripping the markdown code fence off stored code fields."""

from __future__ import annotations

from strix.interface.tui.renderers.fenced import parse_fenced_code
from strix.viewer.report_pdf import _strip_code_fence


def test_parse_fenced_code_extracts_language_and_body() -> None:
    language, code = parse_fenced_code("```python\nimport requests\nprint(1)\n```")
    assert language == "python"
    assert code == "import requests\nprint(1)"


def test_parse_fenced_code_uses_first_token_of_info_string() -> None:
    language, code = parse_fenced_code("```python title=app.py\nx = 1\n```")
    assert language == "python"
    assert code == "x = 1"


def test_parse_fenced_code_handles_non_python_language() -> None:
    language, code = parse_fenced_code("```http\nGET / HTTP/1.1\n```")
    assert language == "http"
    assert code == "GET / HTTP/1.1"


def test_parse_fenced_code_passes_through_unfenced() -> None:
    language, code = parse_fenced_code("import requests\nprint(1)")
    assert language is None
    assert code == "import requests\nprint(1)"


def test_parse_fenced_code_fence_without_language() -> None:
    language, code = parse_fenced_code("```\nplain\n```")
    assert language is None
    assert code == "plain"


def test_strip_code_fence_removes_fence() -> None:
    assert _strip_code_fence("```python\nx = 1\n```") == "x = 1"


def test_strip_code_fence_passes_through_non_string_and_unfenced() -> None:
    assert _strip_code_fence(None) is None
    assert _strip_code_fence("x = 1") == "x = 1"
