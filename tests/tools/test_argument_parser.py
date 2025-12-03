from collections.abc import Callable

import pytest

from strix.tools.argument_parser import (
    ArgumentConversionError,
    _convert_basic_types,
    _convert_to_bool,
    _convert_to_dict,
    _convert_to_list,
    convert_arguments,
    convert_string_to_type,
)


class TestConvertToBool:
    """Tests for the _convert_to_bool function."""

    @pytest.mark.parametrize(
        "value",
        ["true", "True", "TRUE", "1", "yes", "Yes", "YES", "on", "On", "ON"],
    )
    def test_truthy_values(self, value: str) -> None:
        """Test that truthy string values are converted to True."""
        assert _convert_to_bool(value) is True

    @pytest.mark.parametrize(
        "value",
        ["false", "False", "FALSE", "0", "no", "No", "NO", "off", "Off", "OFF"],
    )
    def test_falsy_values(self, value: str) -> None:
        """Test that falsy string values are converted to False."""
        assert _convert_to_bool(value) is False

    def test_non_standard_truthy_string(self) -> None:
        """Test that non-empty non-standard strings are truthy."""
        assert _convert_to_bool("anything") is True
        assert _convert_to_bool("hello") is True

    def test_empty_string(self) -> None:
        """Test that empty string is falsy."""
        assert _convert_to_bool("") is False


class TestConvertToList:
    """Tests for the _convert_to_list function."""

    def test_json_array_string(self) -> None:
        """Test parsing a JSON array string."""
        result = _convert_to_list('["a", "b", "c"]')
        assert result == ["a", "b", "c"]

    def test_json_array_with_numbers(self) -> None:
        """Test parsing a JSON array with numbers."""
        result = _convert_to_list("[1, 2, 3]")
        assert result == [1, 2, 3]

    def test_comma_separated_string(self) -> None:
        """Test parsing a comma-separated string."""
        result = _convert_to_list("a, b, c")
        assert result == ["a", "b", "c"]

    def test_comma_separated_no_spaces(self) -> None:
        """Test parsing comma-separated values without spaces."""
        result = _convert_to_list("x,y,z")
        assert result == ["x", "y", "z"]

    def test_single_value(self) -> None:
        """Test that a single value returns a list with one element."""
        result = _convert_to_list("single")
        assert result == ["single"]

    def test_json_non_array_wraps_in_list(self) -> None:
        """Test that a valid JSON non-array value is wrapped in a list."""
        result = _convert_to_list('"string"')
        assert result == ["string"]

    def test_json_object_wraps_in_list(self) -> None:
        """Test that a JSON object is wrapped in a list."""
        result = _convert_to_list('{"key": "value"}')
        assert result == [{"key": "value"}]

    def test_empty_json_array(self) -> None:
        """Test parsing an empty JSON array."""
        result = _convert_to_list("[]")
        assert result == []


class TestConvertToDict:
    """Tests for the _convert_to_dict function."""

    def test_valid_json_object(self) -> None:
        """Test parsing a valid JSON object string."""
        result = _convert_to_dict('{"key": "value", "number": 42}')
        assert result == {"key": "value", "number": 42}

    def test_empty_json_object(self) -> None:
        """Test parsing an empty JSON object."""
        result = _convert_to_dict("{}")
        assert result == {}

    def test_invalid_json_returns_empty_dict(self) -> None:
        """Test that invalid JSON returns an empty dictionary."""
        result = _convert_to_dict("not json")
        assert result == {}

    def test_json_array_returns_empty_dict(self) -> None:
        """Test that a JSON array returns an empty dictionary."""
        result = _convert_to_dict("[1, 2, 3]")
        assert result == {}

    def test_nested_json_object(self) -> None:
        """Test parsing a nested JSON object."""
        result = _convert_to_dict('{"outer": {"inner": "value"}}')
        assert result == {"outer": {"inner": "value"}}


class TestConvertBasicTypes:
    """Tests for the _convert_basic_types function."""

    def test_convert_to_int(self) -> None:
        """Test converting string to int."""
        assert _convert_basic_types("42", int) == 42
        assert _convert_basic_types("-10", int) == -10

    def test_convert_to_float(self) -> None:
        """Test converting string to float."""
        assert _convert_basic_types("3.14", float) == 3.14
        assert _convert_basic_types("-2.5", float) == -2.5

    def test_convert_to_str(self) -> None:
        """Test converting string to str (passthrough)."""
        assert _convert_basic_types("hello", str) == "hello"

    def test_convert_to_bool(self) -> None:
        """Test converting string to bool."""
        assert _convert_basic_types("true", bool) is True
        assert _convert_basic_types("false", bool) is False

    def test_convert_to_list_type(self) -> None:
        """Test converting to list type."""
        result = _convert_basic_types("[1, 2, 3]", list)
        assert result == [1, 2, 3]

    def test_convert_to_dict_type(self) -> None:
        """Test converting to dict type."""
        result = _convert_basic_types('{"a": 1}', dict)
        assert result == {"a": 1}

    def test_unknown_type_attempts_json(self) -> None:
        """Test that unknown types attempt JSON parsing."""
        result = _convert_basic_types('{"key": "value"}', object)
        assert result == {"key": "value"}

    def test_unknown_type_returns_original(self) -> None:
        """Test that unparseable values are returned as-is."""
        result = _convert_basic_types("plain text", object)
        assert result == "plain text"


class TestConvertStringToType:
    """Tests for the convert_string_to_type function."""

    def test_basic_type_conversion(self) -> None:
        """Test basic type conversions."""
        assert convert_string_to_type("42", int) == 42
        assert convert_string_to_type("3.14", float) == 3.14
        assert convert_string_to_type("true", bool) is True

    def test_optional_type(self) -> None:
        """Test conversion with Optional type."""
        result = convert_string_to_type("42", int | None)
        assert result == 42

    def test_union_type(self) -> None:
        """Test conversion with Union type."""
        result = convert_string_to_type("42", int | str)
        assert result == 42

    def test_union_type_with_none(self) -> None:
        """Test conversion with Union including None."""
        result = convert_string_to_type("hello", str | None)
        assert result == "hello"

    def test_modern_union_syntax(self) -> None:
        """Test conversion with modern union syntax (int | None)."""
        result = convert_string_to_type("100", int | None)
        assert result == 100


class TestConvertArguments:
    """Tests for the convert_arguments function."""

    def test_converts_typed_arguments(
        self, sample_function_with_types: Callable[..., None]
    ) -> None:
        """Test that arguments are converted based on type annotations."""
        kwargs = {
            "name": "test",
            "count": "5",
            "enabled": "true",
            "ratio": "2.5",
            "items": "[1, 2, 3]",
            "config": '{"key": "value"}',
        }
        result = convert_arguments(sample_function_with_types, kwargs)

        assert result["name"] == "test"
        assert result["count"] == 5
        assert result["enabled"] is True
        assert result["ratio"] == 2.5
        assert result["items"] == [1, 2, 3]
        assert result["config"] == {"key": "value"}

    def test_passes_through_none_values(
        self, sample_function_with_types: Callable[..., None]
    ) -> None:
        """Test that None values are passed through unchanged."""
        kwargs = {"name": "test", "count": None}
        result = convert_arguments(sample_function_with_types, kwargs)
        assert result["count"] is None

    def test_passes_through_non_string_values(
        self, sample_function_with_types: Callable[..., None]
    ) -> None:
        """Test that non-string values are passed through unchanged."""
        kwargs = {"name": "test", "count": 42}
        result = convert_arguments(sample_function_with_types, kwargs)
        assert result["count"] == 42

    def test_unknown_parameter_passed_through(
        self, sample_function_with_types: Callable[..., None]
    ) -> None:
        """Test that parameters not in signature are passed through."""
        kwargs = {"name": "test", "unknown_param": "value"}
        result = convert_arguments(sample_function_with_types, kwargs)
        assert result["unknown_param"] == "value"

    def test_function_without_annotations(
        self, sample_function_no_annotations: Callable[..., None]
    ) -> None:
        """Test handling of functions without type annotations."""
        kwargs = {"arg1": "value1", "arg2": "42"}
        result = convert_arguments(sample_function_no_annotations, kwargs)
        assert result["arg1"] == "value1"
        assert result["arg2"] == "42"

    def test_raises_error_on_conversion_failure(
        self, sample_function_with_types: Callable[..., None]
    ) -> None:
        """Test that ArgumentConversionError is raised on conversion failure."""
        kwargs = {"count": "not_a_number"}
        with pytest.raises(ArgumentConversionError) as exc_info:
            convert_arguments(sample_function_with_types, kwargs)
        assert exc_info.value.param_name == "count"


class TestArgumentConversionError:
    """Tests for the ArgumentConversionError exception class."""

    def test_error_with_param_name(self) -> None:
        """Test creating error with parameter name."""
        error = ArgumentConversionError("Test error", param_name="test_param")
        assert error.param_name == "test_param"
        assert str(error) == "Test error"

    def test_error_without_param_name(self) -> None:
        """Test creating error without parameter name."""
        error = ArgumentConversionError("Test error")
        assert error.param_name is None
        assert str(error) == "Test error"
