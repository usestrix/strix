"""Tests for the SecretRedactor module."""

import pytest

from strix.telemetry.redactor import SecretRedactor


class TestSecretRedactor:
    """Tests for SecretRedactor class."""

    def test_redact_api_key(self) -> None:
        """Test redaction of API key fields."""
        redactor = SecretRedactor()

        data = {"api_key": "sk-secret-12345", "name": "test"}
        result = redactor.redact(data)

        assert result["api_key"] == "[REDACTED]"
        assert result["name"] == "test"

    def test_redact_password(self) -> None:
        """Test redaction of password fields."""
        redactor = SecretRedactor()

        data = {"password": "supersecret", "username": "admin"}
        result = redactor.redact(data)

        assert result["password"] == "[REDACTED]"
        assert result["username"] == "admin"

    def test_redact_access_token(self) -> None:
        """Test redaction of access token fields."""
        redactor = SecretRedactor()

        data = {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "refresh_token": "refresh-token-value",
            "data": "normal",
        }
        result = redactor.redact(data)

        assert result["access_token"] == "[REDACTED]"
        assert result["refresh_token"] == "[REDACTED]"
        assert result["data"] == "normal"

    def test_redact_nested_dict(self) -> None:
        """Test redaction in nested dictionaries."""
        redactor = SecretRedactor()

        data = {
            "config": {
                "database": {"password": "dbpass123", "host": "localhost"},
                "api": {"secret_key": "my-secret"},
            },
            "name": "app",
        }
        result = redactor.redact(data)

        assert result["config"]["database"]["password"] == "[REDACTED]"
        assert result["config"]["database"]["host"] == "localhost"
        assert result["config"]["api"]["secret_key"] == "[REDACTED]"
        assert result["name"] == "app"

    def test_redact_list_of_dicts(self) -> None:
        """Test redaction in lists of dictionaries."""
        redactor = SecretRedactor()

        data = [
            {"api_key": "key1", "name": "service1"},
            {"api_key": "key2", "name": "service2"},
        ]
        result = redactor.redact(data)

        assert result[0]["api_key"] == "[REDACTED]"
        assert result[0]["name"] == "service1"
        assert result[1]["api_key"] == "[REDACTED]"
        assert result[1]["name"] == "service2"

    def test_redact_bearer_token_in_string(self) -> None:
        """Test redaction of Bearer tokens in string values."""
        redactor = SecretRedactor()

        data = {
            "headers": "Authorization: Bearer sk-very-long-secret-token-12345678901234567890",
            "method": "GET",
        }
        result = redactor.redact(data)

        assert "Bearer" not in result["headers"] or "[REDACTED]" in result["headers"]
        assert result["method"] == "GET"

    def test_redact_openai_api_key_pattern(self) -> None:
        """Test redaction of OpenAI API key pattern."""
        redactor = SecretRedactor()

        value = "Using API key: sk-abcdefghijklmnopqrstuvwxyz1234567890"
        result = redactor.redact(value)

        assert "sk-" not in result or "[REDACTED]" in result

    def test_redact_anthropic_api_key_pattern(self) -> None:
        """Test redaction of Anthropic API key pattern."""
        redactor = SecretRedactor()

        value = "Anthropic key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        result = redactor.redact(value)

        assert "sk-ant-" not in result or "[REDACTED]" in result

    def test_redact_aws_access_key_pattern(self) -> None:
        """Test redaction of AWS access key pattern."""
        redactor = SecretRedactor()

        value = "AWS key: AKIAIOSFODNN7EXAMPLE"
        result = redactor.redact(value)

        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_redact_env_vars_in_string(self) -> None:
        """Test redaction of environment variable values in strings."""
        redactor = SecretRedactor()

        value = 'export LLM_API_KEY="my-secret-key-value"'
        result = redactor.redact(value)

        assert "my-secret-key-value" not in result or "[REDACTED]" in result

    def test_redact_headers_method(self) -> None:
        """Test the specialized redact_headers method."""
        redactor = SecretRedactor()

        headers = {
            "Authorization": "Bearer secret-token",
            "X-API-Key": "another-secret",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        result = redactor.redact_headers(headers)

        assert result["Authorization"] == "[REDACTED]"
        assert result["X-API-Key"] == "[REDACTED]"
        assert result["Content-Type"] == "application/json"
        assert result["Accept"] == "application/json"

    def test_redact_cookie_header(self) -> None:
        """Test redaction of cookie headers."""
        redactor = SecretRedactor()

        headers = {"Cookie": "session=abc123; auth_token=secret123"}
        result = redactor.redact_headers(headers)

        assert result["Cookie"] == "[REDACTED]"

    def test_redact_none_value(self) -> None:
        """Test that None values pass through unchanged."""
        redactor = SecretRedactor()

        result = redactor.redact(None)
        assert result is None

    def test_redact_primitive_values(self) -> None:
        """Test that primitive values (int, float, bool) pass through unchanged."""
        redactor = SecretRedactor()

        assert redactor.redact(42) == 42
        assert redactor.redact(3.14) == 3.14
        assert redactor.redact(True) is True
        assert redactor.redact(False) is False

    def test_redact_empty_string(self) -> None:
        """Test that empty strings pass through unchanged."""
        redactor = SecretRedactor()

        assert redactor.redact("") == ""

    def test_redact_preserves_dict_structure(self) -> None:
        """Test that dictionary structure is preserved during redaction."""
        redactor = SecretRedactor()

        data = {
            "level1": {
                "level2": {
                    "level3": {"api_key": "secret", "data": [1, 2, 3]},
                },
            },
        }
        result = redactor.redact(data)

        assert isinstance(result["level1"]["level2"]["level3"]["data"], list)
        assert result["level1"]["level2"]["level3"]["data"] == [1, 2, 3]

    def test_redact_case_insensitive_keys(self) -> None:
        """Test that key matching is case-insensitive."""
        redactor = SecretRedactor()

        data = {
            "API_KEY": "secret1",
            "Api_Key": "secret2",
            "api_key": "secret3",
            "APIKEY": "secret4",
        }
        result = redactor.redact(data)

        for key in data:
            assert result[key] == "[REDACTED]"

    def test_redact_various_secret_patterns(self) -> None:
        """Test redaction of various secret key patterns."""
        redactor = SecretRedactor()

        data = {
            "private_key": "-----BEGIN RSA PRIVATE KEY-----",
            "client_secret": "oauth-client-secret",
            "database_password": "dbpass",
            "jwt_secret": "jwt-secret-key",
            "session_secret": "session-secret",
            "encryption_key": "enc-key",
            "signing_key": "sig-key",
        }
        result = redactor.redact(data)

        for key in data:
            assert result[key] == "[REDACTED]", f"Expected {key} to be redacted"

    def test_custom_additional_patterns(self) -> None:
        """Test adding custom patterns to the redactor."""
        import re

        custom_pattern = re.compile(r"(?i)my_custom_secret")
        redactor = SecretRedactor(additional_patterns=[custom_pattern])

        data = {"my_custom_secret": "should-be-redacted", "other": "visible"}
        result = redactor.redact(data)

        assert result["my_custom_secret"] == "[REDACTED]"
        assert result["other"] == "visible"

    def test_redact_long_alphanumeric_in_string(self) -> None:
        """Test redaction of long alphanumeric strings that look like tokens."""
        redactor = SecretRedactor()

        # 40+ character alphanumeric strings are likely tokens
        value = "Token: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        result = redactor.redact(value)

        # The long string should be redacted
        assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in result

    def test_redact_sandbox_token(self) -> None:
        """Test redaction of sandbox token fields."""
        redactor = SecretRedactor()

        data = {"sandbox_token": "sandbox-auth-token-123", "sandbox_id": "sbx-123"}
        result = redactor.redact(data)

        assert result["sandbox_token"] == "[REDACTED]"
        assert result["sandbox_id"] == "sbx-123"
