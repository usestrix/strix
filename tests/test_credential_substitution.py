"""Tests for credential placeholder substitution and output scrubbing."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

from agents.tool import FunctionTool

from strix.agents.factory import _wrap_credential_substitution
from strix.tools.credentials.tool import scrub_credentials, substitute_credentials


# ---------------------------------------------------------------------------
# substitute_credentials
# ---------------------------------------------------------------------------


def test_substitute_known_placeholder() -> None:
    creds = {"PASSWORD": "s3cr3t"}
    assert substitute_credentials("pass={{PASSWORD}}", creds) == "pass=s3cr3t"


def test_substitute_unknown_placeholder_unchanged() -> None:
    creds = {"PASSWORD": "s3cr3t"}
    assert substitute_credentials("{{UNKNOWN}}", creds) == "{{UNKNOWN}}"


def test_substitute_multiple_placeholders() -> None:
    creds = {"USER": "admin", "PASS": "hunter2"}
    result = substitute_credentials("curl -u {{USER}}:{{PASS}} http://x", creds)
    assert result == "curl -u admin:hunter2 http://x"


def test_substitute_empty_value() -> None:
    creds = {"EMPTY": ""}
    assert substitute_credentials("x={{EMPTY}}!", creds) == "x=!"


def test_substitute_case_sensitive() -> None:
    creds = {"PASSWORD": "s3cr3t"}
    # lowercase key does not match uppercase credential
    assert substitute_credentials("{{password}}", creds) == "{{password}}"


def test_substitute_no_credentials_returns_unchanged() -> None:
    assert substitute_credentials("{{PASSWORD}}", {}) == "{{PASSWORD}}"


def test_substitute_text_without_placeholders() -> None:
    creds = {"PASSWORD": "s3cr3t"}
    assert substitute_credentials("no placeholders here", creds) == "no placeholders here"


# ---------------------------------------------------------------------------
# scrub_credentials
# ---------------------------------------------------------------------------


def test_scrub_long_value_replaced() -> None:
    creds = {"PASSWORD": "supersecret"}
    result = scrub_credentials("output: supersecret done", creds)
    assert result == "output: [CREDENTIAL:PASSWORD] done"


def test_scrub_short_value_not_replaced() -> None:
    # Values shorter than 4 chars must not be scrubbed
    creds = {"PIN": "123"}
    result = scrub_credentials("code 123 here", creds)
    assert result == "code 123 here"


def test_scrub_multiple_occurrences() -> None:
    creds = {"TOKEN": "abcd1234"}
    result = scrub_credentials("token=abcd1234 and again abcd1234", creds)
    assert result == "token=[CREDENTIAL:TOKEN] and again [CREDENTIAL:TOKEN]"


def test_scrub_longest_first_prevents_partial_overlap() -> None:
    # "password" is a prefix of "password123"; longest must be replaced first
    creds = {"SHORT": "pass", "LONG": "password123"}
    result = scrub_credentials("password123", creds)
    # "pass" (len 4) would match inside "password123", but "password123" (len 11)
    # is replaced first, leaving no "pass" substring.
    assert result == "[CREDENTIAL:LONG]"


def test_scrub_no_credentials_returns_unchanged() -> None:
    assert scrub_credentials("some output", {}) == "some output"


def test_scrub_value_exactly_4_chars() -> None:
    creds = {"KEY": "abcd"}
    result = scrub_credentials("value abcd here", creds)
    assert result == "value [CREDENTIAL:KEY] here"


# ---------------------------------------------------------------------------
# _wrap_credential_substitution integration
# ---------------------------------------------------------------------------


def test_wrap_substitutes_input_and_scrubs_output() -> None:
    received_inputs: list[str] = []

    async def inner(_ctx: Any, raw_input: str) -> str:
        received_inputs.append(raw_input)
        # Echo back the substituted value so we can verify scrubbing
        return "executed with supersecret done"

    original = FunctionTool(
        name="test_tool",
        description="test",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=inner,
    )
    wrapped = _wrap_credential_substitution(original)

    ctx = MagicMock()
    ctx.context = {"credentials": {"PASSWORD": "supersecret"}}

    result = asyncio.run(wrapped.on_invoke_tool(ctx, '{"cmd": "login {{PASSWORD}}"}'))

    # Input must have placeholder replaced
    assert received_inputs == ['{"cmd": "login supersecret"}']
    # Output must have the value scrubbed
    assert "supersecret" not in result
    assert "[CREDENTIAL:PASSWORD]" in result


def test_wrap_does_not_mutate_original_tool() -> None:
    async def inner(_ctx: Any, raw_input: str) -> str:
        return raw_input

    original = FunctionTool(
        name="singleton_tool",
        description="test",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=inner,
    )
    original_invoke = original.on_invoke_tool

    _wrap_credential_substitution(original)

    # The original tool must not be mutated
    assert original.on_invoke_tool is original_invoke


def test_wrap_passthrough_when_no_credentials() -> None:
    async def inner(_ctx: Any, _raw_input: str) -> str:
        return "result with {{PASSWORD}}"

    original = FunctionTool(
        name="tool",
        description="test",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=inner,
    )
    wrapped = _wrap_credential_substitution(original)

    ctx = MagicMock()
    ctx.context = {"credentials": {}}

    result = asyncio.run(wrapped.on_invoke_tool(ctx, "{{PASSWORD}}"))
    # No substitution or scrubbing when credentials dict is empty
    assert result == "result with {{PASSWORD}}"
