"""Tests for credential_names in build_scope_context."""

from __future__ import annotations

from strix.core.inputs import build_scope_context


def _base_config() -> dict:
    return {
        "targets": [
            {
                "type": "web_application",
                "original": "https://example.com",
                "details": {"target_url": "https://example.com"},
            }
        ]
    }


def test_no_credentials_gives_no_credential_names():
    ctx = build_scope_context(_base_config())
    assert ctx.get("credential_names") == []


def test_credentials_appear_as_sorted_names():
    config = {**_base_config(), "credentials": {"PASSWORD": "s", "USERNAME": "u"}}
    ctx = build_scope_context(config)
    assert ctx["credential_names"] == ["PASSWORD", "USERNAME"]


def test_empty_credentials_gives_empty_list():
    config = {**_base_config(), "credentials": {}}
    ctx = build_scope_context(config)
    assert ctx["credential_names"] == []
