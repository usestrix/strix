"""Tests for provider default-domain classification."""

from strix.interface.cloud.domain_verifier import (
    get_provider_info,
    is_provider_default_domain,
    validate_domain_verification_method,
)


def test_provider_domains_are_case_insensitive_and_label_aware() -> None:
    assert is_provider_default_domain("Demo.Vercel.App.")
    assert is_provider_default_domain("user.github.io")
    assert not is_provider_default_domain("notvercel.app")
    assert not is_provider_default_domain("demo.vercel.app.evil.example")


def test_provider_info_and_verification_method() -> None:
    info = get_provider_info("demo.vercel.app")
    assert info is not None
    assert info.provider == "vercel"
    assert validate_domain_verification_method("demo.vercel.app") == (True, "provider")
    assert validate_domain_verification_method("example.com") == (True, "dns")
    assert validate_domain_verification_method("") == (False, "unknown")
