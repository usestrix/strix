from litellm import get_llm_provider
from litellm.llms.openai_like.json_loader import JSONProviderRegistry

from strix.llm.utils import resolve_strix_model


def test_resolve_custom_openai_compatible_model_with_api_base() -> None:
    api_model, canonical_model = resolve_strix_model(
        "AstronCodingPlan/astron-code-latest",
        api_base="https://maas-coding-api.cn-huabei-1.xf-yun.com/v2",
    )

    assert api_model == "AstronCodingPlan/astron-code-latest"
    assert canonical_model == "AstronCodingPlan/astron-code-latest"
    assert JSONProviderRegistry.exists("AstronCodingPlan")

    resolved_model, provider, dynamic_api_key, api_base = get_llm_provider(
        model=api_model,
        api_base="https://maas-coding-api.cn-huabei-1.xf-yun.com/v2",
        api_key="test-key",
    )

    assert resolved_model == "astron-code-latest"
    assert provider == "AstronCodingPlan"
    assert dynamic_api_key == "test-key"
    assert api_base == "https://maas-coding-api.cn-huabei-1.xf-yun.com/v2"


def test_resolve_explicit_openai_compatible_provider_from_config() -> None:
    api_model, canonical_model = resolve_strix_model(
        "astron-code-latest",
        api_base="https://maas-coding-api.cn-huabei-1.xf-yun.com/v2",
        openai_compatible_provider="AstronCodingPlan",
    )

    assert api_model == "AstronCodingPlan/astron-code-latest"
    assert canonical_model == "AstronCodingPlan/astron-code-latest"
    assert JSONProviderRegistry.exists("AstronCodingPlan")

    resolved_model, provider, dynamic_api_key, api_base = get_llm_provider(
        model=api_model,
        api_base="https://maas-coding-api.cn-huabei-1.xf-yun.com/v2",
        api_key="test-key",
    )

    assert resolved_model == "astron-code-latest"
    assert provider == "AstronCodingPlan"
    assert dynamic_api_key == "test-key"
    assert api_base == "https://maas-coding-api.cn-huabei-1.xf-yun.com/v2"


def test_resolve_known_provider_model_with_api_base_keeps_provider() -> None:
    api_model, canonical_model = resolve_strix_model(
        "anthropic/claude-sonnet-4-6",
        api_base="https://example.com/v1",
    )

    assert api_model == "anthropic/claude-sonnet-4-6"
    assert canonical_model == "anthropic/claude-sonnet-4-6"
