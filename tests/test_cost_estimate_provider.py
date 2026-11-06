"""Cost estimates must stay local: no provider inference, no authentication."""

from __future__ import annotations

from types import SimpleNamespace

import litellm
import pytest

from strix.report.pricing import split_provider_model
from strix.report.state import _estimate_response_cost
from strix.report.usage import _estimate_litellm_entry_cost


def _register(monkeypatch: pytest.MonkeyPatch, name: str) -> str:
    """Add a synthetic provider-prefixed catalog entry and forbid inference."""
    litellm.model_cost[name] = {
        "input_cost_per_token": 1e-6,
        "output_cost_per_token": 2e-6,
        "litellm_provider": name.split("/", 1)[0],
        "mode": "chat",
    }

    def _inference_is_forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("cost estimation asked LiteLLM to infer the provider")

    monkeypatch.setattr(litellm, "get_llm_provider", _inference_is_forbidden)
    return name


def test_split_provider_model_separates_the_provider() -> None:
    assert split_provider_model("github_copilot/gpt-4o") == ("github_copilot", "gpt-4o")
    assert split_provider_model("gpt-4o") == (None, "gpt-4o")


def test_entry_cost_uses_the_resolved_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _register(monkeypatch, "github_copilot/synthetic-entry")
    entry = SimpleNamespace(input_tokens=1000, output_tokens=500, total_tokens=1500)

    assert _estimate_litellm_entry_cost(entry, model) == pytest.approx(0.002)


def test_response_cost_uses_the_resolved_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _register(monkeypatch, "github_copilot/synthetic-response")
    kwargs = {"model": model}
    response = {"usage": {"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500}}

    assert _estimate_response_cost(kwargs, response) == pytest.approx(0.002)
