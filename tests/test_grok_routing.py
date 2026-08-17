"""Grok subscription routing through StrixProvider.get_model."""

from __future__ import annotations

import argparse
from unittest import mock

from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel

from strix.config import grok, subscription
from strix.config.models import StrixProvider, _TurnGuardModel
from strix.interface import scan_setup, utils
from strix.report import state as state_mod


def test_grok_prefix_routes_to_chat_completions(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    client = mock.MagicMock()
    monkeypatch.setattr(grok, "get_subscription_client", lambda: client)

    model = StrixProvider().get_model("grok/grok-4")

    assert isinstance(model, _TurnGuardModel)
    assert isinstance(model._inner, OpenAIChatCompletionsModel)
    # The provider strips the grok/ prefix and passes xAI's bare model slug.
    assert model._inner.model == "grok-4"


def test_non_subscription_model_is_not_hijacked_by_grok(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def _boom() -> object:
        msg = "grok client must not be built for a non-grok model"
        raise AssertionError(msg)

    monkeypatch.setattr(grok, "get_subscription_client", _boom)

    # A metered xai/* key model must fall through to the normal provider path,
    # not the subscription route.
    model = StrixProvider().get_model("xai/grok-4")
    assert isinstance(model, _TurnGuardModel)
    assert not isinstance(model._inner, OpenAIChatCompletionsModel)


def test_provider_label_names_the_subscription() -> None:
    assert subscription.provider_label("grok/grok-4") == "Grok"
    assert subscription.provider_label("chatgpt/gpt-5.4") == "ChatGPT"
    # Metered API-key models are not subscriptions.
    assert subscription.provider_label("xai/grok-4") is None
    assert subscription.provider_label("openai/gpt-5.4") is None


def test_litellm_model_name_maps_subscription_prefixes() -> None:
    # Model metadata (context window, output cap) is keyed "xai/…" for Grok and
    # bare for ChatGPT; the routing prefixes themselves are never LiteLLM keys.
    assert subscription.litellm_model_name("grok/grok-4") == "xai/grok-4"
    assert subscription.litellm_model_name("chatgpt/gpt-5.4") == "gpt-5.4"
    # Non-subscription models pass through untouched.
    assert subscription.litellm_model_name("xai/grok-4") == "xai/grok-4"
    assert subscription.litellm_model_name("openai/gpt-5.4") == "openai/gpt-5.4"
    assert subscription.litellm_model_name(None) is None


def test_run_record_reports_grok_provider(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    settings = mock.MagicMock()
    settings.llm.model = "grok/grok-4"
    monkeypatch.setattr(state_mod, "load_settings", lambda: settings)

    record = state_mod.ReportState(run_name="run-test").run_record
    assert record["auth_mode"] == "subscription"
    assert record["subscription_provider"] == "Grok"


def test_subscription_label_prefers_persisted_provider(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    settings = mock.MagicMock()
    settings.llm.model = "chatgpt/gpt-5.4"  # current settings point at ChatGPT
    monkeypatch.setattr(utils, "load_settings", lambda: settings)

    # A resumed Grok run keeps its persisted provider even though settings changed.
    resumed = mock.MagicMock(
        run_record={"auth_mode": "subscription", "subscription_provider": "Grok"}
    )
    assert utils.subscription_label(resumed) == "Grok subscription"

    # With no persisted provider, it derives the label from settings (not a
    # hardcoded default).
    fresh = mock.MagicMock(run_record={})
    assert utils.subscription_label(fresh) == "ChatGPT subscription"


def test_persisted_run_record_carries_provider(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    settings = mock.MagicMock()
    settings.llm.model = "grok/grok-4"
    monkeypatch.setattr(scan_setup, "load_settings", lambda: settings)
    monkeypatch.setattr(scan_setup, "run_dir_for", lambda _name: tmp_path)
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        "strix.report.writer.write_run_record", lambda _dir, rec: captured.update(rec)
    )

    args = argparse.Namespace(
        run_name="run-test",
        targets_info=[],
        scan_mode="scan",
        instruction=None,
        non_interactive=True,
        local_sources=[],
        diff_scope={"active": False},
        scope_mode="mode",
        diff_base=None,
    )
    scan_setup._persist_run_record(args)

    # The resume/viewer record must carry the provider so resumed runs stay labeled.
    assert captured["auth_mode"] == "subscription"
    assert captured["subscription_provider"] == "Grok"
