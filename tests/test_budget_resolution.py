from __future__ import annotations

from argparse import Namespace
from importlib import import_module

import pytest

from strix.interface.main import DEFAULT_WARN_THRESHOLD, resolve_budget_config


def _make_args(**overrides: object) -> Namespace:
    base = {
        "max_tokens": None,
        "max_cost": None,
        "warn_threshold": None,
    }
    base.update(overrides)
    return Namespace(**base)


def _patch_defaults(monkeypatch: pytest.MonkeyPatch, replacement: object) -> None:
    module = import_module("strix.interface.main")
    monkeypatch.setattr(module, "get_budget_defaults", replacement)


def test_resolve_budget_cli_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    args = _make_args(max_tokens=200_000)

    monkeypatch.setenv("STRIX_MAX_TOKENS", "999999")
    monkeypatch.setenv("STRIX_MAX_COST", "12.5")
    monkeypatch.delenv("STRIX_WARN_THRESHOLD", raising=False)
    monkeypatch.delenv("STRIX_FALLBACK_COST_PER_1K", raising=False)

    _patch_defaults(
        monkeypatch,
        lambda: {"max_tokens": 50_000, "max_cost": 4.0, "warn_threshold": 70},
    )

    config, sources = resolve_budget_config(args)

    assert config.max_tokens == 200_000
    assert config.max_cost == pytest.approx(12.5)
    assert config.warn_threshold == 70
    assert config.fallback_cost_per_1k_tokens == pytest.approx(0.08)

    assert sources["max_tokens"] == "cli"
    assert sources["max_cost"] == "env"
    assert sources["warn_threshold"] == "saved"
    assert sources["fallback_cost_per_1k_tokens"] == "default"


def test_resolve_budget_saved_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    args = _make_args()

    monkeypatch.delenv("STRIX_MAX_TOKENS", raising=False)
    monkeypatch.delenv("STRIX_MAX_COST", raising=False)
    monkeypatch.delenv("STRIX_WARN_THRESHOLD", raising=False)
    monkeypatch.delenv("STRIX_FALLBACK_COST_PER_1K", raising=False)

    _patch_defaults(
        monkeypatch,
        lambda: {
            "max_tokens": "150000",
            "max_cost": "9.5",
            "warn_threshold": 60,
            "fallback_cost_per_1k_tokens": 0.05,
        },
    )

    config, sources = resolve_budget_config(args)

    assert config.max_tokens == 150_000
    assert config.max_cost == pytest.approx(9.5)
    assert config.warn_threshold == 60
    assert config.fallback_cost_per_1k_tokens == pytest.approx(0.05)

    assert all(value == "saved" for value in sources.values())


def test_resolve_budget_invalid_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    args = _make_args(warn_threshold=150)
    _patch_defaults(monkeypatch, dict)

    with pytest.raises(ValueError, match="between 0 and 100"):
        resolve_budget_config(args)


def test_resolve_budget_defaults_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    args = _make_args()

    monkeypatch.delenv("STRIX_MAX_TOKENS", raising=False)
    monkeypatch.delenv("STRIX_MAX_COST", raising=False)
    monkeypatch.delenv("STRIX_WARN_THRESHOLD", raising=False)
    monkeypatch.delenv("STRIX_FALLBACK_COST_PER_1K", raising=False)
    _patch_defaults(monkeypatch, dict)

    config, sources = resolve_budget_config(args)

    assert config.max_tokens is None
    assert config.max_cost is None
    assert config.warn_threshold == DEFAULT_WARN_THRESHOLD
    assert config.fallback_cost_per_1k_tokens == pytest.approx(0.08)

    assert sources["warn_threshold"] == "default"
    assert sources["fallback_cost_per_1k_tokens"] == "default"
