"""Tests for strix.interface.scaffold_presets."""

from __future__ import annotations

from strix.interface.scaffold_presets import SCAFFOLD_PRESETS, validate_scaffold_variants


def test_all_presets_have_non_empty_framing_text() -> None:
    assert SCAFFOLD_PRESETS
    for name, text in SCAFFOLD_PRESETS.items():
        assert name.strip() == name
        assert len(text.strip()) > 50


def test_validate_scaffold_variants_accepts_known_names() -> None:
    assert validate_scaffold_variants(["injection", "client-side"]) is None


def test_validate_scaffold_variants_rejects_unknown_name() -> None:
    error = validate_scaffold_variants(["injection", "not-a-preset"])
    assert error is not None
    assert "not-a-preset" in error
    assert "injection" not in error.split("Known presets:")[0]


def test_validate_scaffold_variants_empty_list_is_valid() -> None:
    assert validate_scaffold_variants([]) is None
