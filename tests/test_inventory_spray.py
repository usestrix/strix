"""Tier-1 + PBT tests for Phase 5 class-spray library."""

from __future__ import annotations

import unittest

from hypothesis import given
from hypothesis import strategies as st

from strix.core.inventory.models import Param, ParamClassEvidence
from strix.core.inventory.spray import (
    all_classes,
    spray_values_for,
    spray_values_for_param,
)


class TestSprayLibrary(unittest.TestCase):
    """Fixed deterministic value sets per class."""

    def test_all_classes_have_non_empty_sets(self) -> None:
        for class_name in all_classes():
            values = spray_values_for(class_name)
            self.assertGreater(len(values), 0, f"{class_name} must have spray values")

    def test_spray_values_are_deterministic(self) -> None:
        first = spray_values_for("object-id")
        second = spray_values_for("object-id")
        self.assertEqual(first, second)

    def test_spray_for_unknown_fallback(self) -> None:
        values = spray_values_for("unknown")
        self.assertIn("test", values)

    def test_spray_for_param_uses_class_evidence(self) -> None:
        param = Param(name="file", location="body")
        param.class_evidence = ParamClassEvidence(class_name="file")
        values = spray_values_for_param(param)
        self.assertIn("exploit.php", values)

    def test_spray_for_param_without_evidence_is_unknown(self) -> None:
        param = Param(name="foo", location="query")
        values = spray_values_for_param(param)
        self.assertIn("test", values)


class TestSprayPBT(unittest.TestCase):
    """Class spray determinism invariant."""

    @given(st.sampled_from(all_classes()))
    def test_class_spray_is_deterministic(self, class_name: str) -> None:
        first = spray_values_for(class_name)  # type: ignore[arg-type]
        second = spray_values_for(class_name)  # type: ignore[arg-type]
        self.assertEqual(first, second)
