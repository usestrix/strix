"""Pytest configuration and shared fixtures for Strix tests."""

from collections.abc import Callable
from typing import Any

import pytest


@pytest.fixture
def sample_function_with_types() -> Callable[..., None]:
    """Create a sample function with type annotations for testing argument conversion."""

    def func(
        name: str,
        count: int,
        enabled: bool,
        ratio: float,
        items: list[Any],
        config: dict[str, Any],
        optional: str | None = None,
    ) -> None:
        pass

    return func


@pytest.fixture
def sample_function_no_annotations() -> Callable[..., None]:
    """Create a sample function without type annotations."""

    def func(arg1: Any, arg2: Any, arg3: Any) -> None:
        pass

    return func
