"""Pytest configuration and shared fixtures for Strix tests."""

import pytest


@pytest.fixture
def sample_function_with_types():
    """Create a sample function with type annotations for testing argument conversion."""

    def func(
        name: str,
        count: int,
        enabled: bool,
        ratio: float,
        items: list,
        config: dict,
        optional: str | None = None,
    ) -> None:
        pass

    return func


@pytest.fixture
def sample_function_no_annotations():
    """Create a sample function without type annotations."""

    def func(arg1, arg2, arg3):
        pass

    return func
