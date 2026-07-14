"""Tests for SDK session helpers in strix/core/sessions.py."""

from __future__ import annotations

from typing import Any

import pytest

from strix.core.sessions import strip_all_images_from_session


class _FakeSession:
    """Minimal Session stub whose add_items can be scripted to fail then succeed."""

    def __init__(self, items: list[Any], add_items_errors: list[Exception | None]) -> None:
        self._items = items
        self._add_items_errors = add_items_errors
        self.add_items_calls = 0
        self.cleared = False
        self.added_items: list[Any] | None = None

    async def get_items(self) -> list[Any]:
        return self._items

    async def clear_session(self) -> None:
        self.cleared = True

    async def add_items(self, items: list[Any]) -> None:
        index = self.add_items_calls
        self.add_items_calls += 1
        error = self._add_items_errors[index] if index < len(self._add_items_errors) else None
        if error is not None:
            raise error
        self.added_items = items


def _image_item() -> dict[str, Any]:
    return {
        "type": "function_call_output",
        "call_id": "call-1",
        "output": [{"type": "input_image", "image_url": "data:image/png;base64,abc"}],
    }


async def test_retry_success_returns_true() -> None:
    session = _FakeSession(
        items=[_image_item()],
        add_items_errors=[RuntimeError("first attempt failed"), None],
    )

    result = await strip_all_images_from_session(session)  # type: ignore[arg-type]

    assert result is True
    assert session.add_items_calls == 2
    assert session.added_items is not None


async def test_retry_double_failure_propagates_second_error() -> None:
    second_error = ValueError("second attempt failed")
    session = _FakeSession(
        items=[_image_item()],
        add_items_errors=[RuntimeError("first attempt failed"), second_error],
    )

    with pytest.raises(ValueError, match="second attempt failed"):
        await strip_all_images_from_session(session)  # type: ignore[arg-type]

    assert session.add_items_calls == 2
