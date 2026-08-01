from abc import ABC, abstractmethod
from typing import Any, ClassVar

from textual.widgets import Static


_TERMINAL_STATUSES = ("completed", "failed", "error")
_CACHE_SIZE_LIMIT = 200


class BaseToolRenderer(ABC):
    tool_name: ClassVar[str] = ""
    css_classes: ClassVar[list[str]] = ["tool-call"]
    _cache: ClassVar[dict[tuple[str, str, str], Static]] = {}

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        status = tool_data.get("status", "")
        call_id = tool_data.get("call_id")
        if status not in _TERMINAL_STATUSES or not call_id:
            return cls._build(tool_data)

        key = (cls.tool_name, str(call_id), status)
        cached = cls._cache.get(key)
        if cached is not None:
            return cached

        widget = cls._build(tool_data)
        if len(cls._cache) > _CACHE_SIZE_LIMIT:
            cls._cache.clear()
        cls._cache[key] = widget
        return widget

    @classmethod
    @abstractmethod
    def _build(cls, tool_data: dict[str, Any]) -> Static:
        pass

    @classmethod
    def status_icon(cls, status: str) -> tuple[str, str]:
        icons = {
            "running": ("● In progress...", "#f59e0b"),
            "completed": ("✓ Done", "#22c55e"),
            "failed": ("✗ Failed", "#dc2626"),
            "error": ("✗ Error", "#dc2626"),
        }
        return icons.get(status, ("○ Unknown", "dim"))

    @classmethod
    def get_css_classes(cls, status: str) -> str:
        base_classes = cls.css_classes.copy()
        base_classes.append(f"status-{status}")
        return " ".join(base_classes)
