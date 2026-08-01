from __future__ import annotations

import json
from functools import cache
from typing import Any, ClassVar

from pygments.lexers import get_lexer_by_name, get_lexer_for_filename
from pygments.styles import get_style_by_name
from pygments.util import ClassNotFound
from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


_ADD_FILE = "*** Add File: "
_DELETE_FILE = "*** Delete File: "
_UPDATE_FILE = "*** Update File: "
_BEGIN_PATCH = "*** Begin Patch"
_END_PATCH = "*** End Patch"

_VIEW_IMAGE_ERROR_PREFIXES = (
    "image path ",
    "unable to read image",
    "manifest path",
    "exceeded the allowed size",
)


@cache
def _get_style_colors() -> dict[Any, str]:
    style = get_style_by_name("native")
    return {token: f"#{style_def['color']}" for token, style_def in style if style_def["color"]}


def _get_lexer_for_file(path: str) -> Any:
    try:
        return get_lexer_for_filename(path)
    except ClassNotFound:
        return get_lexer_by_name("text")


def _get_token_color(token_type: Any) -> str | None:
    colors = _get_style_colors()
    while token_type:
        if token_type in colors:
            return colors[token_type]
        token_type = token_type.parent
    return None


def _highlight_code(code: str, path: str) -> Text:
    lexer = _get_lexer_for_file(path)
    text = Text()
    for token_type, token_value in lexer.get_tokens(code):
        if not token_value:
            continue
        color = _get_token_color(token_type)
        text.append(token_value, style=color)
    return text


def _extract_patch_text(args: dict[str, Any]) -> str:
    """apply_patch input arrives as either {"patch": text} or raw text in
    the "input" field, depending on whether the tool is wrapped as a
    chat-completions FunctionTool or routed through as a CustomTool.
    """
    raw = args.get("patch")
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        inner = raw.get("patch")
        if isinstance(inner, str):
            return inner
    fallback = args.get("input") if isinstance(args, dict) else None
    if isinstance(fallback, str):
        return fallback
    return ""


def _parse_patch_operations(
    patch_text: str,
) -> list[tuple[str, str, list[str], list[str]]]:
    """Return [(kind, path, old_lines, new_lines), ...] for each file op."""
    ops: list[tuple[str, str, list[str], list[str]]] = []
    current_kind: str | None = None
    current_path: str | None = None
    old_lines: list[str] = []
    new_lines: list[str] = []

    def flush() -> None:
        nonlocal current_kind, current_path, old_lines, new_lines
        if current_kind and current_path is not None:
            ops.append((current_kind, current_path, old_lines, new_lines))
        current_kind = None
        current_path = None
        old_lines = []
        new_lines = []

    for line in patch_text.splitlines():
        if line in (_BEGIN_PATCH, _END_PATCH):
            continue
        if line.startswith(_ADD_FILE):
            flush()
            current_kind = "add"
            current_path = line[len(_ADD_FILE) :].strip()
        elif line.startswith(_UPDATE_FILE):
            flush()
            current_kind = "update"
            current_path = line[len(_UPDATE_FILE) :].strip()
        elif line.startswith(_DELETE_FILE):
            flush()
            current_kind = "delete"
            current_path = line[len(_DELETE_FILE) :].strip()
        elif current_kind == "update":
            if line.startswith("@@"):
                continue
            if line.startswith("-") and not line.startswith("---"):
                old_lines.append(line[1:])
            elif line.startswith("+") and not line.startswith("+++"):
                new_lines.append(line[1:])
        elif current_kind == "add":
            if line.startswith("+"):
                new_lines.append(line[1:])
            elif line.strip():
                new_lines.append(line)
    flush()
    return ops


_OP_LABEL = {
    "add": "create",
    "update": "edit",
    "delete": "delete",
}


def _render_operation(text: Text, kind: str, path: str, old: list[str], new: list[str]) -> None:
    label = _OP_LABEL.get(kind, "file")

    text.append("◇ ", style="#10b981")
    text.append(label, style="dim")

    if path:
        path_display = path[-60:] if len(path) > 60 else path
        text.append(" ")
        text.append(path_display, style="dim")

    if kind == "update":
        if old:
            highlighted_old = _highlight_code("\n".join(old), path)
            for line in highlighted_old.plain.split("\n"):
                text.append("\n")
                text.append("-", style="#ef4444")
                text.append(" ")
                text.append(line)
        if new:
            highlighted_new = _highlight_code("\n".join(new), path)
            for line in highlighted_new.plain.split("\n"):
                text.append("\n")
                text.append("+", style="#22c55e")
                text.append(" ")
                text.append(line)
    elif kind == "add" and new:
        text.append("\n")
        text.append_text(_highlight_code("\n".join(new), path))


@register_tool_renderer
class ApplyPatchRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "apply_patch"
    css_classes: ClassVar[list[str]] = ["tool-call", "file-edit-tool"]

    @classmethod
    def _build(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        result = tool_data.get("result")
        status = tool_data.get("status", "completed")

        patch_text = _extract_patch_text(args)
        ops = _parse_patch_operations(patch_text)

        text = Text()

        if not ops:
            text.append("◇ ", style="#10b981")
            text.append("patch", style="dim")
            if isinstance(result, str) and result.strip():
                text.append("\n  ")
                text.append(result.strip(), style="dim")
            elif not result:
                text.append(" ")
                text.append("Processing...", style="dim")
            return Static(text, classes=cls.get_css_classes(status))

        for i, (kind, path, old, new) in enumerate(ops):
            if i > 0:
                text.append("\n")
            _render_operation(text, kind, path, old, new)

        if status == "failed" and isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="#ef4444")

        return Static(text, classes=cls.get_css_classes(status))


def _is_image_success(result: Any) -> bool:
    if isinstance(result, dict) and result.get("type") == "image":
        return True
    if isinstance(result, str):
        stripped = result.lstrip()
        if stripped.startswith("data:image/"):
            return True
        try:
            obj = json.loads(stripped)
        except (TypeError, ValueError):
            return False
        return isinstance(obj, dict) and obj.get("type") == "image"
    return False


def _image_error_text(result: Any) -> str | None:
    if not isinstance(result, str):
        return None
    stripped = result.strip()
    if not stripped:
        return None
    lower = stripped.lower()
    if lower.startswith(_VIEW_IMAGE_ERROR_PREFIXES) or "not a supported image" in lower:
        return stripped
    return None


@register_tool_renderer
class ViewImageRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "view_image"
    css_classes: ClassVar[list[str]] = ["tool-call", "file-edit-tool"]

    @classmethod
    def _build(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        result = tool_data.get("result")
        status = tool_data.get("status", "completed")

        path = str(args.get("path", "")).strip()

        text = Text()
        text.append("◇ ", style="#10b981")
        text.append("view image", style="dim")

        if path:
            path_display = path[-60:] if len(path) > 60 else path
            text.append(" ")
            text.append(path_display, style="dim")

        err = _image_error_text(result)
        if err is not None:
            text.append("\n  ")
            text.append(err, style="#ef4444")
        elif _is_image_success(result):
            text.append("  ")
            text.append("✓", style="#22c55e")

        return Static(text, classes=cls.get_css_classes(status))
