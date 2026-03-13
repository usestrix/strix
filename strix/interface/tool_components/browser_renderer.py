from functools import cache
from typing import Any, ClassVar

from pygments.lexers import get_lexer_by_name
from pygments.styles import get_style_by_name
from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@cache
def _get_style_colors() -> dict[Any, str]:
    style = get_style_by_name("native")
    return {token: f"#{style_def['color']}" for token, style_def in style if style_def["color"]}


@register_tool_renderer
class BrowserRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "browser_actions"
    css_classes: ClassVar[list[str]] = ["tool-call", "browser-tool"]

    # -- palette (used only for highlights) ----------------------------
    NAV: ClassVar[str] = "#06b6d4"  # cyan  — links / URLs
    INTERACT: ClassVar[str] = "#3b82f6"  # blue  — targets / values
    OBSERVE: ClassVar[str] = "#a78bfa"  # purple — data fields
    EXEC: ClassVar[str] = "#f59e0b"  # amber — task text
    LIFE: ClassVar[str] = "#10b981"  # teal  — lifecycle values
    OK: ClassVar[str] = "#22c55e"  # green — success
    ERR: ClassVar[str] = "#ef4444"  # red   — error
    DIM: ClassVar[str] = "dim"  # gray  — prose / labels

    # -----------------------------------------------------------------
    # helpers
    # -----------------------------------------------------------------

    @classmethod
    def _get_token_color(cls, token_type: Any) -> str | None:
        colors = _get_style_colors()
        while token_type:
            if token_type in colors:
                return colors[token_type]
            token_type = token_type.parent
        return None

    @classmethod
    def _highlight_js(cls, code: str) -> Text:
        lexer = get_lexer_by_name("javascript")
        text = Text()
        for token_type, token_value in lexer.get_tokens(code):
            if not token_value:
                continue
            color = cls._get_token_color(token_type)
            text.append(token_value, style=color)
        return text

    @classmethod
    def _status_mark(cls, status: str) -> Text:
        text = Text()
        if status == "completed":
            text.append(" ✓", style=f"dim {cls.OK}")
        elif status in ("failed", "error"):
            text.append(" ✗", style=f"dim {cls.ERR}")
        return text

    @classmethod
    def _append_fields(cls, text: Text, res: dict[str, Any]) -> None:
        """Append a dim summary of returned history fields."""
        fields = res.get("fields")
        if not fields or not isinstance(fields, dict):
            return
        names = sorted(fields)
        text.append("\n  ")
        text.append("fields ", style=cls.OBSERVE)
        text.append(" ".join(names), style=cls.DIM)

    # -----------------------------------------------------------------
    # public
    # -----------------------------------------------------------------

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")
        result = tool_data.get("result")

        action = args.get("action", "")
        content = cls._build_content(action, args, status, result)

        css_classes = cls.get_css_classes(status)
        return Static(content, classes=css_classes)

    # -----------------------------------------------------------------
    # content builder
    # -----------------------------------------------------------------

    @classmethod
    def _build_content(
        cls,
        action: str,
        args: dict[str, Any],
        status: str,
        result: Any,
    ) -> Text:
        if action == "run":
            return cls._build_run(args, status, result)

        # --- simple one-liners ----------------------------------------
        simple = {
            "go_back": "going back",
            "close_browser": "closing browser",
            "close_tab": "closing tab",
            "screenshot": "taking screenshot",
            "save_as_pdf": "saving page as pdf",
            "extract": "extracting content",
            "read_long_content": "reading long content",
        }
        if action in simple:
            text = Text("@ ", style=cls.DIM)
            text.append(simple[action], style=cls.DIM)
            text.append_text(cls._status_mark(status))
            return text

        # --- launch ----------------------------------------------------
        if action == "launch":
            mode = "local" if args.get("use_local") else "sandboxed"
            text = Text("◈ ", style=cls.LIFE)
            text.append("launching browser", style=f"bold {cls.LIFE}")
            text.append(f" {mode}", style=cls.DIM)
            res = result if isinstance(result, dict) else {}
            warning = res.get("warning")
            if warning:
                text.append(f"\n  ⚠ {warning}", style=f"italic {cls.DIM}")
            return text

        # --- navigate / search ----------------------------------------
        if action == "navigate":
            text = Text("@ ", style=cls.DIM)
            text.append("navigating to ", style=cls.DIM)
            url = args.get("url", "")
            if len(url) > 80:
                url = url[:77] + "..."
            text.append(url, style=f"{cls.NAV} underline")
            if args.get("new_tab"):
                text.append(" in new tab", style=cls.DIM)
            text.append_text(cls._status_mark(status))
            return text

        if action == "search":
            text = Text("@ ", style=cls.DIM)
            text.append("searching for ", style=cls.DIM)
            query = args.get("query", "")
            if query:
                preview = query if len(query) <= 80 else query[:77] + "..."
                text.append(f'"{preview}"', style=cls.INTERACT)
            engine = args.get("engine")
            if engine:
                text.append(f" via {engine}", style=cls.DIM)
            text.append_text(cls._status_mark(status))
            return text

        # --- pointer actions -------------------------------------------
        if action == "click":
            text = Text("@ ", style=cls.DIM)
            text.append("clicking", style=cls.DIM)
            index = args.get("index")
            if index is not None:
                text.append(f" #{index}", style=f"bold {cls.INTERACT}")
            text.append_text(cls._status_mark(status))
            return text

        # --- text / file input ----------------------------------------
        if action == "input":
            text = Text("@ ", style=cls.DIM)
            text.append("inputting", style=cls.DIM)
            index = args.get("index")
            if index is not None:
                text.append(f" #{index}", style=f"bold {cls.INTERACT}")
            value = args.get("text")
            if value:
                preview = value if len(value) <= 60 else value[:57] + "..."
                text.append(f' "{preview}"', style=cls.INTERACT)
            if args.get("clear"):
                text.append(" (clear)", style=cls.DIM)
            text.append_text(cls._status_mark(status))
            return text

        if action == "upload_file":
            text = Text("@ ", style=cls.DIM)
            text.append("uploading file", style=cls.DIM)
            index = args.get("index")
            if index is not None:
                text.append(f" #{index}", style=f"bold {cls.INTERACT}")
            path = args.get("path", "")
            if path:
                text.append(" ", style=cls.DIM)
                text.append(path, style=cls.NAV)
            text.append_text(cls._status_mark(status))
            return text

        # --- scroll / find --------------------------------------------
        if action == "scroll":
            direction = "down" if args.get("down", True) else "up"
            text = Text("@ ", style=cls.DIM)
            text.append("scrolling ", style=cls.DIM)
            text.append(direction, style=cls.INTERACT)
            pages = args.get("pages")
            if pages is not None:
                text.append(f" {pages} page(s)", style=cls.DIM)
            index = args.get("index")
            if index is not None:
                text.append(" on ", style=cls.DIM)
                text.append(f"#{index}", style=f"bold {cls.INTERACT}")
            text.append_text(cls._status_mark(status))
            return text

        if action == "find_text":
            text = Text("@ ", style=cls.DIM)
            text.append("finding text ", style=cls.DIM)
            value = args.get("text", "")
            if value:
                preview = value if len(value) <= 80 else value[:77] + "..."
                text.append(f'"{preview}"', style=cls.OBSERVE)
            text.append_text(cls._status_mark(status))
            return text

        # --- keyboard --------------------------------------------------
        if action == "send_keys":
            text = Text("@ ", style=cls.DIM)
            text.append("pressing ", style=cls.DIM)
            text.append(args.get("keys", ""), style=f"bold {cls.INTERACT}")
            text.append_text(cls._status_mark(status))
            return text

        # --- search/extract helpers -----------------------------------
        if action == "search_page":
            text = Text("@ ", style=cls.DIM)
            text.append("searching page for ", style=cls.DIM)
            pattern = args.get("pattern", "")
            if pattern:
                preview = pattern if len(pattern) <= 80 else pattern[:77] + "..."
                text.append(f'"{preview}"', style=cls.OBSERVE)
            text.append_text(cls._status_mark(status))
            return text

        if action == "find_elements":
            text = Text("@ ", style=cls.DIM)
            text.append("finding elements ", style=cls.DIM)
            selector = args.get("selector", "")
            if selector:
                text.append(selector, style=cls.OBSERVE)
            text.append_text(cls._status_mark(status))
            return text

        # --- dropdowns -------------------------------------------------
        if action == "dropdown_options":
            text = Text("@ ", style=cls.DIM)
            text.append("reading dropdown options", style=cls.DIM)
            index = args.get("index")
            if index is not None:
                text.append(f" #{index}", style=f"bold {cls.INTERACT}")
            text.append_text(cls._status_mark(status))
            return text

        if action == "select_dropdown":
            text = Text("@ ", style=cls.DIM)
            text.append("selecting dropdown value", style=cls.DIM)
            index = args.get("index")
            if index is not None:
                text.append(f" #{index}", style=f"bold {cls.INTERACT}")
            value = args.get("text", "")
            if value:
                text.append(f' "{value}"', style=f"bold {cls.INTERACT}")
            text.append_text(cls._status_mark(status))
            return text

        # --- eval js ---------------------------------------------------
        if action == "evaluate":
            js = args.get("code")

            text = Text("@ ", style=cls.DIM)
            text.append("executing javascript", style=cls.DIM)
            text.append_text(cls._status_mark(status))
            if js:
                text.append("\n")
                text.append_text(cls._highlight_js(js))

            return text

        # --- wait ------------------------------------------------------
        if action == "wait":
            text = Text("@ ", style=cls.DIM)
            seconds = args.get("seconds")
            if status == "completed":
                text.append("waited", style=cls.DIM)
            else:
                text.append("waiting", style=cls.DIM)
            if seconds is not None:
                text.append(f" {seconds}s", style=cls.INTERACT)
            text.append_text(cls._status_mark(status))
            return text

        # --- tab switch ------------------------------------------------
        if action == "switch":
            text = Text("@ ", style=cls.DIM)
            text.append("switching to tab ", style=cls.DIM)
            text.append(str(args.get("tab_id", "?")), style=f"bold {cls.NAV}")
            text.append_text(cls._status_mark(status))
            return text

        # --- file operations ------------------------------------------
        if action in {"write_file", "read_file", "replace_file"}:
            labels = {
                "write_file": "writing file",
                "read_file": "reading file",
                "replace_file": "replacing file content",
            }
            text = Text("@ ", style=cls.DIM)
            text.append(labels[action], style=cls.DIM)
            file_name = args.get("file_name", "")
            if file_name:
                text.append(" ", style=cls.DIM)
                text.append(file_name, style=cls.NAV)
            text.append_text(cls._status_mark(status))
            return text

        # --- completion ------------------------------------------------
        if action == "done":
            text = Text("@ ", style=cls.DIM)
            success = args.get("success")
            if success is True:
                text.append("marking task done", style=f"bold {cls.OK}")
            elif success is False:
                text.append("marking task failed", style=f"bold {cls.ERR}")
            else:
                text.append("marking task done", style=cls.DIM)

            summary = args.get("text", "")
            if summary:
                preview = summary if len(summary) <= 120 else summary[:117] + "..."
                text.append("\n  ")
                text.append(preview, style=cls.DIM)

            text.append_text(cls._status_mark(status))
            return text

        # --- fallback --------------------------------------------------
        text = Text("@ ", style=cls.DIM)
        if action:
            text.append(action, style=cls.DIM)
        text.append_text(cls._status_mark(status))
        return text

    # -----------------------------------------------------------------
    # run task
    # -----------------------------------------------------------------

    @classmethod
    def _build_run(
        cls,
        args: dict[str, Any],
        status: str,
        result: Any,
    ) -> Text:
        task = args.get("task", "")

        if status == "running":
            text = Text("@ ", style=cls.DIM)
            text.append("running task", style=f"bold {cls.EXEC}")
            if task:
                text.append("\n  ")
                text.append(task, style=cls.EXEC)
            rf = args.get("return_fields")
            if rf and isinstance(rf, list):
                text.append("\n  ")
                text.append("returning ", style=cls.OBSERVE)
                text.append(" ".join(rf), style=cls.DIM)
            return text

        # Completed or failed — show result
        if status in ("completed", "failed", "error"):
            res = result if isinstance(result, dict) else {}
            has_error = "error" in res

            if has_error:
                text = Text("@ ", style=cls.DIM)
                text.append("task failed", style=f"bold {cls.ERR}")
                if task:
                    text.append("\n  ")
                    text.append(task, style="dim strike")
                text.append("\n  ")
                error_msg = str(res["error"])
                if len(error_msg) > 200:
                    error_msg = error_msg[:197] + "..."
                text.append(error_msg, style=cls.ERR)
            else:
                text = Text("@ ", style=cls.DIM)
                text.append("browser task completed", style=f"bold {cls.OK}")
                if task:
                    text.append("\n  ")
                    text.append(task, style=cls.DIM)
                output = res.get("result", "")
                if output:
                    text.append("\n  ")
                    output_str = str(output)
                    if len(output_str) > 300:
                        output_str = output_str[:297] + "..."
                    text.append(output_str, style=cls.DIM)
                cls._append_fields(text, res)
            return text

        # Unknown status
        text = Text("@ ", style=cls.DIM)
        text.append("running browser task", style=cls.DIM)
        if task:
            text.append("\n  ")
            text.append(task, style=cls.DIM)
        return text
