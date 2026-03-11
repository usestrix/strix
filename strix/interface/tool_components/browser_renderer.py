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
    def _head(cls) -> Text:
        text = Text()
        text.append("@ ", style=cls.DIM)
        return text

    @classmethod
    def _icon(cls, color: str) -> Text:
        text = Text()
        text.append("◈ ", style=color)
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
            "back": "going back",
            "close": "closing browser",
            "close_tab": "closing tab",
            "screenshot": "taking screenshot",
            "state": "reading page state",
            "extract": "extracting content",
        }
        if action in simple:
            text = cls._head()
            text.append(simple[action], style=cls.DIM)
            text.append_text(cls._status_mark(status))
            return text

        # --- launch ----------------------------------------------------
        if action == "launch":
            mode = "local" if args.get("use_local") else "sandboxed"
            text = cls._icon(cls.LIFE)
            text.append("launching browser", style=f"bold {cls.LIFE}")
            text.append(f" {mode}", style=cls.DIM)
            return text

        # --- navigate --------------------------------------------------
        if action == "open":
            text = cls._head()
            text.append("navigating to ", style=cls.DIM)
            url = args.get("url", "")
            if len(url) > 80:
                url = url[:77] + "..."
            text.append(url, style=f"{cls.NAV} underline")
            text.append_text(cls._status_mark(status))
            return text

        # --- pointer actions -------------------------------------------
        if action in ("click", "dblclick", "rightclick", "hover"):
            labels = {
                "click": "clicking",
                "dblclick": "double clicking",
                "rightclick": "right clicking",
                "hover": "hovering over",
            }
            text = cls._head()
            text.append(labels[action], style=cls.DIM)
            index = args.get("index")
            if index is not None:
                text.append(f" #{index}", style=f"bold {cls.INTERACT}")
            elif args.get("x") is not None and args.get("y") is not None:
                text.append(f" ({args['x']}, {args['y']})", style=cls.INTERACT)
            text.append_text(cls._status_mark(status))
            return text

        # --- text input ------------------------------------------------
        if action in ("type", "input"):
            label = "typing" if action == "type" else "inputting"
            text = cls._head()
            text.append(label, style=cls.DIM)
            t = args.get("text")
            if t:
                preview = t if len(t) <= 60 else t[:57] + "..."
                text.append(f' "{preview}"', style=cls.INTERACT)
            text.append_text(cls._status_mark(status))
            return text

        # --- scroll ----------------------------------------------------
        if action == "scroll":
            d = args.get("direction", "down")
            text = cls._head()
            text.append("scrolling ", style=cls.DIM)
            text.append(d, style=cls.INTERACT)
            text.append_text(cls._status_mark(status))
            return text

        # --- tab switch ------------------------------------------------
        if action == "switch":
            text = cls._head()
            text.append("switching to tab ", style=cls.DIM)
            text.append(str(args.get("tab", "?")), style=f"bold {cls.NAV}")
            text.append_text(cls._status_mark(status))
            return text

        # --- keyboard --------------------------------------------------
        if action == "keys":
            text = cls._head()
            text.append("pressing ", style=cls.DIM)
            text.append(args.get("keys", ""), style=f"bold {cls.INTERACT}")
            text.append_text(cls._status_mark(status))
            return text

        # --- select ----------------------------------------------------
        if action == "select":
            text = cls._head()
            text.append("selecting ", style=cls.DIM)
            text.append(args.get("value", ""), style=f"bold {cls.INTERACT}")
            text.append_text(cls._status_mark(status))
            return text

        # --- eval js ---------------------------------------------------
        if action == "eval":
            text = cls._head()
            text.append("executing javascript", style=cls.DIM)
            text.append_text(cls._status_mark(status))
            js = args.get("js")
            if js:
                text.append("\n")
                text.append_text(cls._highlight_js(js))
            return text

        # --- cookies ---------------------------------------------------
        if action == "cookies":
            sub = args.get("subcommand", "")
            text = cls._head()
            text.append("cookies ", style=cls.DIM)
            text.append(sub, style=cls.OBSERVE)
            text.append_text(cls._status_mark(status))
            return text

        # --- wait ------------------------------------------------------
        if action == "wait":
            sub = args.get("subcommand", "")
            target = args.get("selector") or args.get("text") or ""
            text = cls._head()
            if status == "completed":
                text.append(f"waited for {sub}", style=cls.DIM)
                text.append_text(cls._status_mark(status))
            else:
                text.append(f"waiting for {sub}", style=cls.DIM)
            if target:
                text.append(" ", style=cls.DIM)
                text.append(target, style=cls.OBSERVE)
            return text

        # --- get -------------------------------------------------------
        if action == "get":
            sub = args.get("subcommand", "")
            text = cls._head()
            text.append("getting ", style=cls.DIM)
            text.append(sub, style=cls.OBSERVE)
            text.append_text(cls._status_mark(status))
            return text

        # --- fallback --------------------------------------------------
        text = cls._head()
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
            text = cls._head()
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
                text = cls._head()
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
                text = cls._head()
                text.append("task completed", style=f"bold {cls.OK}")
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
        text = cls._head()
        text.append("running task", style=cls.DIM)
        if task:
            text.append("\n  ")
            text.append(task, style=cls.DIM)
        return text
