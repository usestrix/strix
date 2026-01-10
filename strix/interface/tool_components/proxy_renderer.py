from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class ListRequestsRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "list_requests"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        result = tool_data.get("result")

        httpql_filter = args.get("httpql_filter")

        text = Text()
        text.append("📋 ")
        text.append("Listing requests", style="bold #06b6d4")

        if isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="dim")
        elif result and isinstance(result, dict) and "requests" in result:
            requests = result["requests"]
            if isinstance(requests, list) and requests:
                for req in requests[:25]:
                    if isinstance(req, dict):
                        method = req.get("method", "?")
                        path = req.get("path", "?")
                        response = req.get("response") or {}
                        status = response.get("statusCode", "?")
                        text.append("\n  ")
                        text.append(f"{method} {path} → {status}", style="dim")
                if len(requests) > 25:
                    text.append("\n  ")
                    text.append(f"... +{len(requests) - 25} more", style="dim")
            else:
                text.append("\n  ")
                text.append("No requests found", style="dim")
        elif httpql_filter:
            filter_display = (
                httpql_filter[:500] + "..." if len(httpql_filter) > 500 else httpql_filter
            )
            text.append("\n  ")
            text.append(filter_display, style="dim")
        else:
            text.append("\n  ")
            text.append("All requests", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class ViewRequestRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "view_request"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        result = tool_data.get("result")

        part = args.get("part", "request")

        text = Text()
        text.append("👀 ")
        text.append(f"Viewing {part}", style="bold #06b6d4")

        if isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="dim")
        elif result and isinstance(result, dict):
            if "content" in result:
                content = result["content"]
                content_preview = content[:2000] + "..." if len(content) > 2000 else content
                text.append("\n  ")
                text.append(content_preview, style="dim")
            elif "matches" in result:
                matches = result["matches"]
                if isinstance(matches, list) and matches:
                    for match in matches[:25]:
                        if isinstance(match, dict) and "match" in match:
                            text.append("\n  ")
                            text.append(match["match"], style="dim")
                    if len(matches) > 25:
                        text.append("\n  ")
                        text.append(f"... +{len(matches) - 25} more matches", style="dim")
                else:
                    text.append("\n  ")
                    text.append("No matches found", style="dim")
            else:
                text.append("\n  ")
                text.append("Viewing content...", style="dim")
        else:
            text.append("\n  ")
            text.append("Loading...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class SendRequestRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "send_request"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        result = tool_data.get("result")

        method = args.get("method", "GET")
        url = args.get("url", "")

        text = Text()
        text.append("📤 ")
        text.append(f"Sending {method}", style="bold #06b6d4")

        if isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="dim")
        elif result and isinstance(result, dict):
            status_code = result.get("status_code")
            response_body = result.get("body", "")

            if status_code:
                text.append("\n  ")
                text.append(f"Status: {status_code}", style="dim")
                if response_body:
                    body_preview = (
                        response_body[:2000] + "..." if len(response_body) > 2000 else response_body
                    )
                    text.append("\n  ")
                    text.append(body_preview, style="dim")
            else:
                text.append("\n  ")
                text.append("Response received", style="dim")
        elif url:
            url_display = url[:500] + "..." if len(url) > 500 else url
            text.append("\n  ")
            text.append(url_display, style="dim")
        else:
            text.append("\n  ")
            text.append("Sending...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class RepeatRequestRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "repeat_request"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        result = tool_data.get("result")

        modifications = args.get("modifications", {})

        text = Text()
        text.append("🔄 ")
        text.append("Repeating request", style="bold #06b6d4")

        if isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="dim")
        elif result and isinstance(result, dict):
            status_code = result.get("status_code")
            response_body = result.get("body", "")

            if status_code:
                text.append("\n  ")
                text.append(f"Status: {status_code}", style="dim")
                if response_body:
                    body_preview = (
                        response_body[:2000] + "..." if len(response_body) > 2000 else response_body
                    )
                    text.append("\n  ")
                    text.append(body_preview, style="dim")
            else:
                text.append("\n  ")
                text.append("Response received", style="dim")
        elif modifications:
            mod_str = str(modifications)
            mod_display = mod_str[:500] + "..." if len(mod_str) > 500 else mod_str
            text.append("\n  ")
            text.append(mod_display, style="dim")
        else:
            text.append("\n  ")
            text.append("No modifications", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class ScopeRulesRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "scope_rules"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: ARG003
        text = Text()
        text.append("⚙️ ")
        text.append("Updating proxy scope", style="bold #06b6d4")
        text.append("\n  ")
        text.append("Configuring...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class ListSitemapRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "list_sitemap"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("🗺️ ")
        text.append("Listing sitemap", style="bold #06b6d4")

        if isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="dim")
        elif result and isinstance(result, dict) and "entries" in result:
            entries = result["entries"]
            if isinstance(entries, list) and entries:
                for entry in entries[:30]:
                    if isinstance(entry, dict):
                        label = entry.get("label", "?")
                        kind = entry.get("kind", "?")
                        text.append("\n  ")
                        text.append(f"{kind}: {label}", style="dim")
                if len(entries) > 30:
                    text.append("\n  ")
                    text.append(f"... +{len(entries) - 30} more entries", style="dim")
            else:
                text.append("\n  ")
                text.append("No entries found", style="dim")
        else:
            text.append("\n  ")
            text.append("Loading...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class ViewSitemapEntryRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "view_sitemap_entry"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("📍 ")
        text.append("Viewing sitemap entry", style="bold #06b6d4")

        if isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="dim")
        elif result and isinstance(result, dict) and "entry" in result:
            entry = result["entry"]
            if isinstance(entry, dict):
                label = entry.get("label", "")
                kind = entry.get("kind", "")
                if label and kind:
                    text.append("\n  ")
                    text.append(f"{kind}: {label}", style="dim")
                else:
                    text.append("\n  ")
                    text.append("Entry details loaded", style="dim")
            else:
                text.append("\n  ")
                text.append("Entry details loaded", style="dim")
        else:
            text.append("\n  ")
            text.append("Loading...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)
