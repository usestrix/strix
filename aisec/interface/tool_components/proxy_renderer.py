from typing import Any, ClassVar

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

        header = "📋 [bold #06b6d4]Listing requests[/]"

        if result and isinstance(result, dict) and "requests" in result:
            requests = result["requests"]
            if isinstance(requests, list) and requests:
                request_lines = []
                for req in requests[:3]:
                    if isinstance(req, dict):
                        method = req.get("method", "?")
                        path = req.get("path", "?")
                        response = req.get("response") or {}
                        status = response.get("statusCode", "?")
                        line = f"{method} {path} → {status}"
                        request_lines.append(line)

                if len(requests) > 3:
                    request_lines.append(f"... +{len(requests) - 3} more")

                escaped_lines = [cls.escape_markup(line) for line in request_lines]
                content_text = f"{header}\n  [dim]{chr(10).join(escaped_lines)}[/]"
            else:
                content_text = f"{header}\n  [dim]No requests found[/]"
        elif httpql_filter:
            filter_display = (
                httpql_filter[:300] + "..." if len(httpql_filter) > 300 else httpql_filter
            )
            content_text = f"{header}\n  [dim]{cls.escape_markup(filter_display)}[/]"
        else:
            content_text = f"{header}\n  [dim]All requests[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class ViewRequestRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "view_request"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        result = tool_data.get("result")

        part = args.get("part", "request")

        header = f"👀 [bold #06b6d4]Viewing {cls.escape_markup(part)}[/]"

        if result and isinstance(result, dict):
            if "content" in result:
                content = result["content"]
                content_preview = content[:500] + "..." if len(content) > 500 else content
                content_text = f"{header}\n  [dim]{cls.escape_markup(content_preview)}[/]"
            elif "matches" in result:
                matches = result["matches"]
                if isinstance(matches, list) and matches:
                    match_lines = [
                        match["match"]
                        for match in matches[:3]
                        if isinstance(match, dict) and "match" in match
                    ]
                    if len(matches) > 3:
                        match_lines.append(f"... +{len(matches) - 3} more matches")
                    escaped_lines = [cls.escape_markup(line) for line in match_lines]
                    content_text = f"{header}\n  [dim]{chr(10).join(escaped_lines)}[/]"
                else:
                    content_text = f"{header}\n  [dim]No matches found[/]"
            else:
                content_text = f"{header}\n  [dim]Viewing content...[/]"
        else:
            content_text = f"{header}\n  [dim]Loading...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


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

        header = f"📤 [bold #06b6d4]Sending {cls.escape_markup(method)}[/]"

        if result and isinstance(result, dict):
            status_code = result.get("status_code")
            response_body = result.get("body", "")

            if status_code:
                response_preview = f"Status: {status_code}"
                if response_body:
                    body_preview = (
                        response_body[:300] + "..." if len(response_body) > 300 else response_body
                    )
                    response_preview += f"\n{body_preview}"
                content_text = f"{header}\n  [dim]{cls.escape_markup(response_preview)}[/]"
            else:
                content_text = f"{header}\n  [dim]Response received[/]"
        elif url:
            url_display = url[:400] + "..." if len(url) > 400 else url
            content_text = f"{header}\n  [dim]{cls.escape_markup(url_display)}[/]"
        else:
            content_text = f"{header}\n  [dim]Sending...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class RepeatRequestRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "repeat_request"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        result = tool_data.get("result")

        modifications = args.get("modifications", {})

        header = "🔄 [bold #06b6d4]Repeating request[/]"

        if result and isinstance(result, dict):
            status_code = result.get("status_code")
            response_body = result.get("body", "")

            if status_code:
                response_preview = f"Status: {status_code}"
                if response_body:
                    body_preview = (
                        response_body[:300] + "..." if len(response_body) > 300 else response_body
                    )
                    response_preview += f"\n{body_preview}"
                content_text = f"{header}\n  [dim]{cls.escape_markup(response_preview)}[/]"
            else:
                content_text = f"{header}\n  [dim]Response received[/]"
        elif modifications:
            mod_text = str(modifications)
            mod_display = mod_text[:400] + "..." if len(mod_text) > 400 else mod_text
            content_text = f"{header}\n  [dim]{cls.escape_markup(mod_display)}[/]"
        else:
            content_text = f"{header}\n  [dim]No modifications[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class ScopeRulesRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "scope_rules"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: ARG003
        header = "⚙️ [bold #06b6d4]Updating proxy scope[/]"
        content_text = f"{header}\n  [dim]Configuring...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class ListSitemapRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "list_sitemap"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        header = "🗺️ [bold #06b6d4]Listing sitemap[/]"

        if result and isinstance(result, dict) and "entries" in result:
            entries = result["entries"]
            if isinstance(entries, list) and entries:
                entry_lines = []
                for entry in entries[:4]:
                    if isinstance(entry, dict):
                        label = entry.get("label", "?")
                        kind = entry.get("kind", "?")
                        line = f"{kind}: {label}"
                        entry_lines.append(line)

                if len(entries) > 4:
                    entry_lines.append(f"... +{len(entries) - 4} more")

                escaped_lines = [cls.escape_markup(line) for line in entry_lines]
                content_text = f"{header}\n  [dim]{chr(10).join(escaped_lines)}[/]"
            else:
                content_text = f"{header}\n  [dim]No entries found[/]"
        else:
            content_text = f"{header}\n  [dim]Loading...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class ViewSitemapEntryRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "view_sitemap_entry"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        header = "📍 [bold #06b6d4]Viewing sitemap entry[/]"

        if result and isinstance(result, dict):
            if "entry" in result:
                entry = result["entry"]
                if isinstance(entry, dict):
                    label = entry.get("label", "")
                    kind = entry.get("kind", "")
                    if label and kind:
                        entry_info = f"{kind}: {label}"
                        content_text = f"{header}\n  [dim]{cls.escape_markup(entry_info)}[/]"
                    else:
                        content_text = f"{header}\n  [dim]Entry details loaded[/]"
                else:
                    content_text = f"{header}\n  [dim]Entry details loaded[/]"
            else:
                content_text = f"{header}\n  [dim]Loading entry...[/]"
        else:
            content_text = f"{header}\n  [dim]Loading...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)
