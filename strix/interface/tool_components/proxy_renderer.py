from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


PROXY_ICON = "<~>"
MAX_REQUESTS_DISPLAY = 20
MAX_LINE_LENGTH = 200


def _truncate(text: str, max_len: int = 80) -> str:
    return text[: max_len - 3] + "..." if len(text) > max_len else text


def _sanitize(text: str, max_len: int = 150) -> str:
    """Remove newlines and truncate text."""
    clean = text.replace("\n", " ").replace("\r", "").replace("\t", " ")
    return _truncate(clean, max_len)


def _status_style(code: int | None) -> str:
    if code is None:
        return "dim"
    if 200 <= code < 300:
        return "#22c55e"  # green
    if 300 <= code < 400:
        return "#eab308"  # yellow
    if 400 <= code < 500:
        return "#f97316"  # orange
    if code >= 500:
        return "#ef4444"  # red
    return "dim"


@register_tool_renderer
class ListRequestsRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "list_requests"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: PLR0912  # noqa: PLR0912
        args = tool_data.get("args", {})
        result = tool_data.get("result")
        status = tool_data.get("status", "running")

        httpql_filter = args.get("httpql_filter")
        sort_by = args.get("sort_by")
        sort_order = args.get("sort_order")
        scope_id = args.get("scope_id")

        text = Text()
        text.append(PROXY_ICON, style="dim")
        text.append(" listing requests", style="#06b6d4")

        if httpql_filter:
            text.append(f"  where {_truncate(httpql_filter, 150)}", style="dim italic")

        meta_parts = []
        if sort_by and sort_by != "timestamp":
            meta_parts.append(f"by:{sort_by}")
        if sort_order and sort_order != "desc":
            meta_parts.append(sort_order)
        if scope_id and isinstance(scope_id, str):
            meta_parts.append(f"scope:{scope_id[:8]}")
        if meta_parts:
            text.append(f"  ({', '.join(meta_parts)})", style="dim")

        if status == "completed" and isinstance(result, dict):
            if "error" in result:
                text.append(f"  error: {_sanitize(str(result['error']), 150)}", style="#ef4444")
            else:
                total = result.get("total_count", 0)
                requests = result.get("requests", [])

                text.append(f"  [{total} found]", style="dim")

                if requests and isinstance(requests, list):
                    text.append("\n")
                    for i, req in enumerate(requests[:MAX_REQUESTS_DISPLAY]):
                        if not isinstance(req, dict):
                            continue
                        method = req.get("method", "?")
                        host = req.get("host", "")
                        path = req.get("path", "/")
                        resp = req.get("response") or {}
                        code = resp.get("statusCode") if isinstance(resp, dict) else None

                        text.append("  ")
                        text.append(f"{method:6}", style="#a78bfa")
                        text.append(f" {_truncate(host + path, 180)}", style="dim")
                        if code:
                            text.append(f" {code}", style=_status_style(code))

                        if i < min(len(requests), MAX_REQUESTS_DISPLAY) - 1:
                            text.append("\n")

                    if len(requests) > MAX_REQUESTS_DISPLAY:
                        text.append("\n")
                        text.append(
                            f"  ... +{len(requests) - MAX_REQUESTS_DISPLAY} more",
                            style="dim italic",
                        )

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)


@register_tool_renderer
class ViewRequestRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "view_request"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: PLR0912, PLR0915
        args = tool_data.get("args", {})
        result = tool_data.get("result")
        status = tool_data.get("status", "running")

        request_id = args.get("request_id", "")
        part = args.get("part", "request")
        search_pattern = args.get("search_pattern")

        text = Text()
        text.append(PROXY_ICON, style="dim")

        action = "searching" if search_pattern else "viewing"
        text.append(f" {action} {part}", style="#06b6d4")

        if request_id:
            text.append(f" #{request_id}", style="dim")

        if search_pattern:
            text.append(f"  /{_truncate(search_pattern, 100)}/", style="dim italic")

        if status == "completed" and isinstance(result, dict):
            if "error" in result:
                text.append(f"  error: {_sanitize(str(result['error']), 150)}", style="#ef4444")
            elif "matches" in result:
                matches = result.get("matches", [])
                total = result.get("total_matches", len(matches))
                text.append(f"  [{total} matches]", style="dim")

                if matches and isinstance(matches, list):
                    text.append("\n")
                    for i, m in enumerate(matches[:5]):
                        if not isinstance(m, dict):
                            continue
                        before = m.get("before", "") or ""
                        match_text = m.get("match", "") or ""
                        after = m.get("after", "") or ""

                        before = before.replace("\n", " ").replace("\r", "")[-100:]
                        after = after.replace("\n", " ").replace("\r", "")[:100]

                        text.append("  ")

                        if before:
                            text.append(f"...{before}", style="dim")
                        text.append(match_text, style="#22c55e bold")
                        if after:
                            text.append(f"{after}...", style="dim")

                        if i < min(len(matches), 5) - 1:
                            text.append("\n")

                    if len(matches) > 5:
                        text.append("\n")
                        text.append(f"  ... +{len(matches) - 5} more matches", style="dim italic")

            elif "content" in result:
                showing = result.get("showing_lines", "")
                has_more = result.get("has_more", False)
                content = result.get("content", "")

                text.append(f"  [{showing}]", style="dim")

                if content and isinstance(content, str):
                    lines = content.split("\n")[:15]
                    text.append("\n")
                    for i, line in enumerate(lines):
                        text.append("  ")
                        text.append(_truncate(line, MAX_LINE_LENGTH), style="dim")
                        if i < len(lines) - 1:
                            text.append("\n")

                    if has_more or len(lines) > 15:
                        text.append("\n")
                        text.append("  ... more content available", style="dim italic")

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)


@register_tool_renderer
class SendRequestRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "send_request"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: PLR0912, PLR0915
        args = tool_data.get("args", {})
        result = tool_data.get("result")
        status = tool_data.get("status", "running")

        method = args.get("method", "GET")
        url = args.get("url", "")
        req_headers = args.get("headers")
        req_body = args.get("body", "")

        text = Text()
        text.append(PROXY_ICON, style="dim")
        text.append(" sending request", style="#06b6d4")

        text.append("\n")
        text.append("  >> ", style="#3b82f6")
        text.append(method, style="#a78bfa")
        text.append(f" {_truncate(url, 180)}", style="dim")

        if req_headers and isinstance(req_headers, dict):
            for k, v in list(req_headers.items())[:5]:
                text.append("\n")
                text.append("  >> ", style="#3b82f6")
                text.append(f"{k}: ", style="dim")
                text.append(_sanitize(str(v), 150), style="dim")

        if req_body and isinstance(req_body, str):
            text.append("\n")
            text.append("  >> ", style="#3b82f6")
            body_lines = req_body.split("\n")[:4]
            for i, line in enumerate(body_lines):
                if i > 0:
                    text.append("\n")
                    text.append("     ", style="dim")
                text.append(_truncate(line, MAX_LINE_LENGTH), style="dim")
            if len(req_body.split("\n")) > 4:
                text.append(" ...", style="dim italic")

        if status == "completed" and isinstance(result, dict):
            if "error" in result:
                text.append(f"\n  error: {_sanitize(str(result['error']), 150)}", style="#ef4444")
            else:
                code = result.get("status_code")
                time_ms = result.get("response_time_ms")

                text.append("\n")
                text.append("  << ", style="#22c55e")
                if code:
                    text.append(f"{code}", style=_status_style(code))
                if time_ms:
                    text.append(f" ({time_ms}ms)", style="dim")

                body = result.get("body", "")
                if body and isinstance(body, str):
                    lines = body.split("\n")[:6]
                    for line in lines:
                        text.append("\n")
                        text.append("  << ", style="#22c55e")
                        text.append(_truncate(line, MAX_LINE_LENGTH - 5), style="dim")

                    if len(body.split("\n")) > 6:
                        text.append("\n")
                        text.append("  ...", style="dim italic")

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)


@register_tool_renderer
class RepeatRequestRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "repeat_request"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: PLR0912, PLR0915
        args = tool_data.get("args", {})
        result = tool_data.get("result")
        status = tool_data.get("status", "running")

        request_id = args.get("request_id", "")
        modifications = args.get("modifications")

        text = Text()
        text.append(PROXY_ICON, style="dim")
        text.append(" repeating request", style="#06b6d4")

        if request_id:
            text.append(f" #{request_id}", style="dim")

        if modifications and isinstance(modifications, dict):
            text.append("\n  modifications:", style="dim italic")

            if "url" in modifications:
                text.append("\n")
                text.append("  >> ", style="#3b82f6")
                text.append(f"url: {_truncate(str(modifications['url']), 180)}", style="dim")

            if "headers" in modifications and isinstance(modifications["headers"], dict):
                for k, v in list(modifications["headers"].items())[:5]:
                    text.append("\n")
                    text.append("  >> ", style="#3b82f6")
                    text.append(f"{k}: {_sanitize(str(v), 150)}", style="dim")

            if "cookies" in modifications and isinstance(modifications["cookies"], dict):
                for k, v in list(modifications["cookies"].items())[:5]:
                    text.append("\n")
                    text.append("  >> ", style="#3b82f6")
                    text.append(f"cookie {k}={_sanitize(str(v), 100)}", style="dim")

            if "params" in modifications and isinstance(modifications["params"], dict):
                for k, v in list(modifications["params"].items())[:5]:
                    text.append("\n")
                    text.append("  >> ", style="#3b82f6")
                    text.append(f"param {k}={_sanitize(str(v), 100)}", style="dim")

            if "body" in modifications and isinstance(modifications["body"], str):
                text.append("\n")
                text.append("  >> ", style="#3b82f6")
                body_lines = modifications["body"].split("\n")[:4]
                for i, line in enumerate(body_lines):
                    if i > 0:
                        text.append("\n")
                        text.append("     ", style="dim")
                    text.append(_truncate(line, MAX_LINE_LENGTH), style="dim")
                if len(modifications["body"].split("\n")) > 4:
                    text.append(" ...", style="dim italic")

        elif modifications and isinstance(modifications, str):
            text.append(f"\n  {_truncate(modifications, 200)}", style="dim italic")

        if status == "completed" and isinstance(result, dict):
            if "error" in result:
                text.append(f"\n  error: {_sanitize(str(result['error']), 150)}", style="#ef4444")
            else:
                req = result.get("request", {})
                method = req.get("method", "")
                url = req.get("url", "")
                code = result.get("status_code")
                time_ms = result.get("response_time_ms")

                text.append("\n")
                text.append("  >> ", style="#3b82f6")
                if method:
                    text.append(f"{method} ", style="#a78bfa")
                if url:
                    text.append(_truncate(url, 180), style="dim")

                text.append("\n")
                text.append("  << ", style="#22c55e")
                if code:
                    text.append(f"{code}", style=_status_style(code))
                if time_ms:
                    text.append(f" ({time_ms}ms)", style="dim")

                body = result.get("body", "")
                if body and isinstance(body, str):
                    lines = body.split("\n")[:5]
                    for line in lines:
                        text.append("\n")
                        text.append("  << ", style="#22c55e")
                        text.append(_truncate(line, MAX_LINE_LENGTH - 5), style="dim")

                    if len(body.split("\n")) > 5:
                        text.append("\n")
                        text.append("  ...", style="dim italic")

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)


@register_tool_renderer
class ScopeRulesRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "scope_rules"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: PLR0912, PLR0915
        args = tool_data.get("args", {})
        result = tool_data.get("result")
        status = tool_data.get("status", "running")

        action = args.get("action", "")
        scope_name = args.get("scope_name", "")
        scope_id = args.get("scope_id", "")
        allowlist = args.get("allowlist")
        denylist = args.get("denylist")

        text = Text()
        text.append(PROXY_ICON, style="dim")

        action_map = {
            "get": "getting",
            "list": "listing",
            "create": "creating",
            "update": "updating",
            "delete": "deleting",
        }
        action_text = action_map.get(action, action + "ing" if action else "managing")
        text.append(f" {action_text} proxy scope", style="#06b6d4")

        if scope_name:
            text.append(f" '{_truncate(scope_name, 50)}'", style="dim italic")
        if scope_id and isinstance(scope_id, str):
            text.append(f" #{scope_id[:8]}", style="dim")

        if allowlist and isinstance(allowlist, list):
            allow_str = ", ".join(_truncate(str(a), 40) for a in allowlist[:4])
            text.append(f"\n  allow: {allow_str}", style="dim")
            if len(allowlist) > 4:
                text.append(f" +{len(allowlist) - 4}", style="dim italic")
        if denylist and isinstance(denylist, list):
            deny_str = ", ".join(_truncate(str(d), 40) for d in denylist[:4])
            text.append(f"\n  deny: {deny_str}", style="dim")
            if len(denylist) > 4:
                text.append(f" +{len(denylist) - 4}", style="dim italic")

        if status == "completed" and isinstance(result, dict):
            if "error" in result:
                text.append(f"  error: {_sanitize(str(result['error']), 150)}", style="#ef4444")
            elif "scopes" in result:
                scopes = result.get("scopes", [])
                text.append(f"  [{len(scopes)} scopes]", style="dim")

                if scopes and isinstance(scopes, list):
                    text.append("\n")
                    for i, scope in enumerate(scopes[:5]):
                        if not isinstance(scope, dict):
                            continue
                        name = scope.get("name", "?")
                        allow = scope.get("allowlist") or []
                        text.append("  ")
                        text.append(_truncate(str(name), 40), style="#22c55e")
                        if allow and isinstance(allow, list):
                            allow_str = ", ".join(_truncate(str(a), 30) for a in allow[:3])
                            text.append(f"  {allow_str}", style="dim")
                            if len(allow) > 3:
                                text.append(f" +{len(allow) - 3}", style="dim italic")
                        if i < min(len(scopes), 5) - 1:
                            text.append("\n")

            elif "scope" in result:
                scope = result.get("scope") or {}
                if isinstance(scope, dict):
                    allow = scope.get("allowlist") or []
                    deny = scope.get("denylist") or []

                    if allow and isinstance(allow, list):
                        allow_str = ", ".join(_truncate(str(a), 40) for a in allow[:5])
                        text.append(f"\n  allow: {allow_str}", style="dim")
                    if deny and isinstance(deny, list):
                        deny_str = ", ".join(_truncate(str(d), 40) for d in deny[:5])
                        text.append(f"\n  deny: {deny_str}", style="dim")

            elif "message" in result:
                text.append(f"  {result['message']}", style="#22c55e")

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)


@register_tool_renderer
class ListSitemapRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "list_sitemap"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: PLR0912, PLR0915
        args = tool_data.get("args", {})
        result = tool_data.get("result")
        status = tool_data.get("status", "running")

        parent_id = args.get("parent_id")
        scope_id = args.get("scope_id")
        depth = args.get("depth")

        text = Text()
        text.append(PROXY_ICON, style="dim")
        text.append(" listing sitemap", style="#06b6d4")

        if parent_id:
            text.append(f"  under #{_truncate(str(parent_id), 20)}", style="dim")

        meta_parts = []
        if scope_id and isinstance(scope_id, str):
            meta_parts.append(f"scope:{scope_id[:8]}")
        if depth and depth != "DIRECT":
            meta_parts.append(depth.lower())
        if meta_parts:
            text.append(f"  ({', '.join(meta_parts)})", style="dim")

        if status == "completed" and isinstance(result, dict):
            if "error" in result:
                text.append(f"  error: {_sanitize(str(result['error']), 150)}", style="#ef4444")
            else:
                total = result.get("total_count", 0)
                entries = result.get("entries", [])

                text.append(f"  [{total} entries]", style="dim")

                if entries and isinstance(entries, list):
                    text.append("\n")
                    for i, entry in enumerate(entries[:MAX_REQUESTS_DISPLAY]):
                        if not isinstance(entry, dict):
                            continue
                        kind = entry.get("kind") or "?"
                        label = entry.get("label") or "?"
                        has_children = entry.get("hasDescendants", False)
                        req = entry.get("request") or {}

                        kind_style = {
                            "DOMAIN": "#f59e0b",
                            "DIRECTORY": "#3b82f6",
                            "REQUEST": "#22c55e",
                        }.get(kind, "dim")

                        text.append("  ")
                        kind_abbr = kind[:3] if isinstance(kind, str) else "?"
                        text.append(f"{kind_abbr:3}", style=kind_style)
                        text.append(f" {_truncate(label, 150)}", style="dim")

                        if req:
                            method = req.get("method", "")
                            code = req.get("status")
                            if method:
                                text.append(f" {method}", style="#a78bfa")
                            if code:
                                text.append(f" {code}", style=_status_style(code))

                        if has_children:
                            text.append(" +", style="dim italic")

                        if i < min(len(entries), MAX_REQUESTS_DISPLAY) - 1:
                            text.append("\n")

                    if len(entries) > MAX_REQUESTS_DISPLAY:
                        text.append("\n")
                        text.append(
                            f"  ... +{len(entries) - MAX_REQUESTS_DISPLAY} more", style="dim italic"
                        )

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)


@register_tool_renderer
class ViewSitemapEntryRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "view_sitemap_entry"
    css_classes: ClassVar[list[str]] = ["tool-call", "proxy-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: PLR0912
        args = tool_data.get("args", {})
        result = tool_data.get("result")
        status = tool_data.get("status", "running")

        entry_id = args.get("entry_id", "")

        text = Text()
        text.append(PROXY_ICON, style="dim")
        text.append(" viewing sitemap", style="#06b6d4")

        if entry_id:
            text.append(f" #{_truncate(str(entry_id), 20)}", style="dim")

        if status == "completed" and isinstance(result, dict):
            if "error" in result:
                text.append(f"  error: {_sanitize(str(result['error']), 150)}", style="#ef4444")
            elif "entry" in result:
                entry = result.get("entry") or {}
                if not isinstance(entry, dict):
                    entry = {}
                kind = entry.get("kind", "")
                label = entry.get("label", "")
                related = entry.get("related_requests") or {}
                related_reqs = related.get("requests", []) if isinstance(related, dict) else []
                total_related = related.get("total_count", 0) if isinstance(related, dict) else 0

                if kind and label:
                    text.append(f"  {kind}: {_truncate(label, 120)}", style="dim")

                if total_related:
                    text.append(f"  [{total_related} requests]", style="dim")

                if related_reqs and isinstance(related_reqs, list):
                    text.append("\n")
                    for i, req in enumerate(related_reqs[:10]):
                        if not isinstance(req, dict):
                            continue
                        method = req.get("method", "?")
                        path = req.get("path", "/")
                        code = req.get("status")

                        text.append("  ")
                        text.append(f"{method:6}", style="#a78bfa")
                        text.append(f" {_truncate(path, 180)}", style="dim")
                        if code:
                            text.append(f" {code}", style=_status_style(code))

                        if i < min(len(related_reqs), 10) - 1:
                            text.append("\n")

                    if len(related_reqs) > 10:
                        text.append("\n")
                        text.append(f"  ... +{len(related_reqs) - 10} more", style="dim italic")

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)
