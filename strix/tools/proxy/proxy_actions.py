from typing import Any, Literal

from strix.tools.registry import register_tool


RequestPart = Literal["request", "response"]


@register_tool
def list_requests(
    httpql_filter: str | None = None,
    start_page: int = 1,
    end_page: int = 1,
    page_size: int = 50,
    sort_by: Literal[
        "timestamp",
        "host",
        "method",
        "path",
        "status_code",
        "response_time",
        "response_size",
        "source",
    ] = "timestamp",
    sort_order: Literal["asc", "desc"] = "desc",
    scope_id: str | None = None,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.list_requests(
        httpql_filter, start_page, end_page, page_size, sort_by, sort_order, scope_id
    )


@register_tool
def view_request(
    request_id: str,
    part: RequestPart = "request",
    search_pattern: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.view_request(request_id, part, search_pattern, page, page_size)


@register_tool
def send_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 30,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    if headers is None:
        headers = {}
    manager = get_proxy_manager()
    return manager.send_simple_request(method, url, headers, body, timeout)


@register_tool
def repeat_request(
    request_id: str,
    modifications: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    if modifications is None:
        modifications = {}
    manager = get_proxy_manager()
    return manager.repeat_request(request_id, modifications)


@register_tool
def scope_rules(
    action: Literal["get", "list", "create", "update", "delete"],
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.scope_rules(action, allowlist, denylist, scope_id, scope_name)


@register_tool
def list_sitemap(
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: Literal["DIRECT", "ALL"] = "DIRECT",
    page: int = 1,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.list_sitemap(scope_id, parent_id, depth, page)


@register_tool
def view_sitemap_entry(
    entry_id: str,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.view_sitemap_entry(entry_id)
