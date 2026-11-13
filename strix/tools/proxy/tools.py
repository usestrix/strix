"""Caido proxy host-side @function_tool wrappers around caido_api.py."""

from __future__ import annotations

import asyncio
import dataclasses
import functools
import json
import logging
import re
from dataclasses import is_dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

from agents import RunContextWrapper, function_tool
from caido_sdk_client import BaseError

from strix.runtime.caido_handle import CaidoBootstrapHandle
from strix.tools.nullish import clean_optional
from strix.tools.proxy import caido_api


logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from caido_sdk_client import Client

    from strix.tools.proxy.caido_api import (
        RequestPart,
        SitemapDepth,
        SortBy,
        SortOrder,
    )
else:
    from strix.tools.proxy.caido_api import (  # noqa: TC001
        RequestPart,
        SitemapDepth,
        SortBy,
        SortOrder,
    )


ScopeAction = Literal["get", "list", "create", "update", "delete"]

# All agents in a scan share one host-side Caido client whose GraphQL transport
# is not concurrency-safe (parallel calls raise "Transport is already
# connected"). Serialize every host-side proxy call through this lock.
_CAIDO_CALL_LOCK = asyncio.Lock()


async def _ctx_client(ctx: RunContextWrapper) -> Client | None:
    inner: dict[str, Any] = ctx.context if isinstance(ctx.context, dict) else {}
    client: Client | CaidoBootstrapHandle | None = inner.get("caido_client")
    if isinstance(client, CaidoBootstrapHandle):
        try:
            return await client.get()
        except Exception:  # noqa: BLE001
            logger.warning("Caido bootstrap failed; proxy tools unavailable", exc_info=True)
            return None
    return client


async def _call[T](client: Client, fn: Callable[[Client], Awaitable[T]]) -> T:
    """Run ``fn`` against the shared client, serialized under ``_CAIDO_CALL_LOCK``."""
    async with _CAIDO_CALL_LOCK:
        return await fn(client)


_REQUEST_EXISTS_QUERY = "query RequestExists($id: ID!) { request(id: $id) { id } }"
_REQUEST_EXISTS_ATTEMPTS = 2


async def _request_exists(client: Client, request_id: str) -> bool:
    data = await client.graphql.query(_REQUEST_EXISTS_QUERY, {"id": request_id})
    return bool(data) and data.get("request") is not None


async def existing_request_ids(
    ctx: RunContextWrapper,
    request_ids: list[str],
) -> set[str]:
    """Return request IDs that exist in the current Caido project."""
    if not request_ids:
        return set()

    client = await _ctx_client(ctx)
    if client is None:
        raise RuntimeError("Caido client is not available")

    # Request IDs are not an HTTPQL field, so each one is resolved by id. Only
    # the id is selected: pulling the raw request and response bodies just to
    # learn whether a row exists is what made this time out on busy projects.
    existing: set[str] = set()
    for request_id in request_ids:
        for attempt in range(1, _REQUEST_EXISTS_ATTEMPTS + 1):
            try:
                exists = await _call(
                    client,
                    functools.partial(_request_exists, request_id=request_id),
                )
            except Exception:
                if attempt == _REQUEST_EXISTS_ATTEMPTS:
                    raise
                continue
            if exists:
                existing.add(request_id)
            break
    return existing


def _to_tool_json(value: Any) -> Any:
    """Recursively convert SDK dataclasses/Pydantic objects to tool JSON values."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return value.hex()
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return {k: _to_tool_json(v) for k, v in dataclasses.asdict(value).items()}
    if hasattr(value, "model_dump"):
        return _to_tool_json(value.model_dump())
    if isinstance(value, dict):
        return {str(k): _to_tool_json(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set):
        return [_to_tool_json(v) for v in value]
    return str(value)


def _no_client() -> str:
    return json.dumps(
        {"success": False, "error": "Caido client not available in run context"},
        ensure_ascii=False,
        default=str,
    )


def _err(name: str, exc: Exception) -> str:
    # Caido-side failures (timeouts, bad filters, ...) are returned to the model, not our bugs.
    if isinstance(exc, BaseError):
        logger.warning("%s failed", name, exc_info=True)
    else:
        logger.exception("%s failed", name)
    return json.dumps(
        {"success": False, "error": f"{name} failed: {exc}"},
        ensure_ascii=False,
        default=str,
    )


_INVALID_HTTPQL = "Invalid HTTPQL query"
_HTTPQL_FIELDS: dict[str, dict[str, str]] = {
    "req": {
        "method": "text",
        "host": "text",
        "path": "text",
        "query": "text",
        "ext": "text",
        "raw": "text",
        "port": "int",
        "len": "int",
        "created_at": "date",
        "tls": "bool",
    },
    "resp": {"code": "int", "len": "int", "roundtrip": "int", "raw": "text"},
    "row": {"id": "int"},
}
_HTTPQL_OPERATORS: dict[str, frozenset[str]] = {
    "int": frozenset({"eq", "ne", "gt", "gte", "lt", "lte"}),
    "text": frozenset({"eq", "ne", "cont", "ncont", "like", "nlike", "regex", "nregex"}),
    "date": frozenset({"gt", "lt"}),
    "bool": frozenset({"eq", "ne"}),
}
_HTTPQL_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_HTTPQL_CLAUSE = re.compile(
    r"(?<![\w.])([A-Za-z_]+)\.([A-Za-z_]+)(?:\.([A-Za-z_]+))?(\s*):(\s*)"
    r"(\"(?:[^\"\\]|\\.)*\"|'[^']*'|[^\s()]*)"
)


def _httpql_clause_mistake(match: re.Match[str]) -> str | None:
    namespace, field, operator, before, after, value = match.groups()
    clause = match.group(0).strip()
    if before or after:
        return f"{clause}: remove the spaces around ':'."
    fields = _HTTPQL_FIELDS.get(namespace)
    if fields is None:
        return f"{clause}: unknown namespace {namespace!r}; use req, resp or row."
    kind = fields.get(field)
    if kind is None:
        return (
            f"{clause}: {namespace} has no field {field!r}; use one of {', '.join(sorted(fields))}."
        )
    if operator not in _HTTPQL_OPERATORS[kind]:
        operators = ", ".join(sorted(_HTTPQL_OPERATORS[kind]))
        return f"{clause}: {namespace}.{field} takes {operators}."
    if value.startswith("'"):
        return f"{clause}: use double quotes, not single quotes."
    if kind in ("int", "bool") and value.startswith('"'):
        return f"{clause}: {namespace}.{field} values are not quoted."
    if kind in ("text", "date") and not value.startswith('"'):
        return f'{clause}: quote the value, e.g. {namespace}.{field}.eq:"...".'
    return None


def _httpql_mistakes(httpql_filter: str) -> list[str]:
    mistakes = [
        f"{literal}: write each backslash twice inside a string (\\\\d, \\\\.)."
        for literal in _HTTPQL_STRING.findall(httpql_filter)
        if any(escape not in '"\\/' for escape in re.findall(r"\\(.)", literal[1:-1]))
    ]
    unquoted = _HTTPQL_STRING.sub('""', httpql_filter)
    if re.search(r"\bNOT\b", unquoted, re.IGNORECASE):
        mistakes.append("There is no NOT. Use a negated operator: ne, ncont, nlike, nregex.")
    if "&&" in unquoted or "||" in unquoted:
        mistakes.append("Use AND / OR, not && / ||.")
    mistakes.extend(
        f'{match.group(0)}: quote the value, e.g. {match.group(1)}:"intercept".'
        for match in re.finditer(r"\b(source|preset):(?!\")(\S*)", unquoted)
    )
    for match in _HTTPQL_CLAUSE.finditer(httpql_filter):
        mistake = _httpql_clause_mistake(match)
        if mistake:
            mistakes.append(mistake)
    return mistakes


def _invalid_httpql(httpql_filter: str) -> str:
    mistakes = _httpql_mistakes(httpql_filter) or [
        "Check each clause is namespace.field.operator:value, strings are "
        "double-quoted, numbers are not, and clauses are joined with AND / OR."
    ]
    return json.dumps(
        {
            "success": False,
            "error": f"list_requests failed: Caido rejected the HTTPQL filter {httpql_filter!r}.",
            "likely_mistakes": mistakes,
            "next_step": "Correct the filter and call list_requests again.",
        },
        ensure_ascii=False,
    )


@function_tool(timeout=120)
async def list_requests(
    ctx: RunContextWrapper,
    httpql_filter: str | None = None,
    first: int = 50,
    after: str | None = None,
    sort_by: SortBy = "timestamp",
    sort_order: SortOrder = "desc",
    scope_id: str | None = None,
) -> str:
    r"""List captured HTTP requests from the Caido proxy with HTTPQL filtering.

    A clause is ``namespace.field.operator:value`` with no spaces around
    the colon. Fields and operators by type:

    - **Integer fields** (``resp.code``, ``resp.len``, ``resp.roundtrip``,
      ``req.port``, ``req.len``, ``row.id``) take ``eq``, ``ne``, ``gt``,
      ``gte``, ``lt``, ``lte`` and an unquoted number. Examples:
      ``resp.code.eq:200``, ``resp.code.gte:400``, ``req.port.eq:443``.
    - **Text fields** (``req.method``, ``req.host``, ``req.path``,
      ``req.query``, ``req.ext``, ``req.raw``, ``resp.raw``) take ``eq``,
      ``ne``, ``cont``, ``ncont``, ``like``, ``nlike``, ``regex``,
      ``nregex`` and a double-quoted string. Examples:
      ``req.method.eq:"POST"``, ``req.path.cont:"/api/"``,
      ``req.host.regex:".*\\.example\\.com"``. Inside a string, write
      every regex backslash twice (``\\d``, ``\\.``).
    - **Date field** ``req.created_at`` takes ``gt`` / ``lt`` and a quoted
      ISO timestamp: ``req.created_at.gt:"2024-01-01T00:00:00Z"``.
    - **Boolean field** ``req.tls`` takes ``eq`` / ``ne`` and an unquoted
      ``true`` / ``false``.
    - **Combine** with ``AND`` / ``OR`` and parentheses:
      ``req.method.eq:"POST" AND resp.code.gte:400``.
    - **Special**: ``source:"intercept"`` (only intercepted requests),
      ``preset:"name"``.

    For sitemap-style tree traversal use HTTPQL filters: drill into a
    host with ``req.host.eq:"example.com"`` then narrow paths with
    ``req.path.cont:"/api/"``.

    Pagination is cursor-based. Pass the ``end_cursor`` from the
    ``page_info`` of one call as ``after`` to the next.

    Notes:

    - HTTPQL has **no ``NOT`` operator** and no ``&&`` / ``||``. Use the
      negated form of the operator instead: ``ne``, ``ncont``, ``nlike``,
      ``nregex`` (e.g. ``req.path.ncont:"/static"`` to exclude static paths).
    - String values **must be double-quoted**; integer values **must not**.
      ``resp.code.eq:200`` is right; ``resp.code.eq:"200"`` is a parse
      error. There is no ``req.url`` or ``resp.status`` field.
    - A bare quoted string searches both ``req.raw`` and ``resp.raw``,
      handy for sensitive-data sweeps:
      ``"password" OR "secret" OR "api_key"``.
    - A rejected filter returns the likely mistakes. Correct the filter
      and call again.

    Args:
        httpql_filter: Caido HTTPQL query (optional).
        first: Number of entries to return (default 50).
        after: Cursor from a previous response's ``page_info.end_cursor``.
        sort_by: One of ``timestamp`` / ``host`` / ``method`` / ``path``
            / ``status_code`` / ``response_time`` / ``response_size``
            / ``source``.
        sort_order: ``asc`` or ``desc``.
        scope_id: Restrict to a Caido scope (managed via ``scope_rules``).
    """
    client = await _ctx_client(ctx)
    if client is None:
        return _no_client()

    httpql_filter = clean_optional(httpql_filter)
    after = clean_optional(after)
    scope_id = clean_optional(scope_id)

    try:
        connection = await _call(
            client,
            lambda client: caido_api.list_requests_with_client(
                client,
                httpql_filter=httpql_filter,
                first=first,
                after=after,
                sort_by=sort_by,
                sort_order=sort_order,
                scope_id=scope_id,
            ),
        )

        entries = []
        for edge in connection.edges:
            req = edge.node.request
            resp = edge.node.response
            response_payload: dict[str, Any] | None = None
            if resp is not None:
                response_payload = {
                    "id": resp.id,
                    "status_code": resp.status_code,
                    "length": resp.length,
                    "created_at": resp.created_at.isoformat(),
                }
                # Caido populates ``roundtripTime`` for some traffic sources
                # and leaves it as ``0`` for others (notably proxy captures
                # of upstream env-routed traffic). Surface the value only
                # when it's actually measured so the model doesn't waste
                # tokens reading a zero field on every entry.
                if resp.roundtrip_time:
                    response_payload["roundtrip_ms"] = resp.roundtrip_time
            entries.append(
                {
                    "cursor": edge.cursor,
                    "request": {
                        "id": req.id,
                        "host": req.host,
                        "port": req.port,
                        "method": req.method,
                        "path": req.path,
                        "query": req.query,
                        "is_tls": req.is_tls,
                        "created_at": req.created_at.isoformat(),
                    },
                    "response": response_payload,
                },
            )

        return json.dumps(
            {
                "success": True,
                "entries": entries,
                "page_info": {
                    "has_next_page": connection.page_info.has_next_page,
                    "has_previous_page": connection.page_info.has_previous_page,
                    "start_cursor": connection.page_info.start_cursor,
                    "end_cursor": connection.page_info.end_cursor,
                },
            },
            ensure_ascii=False,
            default=str,
        )
    except Exception as exc:  # noqa: BLE001
        if httpql_filter and _INVALID_HTTPQL in str(exc):
            return _invalid_httpql(httpql_filter)
        return _err("list_requests", exc)


@function_tool(timeout=60)
async def view_request(
    ctx: RunContextWrapper,
    request_id: str,
    part: RequestPart = "request",
    search_pattern: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> str:
    """View a captured request or its response, optionally regex-searched.

    Two modes:

    - **With** ``search_pattern`` (compact regex hits) — returns up to 20
      matches with ``before`` / ``after`` context and position. Useful
      for hunting reflected input, leaked URLs, hidden parameters.
    - **Without** ``search_pattern`` (full content with line pagination)
      — returns the page of raw content plus ``has_more`` flag.

    Common search patterns:

    - API endpoints: ``/api/[a-zA-Z0-9._/-]+``
    - URLs: ``https?://[^\\s<>"']+``
    - Query parameters: ``[?&][a-zA-Z0-9_]+=([^&\\s<>"']+)``
    - Specific input reflection: search for the value you submitted.

    Args:
        request_id: Request ID from ``list_requests``.
        part: ``"request"`` or ``"response"``.
        search_pattern: Optional regex; switches the response shape to
            compact hits.
        page: 1-indexed page number (only when no ``search_pattern``).
        page_size: Lines per page.
    """
    client = await _ctx_client(ctx)
    if client is None:
        return _no_client()

    try:
        result = await _call(
            client,
            lambda client: caido_api.get_request_with_client(client, request_id, part=part),
        )
        if result is None:
            return json.dumps(
                {"success": False, "error": f"Request {request_id} not found"},
                ensure_ascii=False,
                default=str,
            )

        raw_bytes = (
            result.request.raw
            if part == "request"
            else (result.response.raw if result.response is not None else None)
        )
        if raw_bytes is None:
            return json.dumps(
                {
                    "success": False,
                    "error": f"No raw {part} for {request_id}",
                },
                ensure_ascii=False,
                default=str,
            )
        content = raw_bytes.decode("utf-8", errors="replace")

        if search_pattern:
            return json.dumps(
                _format_search_hits(content, search_pattern),
                ensure_ascii=False,
                default=str,
            )

        return json.dumps(
            _format_text_page(content, page=page, page_size=page_size),
            ensure_ascii=False,
            default=str,
        )
    except Exception as exc:  # noqa: BLE001
        return _err("view_request", exc)


def _format_search_hits(content: str, pattern: str) -> dict[str, Any]:
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        return {"success": False, "error": f"Invalid regex: {exc}"}

    hits = []
    for match in regex.finditer(content):
        start, end = match.span()
        before = content[max(0, start - 40) : start]
        after = content[end : end + 40]
        hits.append(
            {
                "match": match.group(0),
                "position": start,
                "before": before,
                "after": after,
            },
        )
        if len(hits) >= 20:
            break

    return {"success": True, "hits": hits, "total_hits": len(hits)}


def _format_text_page(content: str, *, page: int, page_size: int) -> dict[str, Any]:
    lines = content.splitlines()
    start = max(0, (page - 1) * page_size)
    end = start + page_size
    return {
        "success": True,
        "content": "\n".join(lines[start:end]),
        "page": page,
        "page_size": page_size,
        "total_lines": len(lines),
        "has_more": end < len(lines),
    }


@function_tool(timeout=120, strict_mode=False)
async def repeat_request(
    ctx: RunContextWrapper,
    request_id: str,
    modifications: dict[str, Any] | None = None,
) -> str:
    """Repeat a captured request, optionally patching individual fields.

    The standard pentesting workflow with this tool:

    1. ``agent-browser`` (via ``exec_command``) or live target traffic
       → request gets captured by Caido.
    2. ``list_requests`` → find the request ID you want to manipulate.
    3. ``repeat_request`` → send a modified version (auth-bypass test,
       payload injection, parameter tampering).

    Mirrors the manual "browse → capture → modify → test" flow used in
    real pentesting. Inherits everything from the original request
    (headers, cookies, auth, method, URL) and overlays only the fields
    you specify in ``modifications``.

    Args:
        request_id: ID of the original request (from ``list_requests``).
        modifications: Patch dict. Recognized keys:

            - ``url`` — replace the URL.
            - ``params`` — dict of query-string keys to add/update.
            - ``headers`` — dict of headers to add/update.
            - ``body`` — replace the body string entirely.
            - ``cookies`` — dict of cookies to add/update.
    """
    client = await _ctx_client(ctx)
    if client is None:
        return _no_client()
    mods = modifications or {}

    async def _do(client: Client) -> dict[str, Any] | None:
        result = await caido_api.get_request_with_client(client, request_id, part="request")
        if result is None or result.request.raw is None:
            return None
        original = result.request
        raw_str = result.request.raw.decode("utf-8", errors="replace")
        components = caido_api.parse_raw_request(raw_str)
        full_url = caido_api.full_url_from_components(original, components, mods)
        modified = caido_api.apply_modifications(components, mods, full_url)
        connection, raw = caido_api.build_raw_request(
            method=modified["method"],
            url=modified["url"],
            headers=modified["headers"],
            body=modified["body"],
        )
        return await caido_api.replay_send_raw(client, raw=raw, connection=connection)

    try:
        replay = await _call(client, _do)
        if replay is None:
            return json.dumps(
                {"success": False, "error": f"Request {request_id} not found"},
                ensure_ascii=False,
                default=str,
            )
        return _format_replay_tool_result(replay)
    except Exception as exc:  # noqa: BLE001
        return _err("repeat_request", exc)


def _format_replay_tool_result(replay: dict[str, Any]) -> str:
    response = caido_api.parse_raw_response(replay.get("response_raw"))
    payload: dict[str, Any] = {
        "success": replay["status"] == "DONE",
        "status": replay["status"],
        "session_id": replay["session_id"],
        "elapsed_ms": replay["elapsed_ms"],
        "response": response,
    }
    if replay.get("error"):
        payload["error"] = replay["error"]
    return json.dumps(payload, ensure_ascii=False, default=str)


@function_tool(timeout=60)
async def list_sitemap(
    ctx: RunContextWrapper,
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: SitemapDepth = "DIRECT",
    page: int = 1,
) -> str:
    """Browse Caido's hierarchical sitemap of proxied traffic.

    Caido aggregates every captured request into a tree:
    ``DOMAIN`` → ``DIRECTORY`` (path segments) → ``REQUEST`` →
    ``REQUEST_BODY`` / ``REQUEST_QUERY`` (variant per body/query shape).
    Use this to understand the discovered attack surface, locate
    promising directories, and pick endpoints worth deeper testing.

    Workflow:
    - Start with no ``parent_id`` to list root domains (scoped by
      ``scope_id`` if you only care about in-scope hosts).
    - Pick an entry where ``has_descendants=true`` and pass its ``id``
      as ``parent_id`` to drill in. ``depth="DIRECT"`` returns only
      immediate children; ``"ALL"`` flattens the full subtree.
    - Hand any ``id`` to ``view_sitemap_entry`` for the full record
      and recent matching requests.

    Args:
        scope_id: Limit roots to a Caido scope (only used when
            ``parent_id`` is omitted). Manage scopes via ``scope_rules``.
        parent_id: Entry ID to expand; omit for root domains.
        depth: ``"DIRECT"`` (immediate children) or ``"ALL"``
            (recursive subtree). Only meaningful with ``parent_id``.
        page: 1-indexed page (30 entries per page).
    """
    client = await _ctx_client(ctx)
    if client is None:
        return _no_client()
    scope_id = clean_optional(scope_id)
    parent_id = clean_optional(parent_id)
    try:
        payload = await _call(
            client,
            lambda client: caido_api.list_sitemap_with_client(
                client,
                scope_id=scope_id,
                parent_id=parent_id,
                depth=depth,
                page=page,
            ),
        )
        return json.dumps(payload, ensure_ascii=False, default=str)
    except Exception as exc:  # noqa: BLE001
        return _err("list_sitemap", exc)


@function_tool(timeout=60)
async def view_sitemap_entry(
    ctx: RunContextWrapper,
    entry_id: str,
) -> str:
    """Get full detail for a sitemap entry plus its recent requests.

    Returns the entry's metadata, the primary request shape
    (method/path/response if any), and the most recent 30 related
    requests that fall under this entry. Pair with ``list_sitemap`` to
    pick the ``entry_id``.

    Args:
        entry_id: ID from ``list_sitemap`` (or any nested entry).
    """
    client = await _ctx_client(ctx)
    if client is None:
        return _no_client()
    try:
        payload = await _call(
            client,
            lambda client: caido_api.view_sitemap_entry_with_client(client, entry_id),
        )
        return json.dumps(payload, ensure_ascii=False, default=str)
    except Exception as exc:  # noqa: BLE001
        return _err("view_sitemap_entry", exc)


@function_tool(timeout=60)
async def scope_rules(
    ctx: RunContextWrapper,
    action: ScopeAction,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> str:
    """CRUD on Caido scope rules (allow/deny patterns).

    Scopes filter which traffic Caido tools see. Use them to focus on a
    target, exclude noisy assets (CDNs, static files), or define a
    bug-bounty allowlist.

    Pattern semantics:

    - Glob wildcards: ``*`` (any), ``?`` (single), ``[abc]`` (one of),
      ``[a-z]`` (range), ``[^abc]`` (none of).
    - **Empty allowlist = allow all domains.**
    - **Denylist always overrides allowlist.**

    Common denylist for noisy static assets:
    ``["*.gif", "*.jpg", "*.png", "*.css", "*.js", "*.ico", "*.svg",
    "*woff*", "*.ttf"]``.

    Each scope has a unique id usable as ``scope_id`` in
    ``list_requests``.

    Args:
        action:

            - ``list`` — return all scopes.
            - ``get`` — single scope by ``scope_id``.
            - ``create`` — needs ``scope_name``, optionally
              ``allowlist`` / ``denylist``.
            - ``update`` — needs ``scope_id`` + ``scope_name``;
              allowlist / denylist replace the previous values.
            - ``delete`` — needs ``scope_id``.

        allowlist: Domain patterns to include (e.g.
            ``["*.example.com", "api.test.com"]``).
        denylist: Patterns to exclude.
        scope_id: Required for ``get`` / ``update`` / ``delete``.
        scope_name: Required for ``create`` / ``update``.
    """
    client = await _ctx_client(ctx)
    if client is None:
        return _no_client()

    try:
        if action == "list":
            scopes = await _call(client, caido_api.scope_list)
            return json.dumps(
                {"success": True, "scopes": [_to_tool_json(s) for s in scopes]},
                ensure_ascii=False,
                default=str,
            )
        if action == "get":
            if not scope_id:
                return json.dumps(
                    {"success": False, "error": "Scope_id is required for action='get'"},
                    ensure_ascii=False,
                    default=str,
                )
            scope = await _call(client, lambda client: caido_api.scope_get(client, scope_id))
            return json.dumps(
                {"success": True, "scope": _to_tool_json(scope)},
                ensure_ascii=False,
                default=str,
            )
        if action == "create":
            if not scope_name:
                return json.dumps(
                    {"success": False, "error": "Scope_name is required for action='create'"},
                    ensure_ascii=False,
                    default=str,
                )
            scope = await _call(
                client,
                lambda client: caido_api.scope_create(
                    client, name=scope_name, allowlist=allowlist, denylist=denylist
                ),
            )
            return json.dumps(
                {"success": True, "scope": _to_tool_json(scope)},
                ensure_ascii=False,
                default=str,
            )
        if action == "update":
            if not scope_id or not scope_name:
                return json.dumps(
                    {
                        "success": False,
                        "error": "Scope_id and scope_name are required for action='update'",
                    },
                    ensure_ascii=False,
                    default=str,
                )
            scope = await _call(
                client,
                lambda client: caido_api.scope_update(
                    client, scope_id, name=scope_name, allowlist=allowlist, denylist=denylist
                ),
            )
            return json.dumps(
                {"success": True, "scope": _to_tool_json(scope)},
                ensure_ascii=False,
                default=str,
            )
        if not scope_id:
            return json.dumps(
                {"success": False, "error": "Scope_id is required for action='delete'"},
                ensure_ascii=False,
                default=str,
            )
        await _call(client, lambda client: caido_api.scope_delete(client, scope_id))
        return json.dumps(
            {
                "success": True,
                "deleted": scope_id,
                "message": f"Scope {scope_id} deleted",
            },
            ensure_ascii=False,
            default=str,
        )
    except Exception as exc:  # noqa: BLE001
        return _err("scope_rules", exc)
