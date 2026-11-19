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


async def _call[T](
    client: Client,
    fn: Callable[[Client], Awaitable[T]],
    *,
    read_only: bool = False,
    timeout: int | None = None,
) -> T:
    """Run ``fn`` against the shared client, serialized under ``_CAIDO_CALL_LOCK``.

    Now and then a request to the proxy gets no answer at all and the same
    request succeeds immediately afterwards, so a ``read_only`` call that
    times out is sent once more. The lock is released between the attempts.
    """
    attempts = 2 if read_only else 1
    if timeout is None:
        # Two read attempts must both fit inside the 60-second tool deadline.
        timeout = (
            caido_api.GRAPHQL_READ_TIMEOUT_SECONDS
            if read_only
            else caido_api.GRAPHQL_TIMEOUT_SECONDS
        )
    for attempt in range(1, attempts + 1):
        async with _CAIDO_CALL_LOCK:
            caido_api.extend_graphql_timeout(client, timeout)
            try:
                return await fn(client)
            except Exception as exc:
                if attempt == attempts or not _is_timeout(exc):
                    raise
                logger.warning("proxy call timed out after %ss; retrying once", timeout)
    raise AssertionError("unreachable")  # pragma: no cover


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
                    timeout=caido_api.GRAPHQL_READ_TIMEOUT_SECONDS,
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


def _iso(epoch_ms: float) -> str:
    # Same local-time rendering as the SDK's own request mapping.
    return datetime.fromtimestamp(epoch_ms / 1000.0).isoformat()  # noqa: DTZ006


def _no_client() -> str:
    return json.dumps(
        {"success": False, "error": "Caido client not available in run context"},
        ensure_ascii=False,
        default=str,
    )


def _is_timeout(exc: object) -> bool:
    """True when ``exc`` or anything it wraps is a timeout."""
    seen: set[int] = set()
    # The SDK's ``source`` is not always an exception: a rejected query carries the error dict.
    while isinstance(exc, BaseException) and id(exc) not in seen:
        if isinstance(exc, TimeoutError):
            return True
        seen.add(id(exc))
        exc = getattr(exc, "source", None) or exc.__cause__
    return False


def _describe(exc: Exception) -> str:
    """Error text for the model; never empty, and explicit about timeouts."""
    if _is_timeout(exc):
        return (
            "the proxy did not answer in time. The request is valid: call again, with a "
            "narrower filter or a smaller page if it repeats."
        )
    text = str(exc).strip()
    source = getattr(exc, "source", None)
    if source is not None and str(source).strip() and isinstance(exc, BaseError):
        # The SDK appends the wrapped error even when it only repeats the message.
        message = text.split("\n  Source:", 1)[0].strip()
        if message == str(source).strip():
            text = message
    if source is not None and not str(source).strip():
        # A wrapped exception with no message renders as a bare "Source:".
        text = f"{text.removesuffix('Source:').strip()} ({type(source).__name__})".strip()
    return text or type(exc).__name__


def _err(name: str, exc: Exception) -> str:
    # Caido-side failures (timeouts, bad filters, ...) are returned to the model, not our bugs.
    if isinstance(exc, BaseError):
        logger.warning("%s failed", name, exc_info=True)
    else:
        logger.exception("%s failed", name)
    return json.dumps(
        {"success": False, "error": f"{name} failed: {_describe(exc)}"},
        ensure_ascii=False,
        default=str,
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
    r"""List captured HTTP requests from the Caido proxy, filtered with HTTPQL.

    HTTPQL grammar: a clause is ``namespace.field.operator:value`` with no
    whitespace inside the clause. Clauses combine with ``AND`` / ``OR``
    (case-insensitive) and parentheses. There is no ``NOT``, ``&&`` or
    ``||``; negate with ``ne``, ``ncont``, ``nlike``, ``nregex``.

    Fields:

    - ``req``: ``method``, ``host``, ``path``, ``query``, ``ext``, ``raw``
      (string); ``port``, ``len`` (integer); ``created_at`` (date);
      ``tls`` (boolean).
    - ``resp``: ``code``, ``len``, ``roundtrip`` (integer); ``raw``
      (string).
    - ``row.id`` (integer).
    - No other field exists in the bundled Caido: no ``req.url``,
      ``resp.status``, ``req.header`` or ``req.body``. Match headers and
      bodies through ``req.raw`` / ``resp.raw``.

    Operators and values:

    - Integer: ``eq``, ``ne``, ``gt``, ``gte``, ``lt``, ``lte`` with a bare
      number: ``resp.code.eq:200``, ``resp.len.gt:1000``, ``row.id.eq:413``.
    - String: ``eq``, ``ne``, ``cont``, ``ncont``, ``like``, ``nlike``,
      ``regex``, ``nregex`` with a double-quoted value:
      ``req.method.eq:"POST"``, ``req.path.cont:"/api/"``,
      ``req.ext.nlike:"%.js"``. ``cont`` is case-insensitive; ``eq`` and
      ``like`` are case-sensitive; ``like`` uses SQLite ``%`` / ``_``
      wildcards. ``req.ext`` includes the dot: ``req.ext.eq:".js"``.
    - Regex: write the pattern between slashes, escaping ``/``:
      ``req.host.regex:/.*\.example\.com/``,
      ``req.path.regex:/\/api\/v\d+/``. In a double-quoted regex every
      backslash is doubled (JSON escaping): ``req.host.regex:"\\.example\\.com"``.
      Rust regex syntax, no lookaround.
    - Date (``req.created_at``): ``gt`` / ``lt`` only, with a quoted
      ISO 8601 / RFC 3339 value: ``req.created_at.gt:"2024-01-01T00:00:00Z"``.
    - Boolean (``req.tls``): ``eq`` / ``ne`` with bare ``true`` / ``false``.
    - ``source:"intercept"`` (also ``"replay"``, ``"automate"``,
      ``"workflow"``, ``"plugin"``) and ``preset:"name"`` take a quoted value.
    - A bare quoted string searches ``req.raw`` and ``resp.raw``:
      ``"password" OR "api_key"``.

    Examples: ``req.host.eq:"example.com" AND req.path.cont:"/api/"``;
    ``req.method.eq:"POST" AND resp.code.gte:400``;
    ``req.path.ncont:"/static"``;
    ``(req.ext.eq:".js" OR req.ext.eq:".map") AND resp.code.eq:200``.

    Caido answers a malformed filter with ``Invalid HTTPQL query`` and
    returns no requests. Fix the clause and call again. Usual causes: a
    quoted integer (``resp.code.eq:"200"``), an unquoted string
    (``req.method.eq:POST``), single quotes, ``NOT``, ``&&``, a field that
    does not exist, or ``gte`` / ``lte`` on ``created_at``.

    For sitemap-style tree traversal, drill into a host with
    ``req.host.eq:"example.com"`` then narrow with ``req.path.cont:"/api/"``.

    Pagination is cursor-based. Pass the ``end_cursor`` from the
    ``page_info`` of one call as ``after`` to the next.

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
            lambda client: caido_api.list_request_summaries_with_client(
                client,
                httpql_filter=httpql_filter,
                first=first,
                after=after,
                sort_by=sort_by,
                sort_order=sort_order,
                scope_id=scope_id,
            ),
            read_only=True,
            timeout=caido_api.GRAPHQL_READ_TIMEOUT_SECONDS,
        )

        entries = []
        for edge in connection.get("edges") or []:
            req = edge["node"]
            resp = req.get("response")
            response_payload: dict[str, Any] | None = None
            if resp is not None:
                response_payload = {
                    "id": resp["id"],
                    "status_code": resp["statusCode"],
                    "length": resp["length"],
                    "created_at": _iso(resp["createdAt"]),
                }
                # Caido populates ``roundtripTime`` for some traffic sources
                # and leaves it as ``0`` for others (notably proxy captures
                # of upstream env-routed traffic). Surface the value only
                # when it's actually measured so the model doesn't waste
                # tokens reading a zero field on every entry.
                if resp.get("roundtripTime"):
                    response_payload["roundtrip_ms"] = resp["roundtripTime"]
            entries.append(
                {
                    "cursor": edge["cursor"],
                    "request": {
                        "id": req["id"],
                        "host": req["host"],
                        "port": req["port"],
                        "method": req["method"],
                        "path": req["path"],
                        "query": req["query"],
                        "is_tls": req["isTls"],
                        "created_at": _iso(req["createdAt"]),
                    },
                    "response": response_payload,
                },
            )
        page_info = connection.get("pageInfo") or {}

        return json.dumps(
            {
                "success": True,
                "entries": entries,
                "page_info": {
                    "has_next_page": bool(page_info.get("hasNextPage")),
                    "has_previous_page": bool(page_info.get("hasPreviousPage")),
                    "start_cursor": page_info.get("startCursor"),
                    "end_cursor": page_info.get("endCursor"),
                },
            },
            ensure_ascii=False,
            default=str,
        )
    except Exception as exc:  # noqa: BLE001
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
            read_only=True,
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
            read_only=True,
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
            read_only=True,
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
            scopes = await _call(client, caido_api.scope_list, read_only=True)
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
            scope = await _call(
                client, lambda client: caido_api.scope_get(client, scope_id), read_only=True
            )
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
