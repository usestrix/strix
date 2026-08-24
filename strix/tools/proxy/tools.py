"""Caido proxy host-side @function_tool wrappers around caido_api.py."""

from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import json
import logging
import re
import socket
from dataclasses import is_dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlparse

from agents import RunContextWrapper, function_tool

from strix.runtime.caido_handle import CaidoBootstrapHandle
from strix.tools.proxy import caido_api


logger = logging.getLogger(__name__)


# --- Code-level scope / SSRF egress guard (DEFENSE-IN-DEPTH) -----------------
#
# SCOPE OF THIS GUARD: it protects the ``repeat_request`` replay path ONLY. That
# path sends a fully model-controlled URL to a real HTTP client, and the scope
# the agent is supposed to stay within is otherwise expressed only as prompt
# text, so a prompt-injected target ("test http://169.254.169.254/...") would
# flow straight to a request against cloud metadata / internal services. This
# module keeps a code-level DENY-by-default check for internal/link-local/
# loopback destinations, with an allow-exception for hosts the platform
# explicitly authorized as in-scope.
#
# THIS IS NOT COMPLETE EGRESS ENFORCEMENT. It is one per-tool check on one tool.
# Other egress channels — ``exec_command`` (curl/nc/any binary the agent runs),
# the agent browser, and DNS — are NOT covered by any per-tool check here and
# MUST be enforced at the container network layer (egress firewall / blocked
# route to 169.254.0.0/16 and RFC1918). Treat this guard as defense-in-depth for
# the replay path, not as the security boundary.
#
# The authorized-target list is built in ``strix.core.inputs.build_scope_context``
# (not importable here without a cycle, and not reachable from the tool's run
# context). It is threaded in here by ``strix.agents.factory.build_strix_agent``,
# which owns ``system_prompt_context.authorized_targets`` and calls
# ``register_authorized_hosts`` for every agent it builds (root + children).
_AUTHORIZED_HOSTS: set[str] = set()


def _host_from_target_value(value: str) -> str | None:
    """Best-effort extraction of a network host from an authorized-target value.

    Target values are URLs (``http://api.example.com/...``), bare hosts, or
    ``host:port``. Repository URLs / local paths yield nothing usable and are
    simply ignored.
    """
    raw = (value or "").strip()
    if not raw:
        return None
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="")
    host = parsed.hostname
    if host:
        return host.lower()
    return None


def register_authorized_hosts(targets: Any) -> None:
    """Register in-scope hosts so ``repeat_request`` can allow-except them.

    Called by the agent factory with ``system_prompt_context.authorized_targets``
    (a list of ``{"type", "value", ...}`` dicts). Every agent in a scan is built
    with the SAME full authorized-target list, so this REPLACES the allow-set
    rather than accumulating into it.

    Security (scope leak across scans): ``_AUTHORIZED_HOSTS`` is a process-global.
    In a long-lived process that runs scan B after scan A, a union/accumulate
    would leave scan A's hosts allow-excepted for scan B, silently widening scan
    B's egress scope. Replace-semantics make each registration fully define the
    allow-set for the current scan. A call that carries no usable target list is
    a no-op (it must not wipe a scope that a sibling build just registered).
    """
    if not isinstance(targets, list):
        return
    hosts: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            continue
        host = _host_from_target_value(str(target.get("value", "")))
        if host:
            hosts.add(host)
    if not hosts:
        # Nothing usable (e.g. a repo-URL-only target list); don't clobber a
        # scope another agent in this same scan already established.
        return
    global _AUTHORIZED_HOSTS  # noqa: PLW0603 - single authoritative process scope
    _AUTHORIZED_HOSTS = hosts


def _ip_is_internal(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """RFC1918 / link-local (incl. 169.254.169.254 metadata) / loopback / unspecified."""
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified


# Hostnames that name an internal endpoint without resolving to a fixed literal.
_BLOCKED_HOSTNAMES = frozenset({"host.docker.internal", "localhost"})


def _screen_destination(url: str) -> tuple[str | None, str | None]:
    """Screen ``url``'s host; return ``(deny_reason, pinned_ip)``.

    ``deny_reason`` is a non-None string when the host is internal and not
    authorized (the caller must refuse). ``pinned_ip`` is the exact IP literal
    that was validated as external and MUST be the one connected to — the caller
    threads it into ``ConnectionInfoInput.host`` so Caido does not re-resolve the
    hostname at send time.

    Security (DNS-rebinding TOCTOU): resolving here and connecting to the
    hostname later is a check/use split. A rebinding name can answer with a
    public A record now and 169.254.169.254 (or an RFC1918 host) at send time,
    slipping past this check. Returning the resolved IP and pinning it collapses
    the window: the IP that gets validated is the IP that gets connected.

    DENY-by-default for RFC1918, link-local (169.254/16 incl. cloud metadata),
    loopback (127/8, ::1), and ``host.docker.internal`` — UNLESS the host is on
    the platform-verified authorized-target list.

    ``pinned_ip`` is None (connect by hostname, no pin) when the host is
    explicitly authorized (scope is by name there), or unresolvable here (Caido
    surfaces the DNS failure and it cannot reach an internal address anyway).
    """
    host = (urlparse(url).hostname or "").strip().rstrip(".").lower()
    if not host:
        return (f"could not determine destination host from URL: {url!r}", None)

    # Explicitly in-scope: the platform authorized this exact host (covers a
    # legitimately-scoped internal IP or an internal hostname target). Allowed
    # regardless of resolved IP, so no pin (connect by hostname as before).
    if host in _AUTHORIZED_HOSTS:
        return (None, None)

    if host in _BLOCKED_HOSTNAMES:
        return (
            f"destination host {host!r} is a sandbox-internal endpoint and is not in the "
            "authorized target scope",
            None,
        )

    # (parsed-ip, literal-string) pairs; the literal is what we pin so the exact
    # form Caido connects to is the exact form we screened.
    candidates: list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, str]] = []
    try:
        candidates.append((ipaddress.ip_address(host), host))
    except ValueError:
        # A hostname — resolve it and screen every address it points at.
        try:
            for info in socket.getaddrinfo(host, None):
                addr = info[4][0]
                try:
                    candidates.append((ipaddress.ip_address(addr), addr))
                except ValueError:
                    continue
        except OSError:
            # Unresolvable here: not our call to block (Caido will surface the
            # DNS failure), and it cannot reach an internal address anyway.
            return (None, None)

    for ip, _addr in candidates:
        if _ip_is_internal(ip):
            return (
                f"destination {host!r} resolves to internal/link-local/loopback address "
                f"{ip} (RFC1918 / 169.254 metadata / 127.0.0.0/8) and is not in the "
                "authorized target scope; blocked to prevent SSRF against internal "
                "services or the cloud metadata endpoint",
                None,
            )

    # All resolved addresses are external. Pin the first so the connection uses
    # exactly this validated IP (defeats a same-name re-resolution at send time).
    if candidates:
        return (None, candidates[0][1])
    return (None, None)


class _ScopeDeniedError(Exception):
    """Raised when a replay target fails the code-level egress guard."""


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
    logger.exception("%s failed", name)
    return json.dumps(
        {"success": False, "error": f"{name} failed: {exc}"},
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
    """List captured HTTP requests from the Caido proxy with HTTPQL filtering.

    Caido HTTPQL syntax (operators differ by field type):

    - **Integer fields** (``resp.code``, ``req.port``, ``id``,
      ``roundtrip``) — ``eq``, ``gt``, ``gte``, ``lt``, ``lte``, ``ne``.
      Examples: ``resp.code.eq:200``, ``resp.code.gte:400``,
      ``req.port.eq:443``.
    - **Text/byte fields** (``req.method``, ``req.host``, ``req.path``,
      ``req.query``, ``req.ext``, ``req.raw``) — ``regex``, ``cont``
      (substring), ``eq``. Examples: ``req.method.eq:"POST"``,
      ``req.path.cont:"/api/"``, ``req.host.regex:".*\\.example\\.com"``.
    - **Date fields** (``req.created_at``) — ``gt``, ``lt`` with ISO
      timestamps: ``req.created_at.gt:"2024-01-01T00:00:00Z"``.
    - **Combine** with ``AND`` / ``OR``: ``req.method.eq:"POST" AND
      resp.code.gte:400``.
    - **Special**: ``source:intercept`` (only intercepted requests),
      ``preset:"name"``.

    For sitemap-style tree traversal use HTTPQL filters: drill into a
    host with ``req.host.eq:"example.com"`` then narrow paths with
    ``req.path.cont:"/api/"``.

    Pagination is cursor-based. Pass the ``end_cursor`` from the
    ``page_info`` of one call as ``after`` to the next.

    Notes:

    - HTTPQL has **no ``NOT`` operator**. Use the negated form of the
      operator instead: ``ne``, ``ncont``, ``nlike``, ``nregex``
      (e.g. ``req.path.ncont:"/static"`` to exclude static paths).
    - String values **must be quoted**; integer values **must not**.
      ``resp.code.eq:200`` is right; ``resp.code.eq:"200"`` is a parse
      error. Same rule for ``cont`` / ``regex`` strings.
    - A bare quoted string searches both ``req.raw`` and ``resp.raw``,
      handy for sensitive-data sweeps:
      ``"password" OR "secret" OR "api_key"``.

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
        # Security (scope/SSRF egress + DNS-rebinding TOCTOU): the destination URL
        # here is model-controlled (``modifications["url"]``). Validate its host
        # before any bytes go on the wire — deny internal/metadata/loopback
        # targets that are not explicitly in the authorized scope. DNS resolution
        # can block, so run the check off the event loop. The guard returns the
        # exact IP it validated; we pin that IP into the connection so Caido
        # connects to it instead of re-resolving the (possibly rebinding)
        # hostname at send time.
        denied, pinned_ip = await asyncio.to_thread(_screen_destination, modified["url"])
        if denied is not None:
            raise _ScopeDeniedError(denied)
        connection, raw = caido_api.build_raw_request(
            method=modified["method"],
            url=modified["url"],
            headers=modified["headers"],
            body=modified["body"],
            pinned_host=pinned_ip,
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
    except _ScopeDeniedError as exc:
        # Deliberate deny — a clear, model-visible result (not an unexpected error).
        logger.warning("repeat_request blocked out-of-scope destination: %s", exc)
        return json.dumps(
            {
                "success": False,
                "blocked": True,
                "error": f"repeat_request blocked: {exc}",
            },
            ensure_ascii=False,
            default=str,
        )
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
