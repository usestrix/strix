import base64
import os
import re
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
from gql import Client, gql
from gql.transport.exceptions import TransportQueryError
from gql.transport.requests import RequestsHTTPTransport
from requests.exceptions import ProxyError, RequestException, Timeout


if TYPE_CHECKING:
    from collections.abc import Callable


class ProxyManager:
    def __init__(self, auth_token: str | None = None):
        host = "127.0.0.1"
        port = os.getenv("CAIDO_PORT", "56789")
        self.base_url = f"http://{host}:{port}/graphql"
        self.proxies = {"http": f"http://{host}:{port}", "https": f"http://{host}:{port}"}
        self.auth_token = auth_token or os.getenv("CAIDO_API_TOKEN")
        self.transport = RequestsHTTPTransport(
            url=self.base_url, headers={"Authorization": f"Bearer {self.auth_token}"}
        )
        self.client = Client(transport=self.transport, fetch_schema_from_transport=False)

    def list_requests(
        self,
        httpql_filter: str | None = None,
        start_page: int = 1,
        end_page: int = 1,
        page_size: int = 50,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
        scope_id: str | None = None,
    ) -> dict[str, Any]:
        offset = (start_page - 1) * page_size
        limit = (end_page - start_page + 1) * page_size

        sort_mapping = {
            "timestamp": "CREATED_AT",
            "host": "HOST",
            "method": "METHOD",
            "path": "PATH",
            "status_code": "RESP_STATUS_CODE",
            "response_time": "RESP_ROUNDTRIP_TIME",
            "response_size": "RESP_LENGTH",
            "source": "SOURCE",
        }

        query = gql("""
            query GetRequests(
                $limit: Int, $offset: Int, $filter: HTTPQL,
                $order: RequestResponseOrderInput, $scopeId: ID
            ) {
                requestsByOffset(
                    limit: $limit, offset: $offset, filter: $filter,
                    order: $order, scopeId: $scopeId
                ) {
                    edges {
                        node {
                            id method host path query createdAt length isTls port
                            source alteration fileExtension
                            response { id statusCode length roundtripTime createdAt }
                        }
                    }
                    count { value }
                }
            }
        """)

        variables = {
            "limit": limit,
            "offset": offset,
            "filter": httpql_filter,
            "order": {
                "by": sort_mapping.get(sort_by, "CREATED_AT"),
                "ordering": sort_order.upper(),
            },
            "scopeId": scope_id,
        }

        try:
            result = self.client.execute(query, variable_values=variables)
            data = result.get("requestsByOffset", {})
            nodes = [edge["node"] for edge in data.get("edges", [])]

            count_data = data.get("count") or {}
            return {
                "requests": nodes,
                "total_count": count_data.get("value", 0),
                "start_page": start_page,
                "end_page": end_page,
                "page_size": page_size,
                "offset": offset,
                "returned_count": len(nodes),
                "sort_by": sort_by,
                "sort_order": sort_order,
            }
        except (TransportQueryError, ValueError, KeyError) as e:
            return {"requests": [], "total_count": 0, "error": f"Error fetching requests: {e}"}

    def view_request(
        self,
        request_id: str,
        part: str = "request",
        search_pattern: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        queries = {
            "request": """query GetRequest($id: ID!) {
                request(id: $id) {
                    id method host path query createdAt length isTls port
                    source alteration edited raw
                }
            }""",
            "response": """query GetRequest($id: ID!) {
                request(id: $id) {
                    id response {
                        id statusCode length roundtripTime createdAt raw
                    }
                }
            }""",
        }

        if part not in queries:
            return {"error": f"Invalid part '{part}'. Use 'request' or 'response'"}

        try:
            result = self.client.execute(gql(queries[part]), variable_values={"id": request_id})
            request_data = result.get("request", {})

            if not request_data:
                return {"error": f"Request {request_id} not found"}

            if part == "request":
                raw_content = request_data.get("raw")
            else:
                response_data = request_data.get("response") or {}
                raw_content = response_data.get("raw")

            if not raw_content:
                return {"error": "No content available"}

            content = base64.b64decode(raw_content).decode("utf-8", errors="replace")

            if part == "response":
                request_data["response"]["raw"] = content
            else:
                request_data["raw"] = content

            return (
                self._search_content(request_data, content, search_pattern)
                if search_pattern
                else self._paginate_content(request_data, content, page, page_size)
            )

        except (TransportQueryError, ValueError, KeyError, UnicodeDecodeError) as e:
            return {"error": f"Failed to view request: {e}"}

    def _search_content(
        self, request_data: dict[str, Any], content: str, pattern: str
    ) -> dict[str, Any]:
        try:
            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            matches = []

            for match in regex.finditer(content):
                start, end = match.start(), match.end()
                context_size = 120

                before = re.sub(r"\s+", " ", content[max(0, start - context_size) : start].strip())[
                    -100:
                ]
                after = re.sub(r"\s+", " ", content[end : end + context_size].strip())[:100]

                matches.append(
                    {"match": match.group(), "before": before, "after": after, "position": start}
                )

                if len(matches) >= 20:
                    break

            return {
                "id": request_data.get("id"),
                "matches": matches,
                "total_matches": len(matches),
                "search_pattern": pattern,
                "truncated": len(matches) >= 20,
            }
        except re.error as e:
            return {"error": f"Invalid regex: {e}"}

    def _paginate_content(
        self, request_data: dict[str, Any], content: str, page: int, page_size: int
    ) -> dict[str, Any]:
        display_lines = []
        for line in content.split("\n"):
            if len(line) <= 80:
                display_lines.append(line)
            else:
                display_lines.extend(
                    [
                        line[i : i + 80] + (" \\" if i + 80 < len(line) else "")
                        for i in range(0, len(line), 80)
                    ]
                )

        total_lines = len(display_lines)
        total_pages = (total_lines + page_size - 1) // page_size
        page = max(1, min(page, total_pages))

        start_line = (page - 1) * page_size
        end_line = min(total_lines, start_line + page_size)

        return {
            "id": request_data.get("id"),
            "content": "\n".join(display_lines[start_line:end_line]),
            "page": page,
            "total_pages": total_pages,
            "showing_lines": f"{start_line + 1}-{end_line} of {total_lines}",
            "has_more": page < total_pages,
        }

    def send_simple_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str = "",
        timeout: int = 30,
    ) -> dict[str, Any]:
        if headers is None:
            headers = {}
        try:
            start_time = time.time()
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body or None,
                proxies=self.proxies,
                timeout=timeout,
                verify=False,
            )
            response_time = int((time.time() - start_time) * 1000)

            body_content = response.text
            if len(body_content) > 10000:
                body_content = body_content[:10000] + "\n... [truncated]"

            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": body_content,
                "response_time_ms": response_time,
                "url": response.url,
                "message": (
                    "Request sent through proxy - check list_requests() for captured traffic"
                ),
            }
        except (RequestException, ProxyError, Timeout) as e:
            return {"error": f"Request failed: {type(e).__name__}", "details": str(e), "url": url}

    def repeat_request(
        self, request_id: str, modifications: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if modifications is None:
            modifications = {}

        original = self.view_request(request_id, "request")
        if "error" in original:
            return {"error": f"Could not retrieve original request: {original['error']}"}

        raw_content = original.get("content", "")
        if not raw_content:
            return {"error": "No raw request content found"}

        request_components = self._parse_http_request(raw_content)
        if "error" in request_components:
            return request_components

        full_url = self._build_full_url(request_components, modifications)
        if "error" in full_url:
            return full_url

        modified_request = self._apply_modifications(
            request_components, modifications, full_url["url"]
        )

        return self._send_modified_request(modified_request, request_id, modifications)

    def _parse_http_request(self, raw_content: str) -> dict[str, Any]:
        lines = raw_content.split("\n")
        request_line = lines[0].strip().split(" ")
        if len(request_line) < 2:
            return {"error": "Invalid request line format"}

        method, url_path = request_line[0], request_line[1]

        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == "":
                body_start = i + 1
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()

        body = "\n".join(lines[body_start:]).strip() if body_start < len(lines) else ""

        return {"method": method, "url_path": url_path, "headers": headers, "body": body}

    def _build_full_url(
        self, components: dict[str, Any], modifications: dict[str, Any]
    ) -> dict[str, Any]:
        headers = components["headers"]
        host = headers.get("Host", "")
        if not host:
            return {"error": "No Host header found"}

        protocol = (
            "https" if ":443" in host or "https" in headers.get("Referer", "").lower() else "http"
        )
        full_url = f"{protocol}://{host}{components['url_path']}"

        if "url" in modifications:
            full_url = modifications["url"]

        return {"url": full_url}

    def _apply_modifications(
        self, components: dict[str, Any], modifications: dict[str, Any], full_url: str
    ) -> dict[str, Any]:
        headers = components["headers"].copy()
        body = components["body"]
        final_url = full_url

        if "params" in modifications:
            parsed = urlparse(final_url)
            params = {k: v[0] if v else "" for k, v in parse_qs(parsed.query).items()}
            params.update(modifications["params"])
            final_url = urlunparse(parsed._replace(query=urlencode(params)))

        if "headers" in modifications:
            headers.update(modifications["headers"])

        if "body" in modifications:
            body = modifications["body"]

        if "cookies" in modifications:
            cookies = {}
            if headers.get("Cookie"):
                for cookie in headers["Cookie"].split(";"):
                    if "=" in cookie:
                        k, v = cookie.split("=", 1)
                        cookies[k.strip()] = v.strip()
            cookies.update(modifications["cookies"])
            headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])

        return {
            "method": components["method"],
            "url": final_url,
            "headers": headers,
            "body": body,
        }

    def _send_modified_request(
        self, request_data: dict[str, Any], request_id: str, modifications: dict[str, Any]
    ) -> dict[str, Any]:
        try:
            start_time = time.time()
            response = requests.request(
                method=request_data["method"],
                url=request_data["url"],
                headers=request_data["headers"],
                data=request_data["body"] or None,
                proxies=self.proxies,
                timeout=30,
                verify=False,
            )
            response_time = int((time.time() - start_time) * 1000)

            response_body = response.text
            truncated = len(response_body) > 10000
            if truncated:
                response_body = response_body[:10000] + "\n... [truncated]"

            return {
                "status_code": response.status_code,
                "status_text": response.reason,
                "headers": {
                    k: v
                    for k, v in response.headers.items()
                    if k.lower()
                    in ["content-type", "content-length", "server", "set-cookie", "location"]
                },
                "body": response_body,
                "body_truncated": truncated,
                "body_size": len(response.content),
                "response_time_ms": response_time,
                "url": response.url,
                "original_request_id": request_id,
                "modifications_applied": modifications,
                "request": {
                    "method": request_data["method"],
                    "url": request_data["url"],
                    "headers": request_data["headers"],
                    "has_body": bool(request_data["body"]),
                },
            }

        except ProxyError as e:
            return {
                "error": "Proxy connection failed - is Caido running?",
                "details": str(e),
                "original_request_id": request_id,
            }
        except (RequestException, Timeout) as e:
            return {
                "error": f"Failed to repeat request: {type(e).__name__}",
                "details": str(e),
                "original_request_id": request_id,
            }

    def _handle_scope_list(self) -> dict[str, Any]:
        result = self.client.execute(gql("query { scopes { id name allowlist denylist indexed } }"))
        scopes = result.get("scopes", [])
        return {"scopes": scopes, "count": len(scopes)}

    def _handle_scope_get(self, scope_id: str | None) -> dict[str, Any]:
        if not scope_id:
            return self._handle_scope_list()

        result = self.client.execute(
            gql(
                "query GetScope($id: ID!) { scope(id: $id) { id name allowlist denylist indexed } }"
            ),
            variable_values={"id": scope_id},
        )
        scope = result.get("scope")
        if not scope:
            return {"error": f"Scope {scope_id} not found"}
        return {"scope": scope}

    def _handle_scope_create(
        self, scope_name: str, allowlist: list[str] | None, denylist: list[str] | None
    ) -> dict[str, Any]:
        if not scope_name:
            return {"error": "scope_name required for create"}

        mutation = gql("""
            mutation CreateScope($input: CreateScopeInput!) {
                createScope(input: $input) {
                    scope { id name allowlist denylist indexed }
                    error {
                        ... on InvalidGlobTermsUserError { code terms }
                        ... on OtherUserError { code }
                    }
                }
            }
        """)

        result = self.client.execute(
            mutation,
            variable_values={
                "input": {
                    "name": scope_name,
                    "allowlist": allowlist or [],
                    "denylist": denylist or [],
                }
            },
        )

        payload = result.get("createScope", {})
        if payload.get("error"):
            error = payload["error"]
            return {"error": f"Invalid glob patterns: {error.get('terms', error.get('code'))}"}

        return {"scope": payload.get("scope"), "message": "Scope created successfully"}

    def _handle_scope_update(
        self,
        scope_id: str,
        scope_name: str,
        allowlist: list[str] | None,
        denylist: list[str] | None,
    ) -> dict[str, Any]:
        if not scope_id or not scope_name:
            return {"error": "scope_id and scope_name required"}

        mutation = gql("""
            mutation UpdateScope($id: ID!, $input: UpdateScopeInput!) {
                updateScope(id: $id, input: $input) {
                    scope { id name allowlist denylist indexed }
                    error {
                        ... on InvalidGlobTermsUserError { code terms }
                        ... on OtherUserError { code }
                    }
                }
            }
        """)

        result = self.client.execute(
            mutation,
            variable_values={
                "id": scope_id,
                "input": {
                    "name": scope_name,
                    "allowlist": allowlist or [],
                    "denylist": denylist or [],
                },
            },
        )

        payload = result.get("updateScope", {})
        if payload.get("error"):
            error = payload["error"]
            return {"error": f"Invalid glob patterns: {error.get('terms', error.get('code'))}"}

        return {"scope": payload.get("scope"), "message": "Scope updated successfully"}

    def _handle_scope_delete(self, scope_id: str) -> dict[str, Any]:
        if not scope_id:
            return {"error": "scope_id required for delete"}

        result = self.client.execute(
            gql("mutation DeleteScope($id: ID!) { deleteScope(id: $id) { deletedId } }"),
            variable_values={"id": scope_id},
        )

        payload = result.get("deleteScope", {})
        if not payload.get("deletedId"):
            return {"error": f"Failed to delete scope {scope_id}"}
        return {"message": f"Scope {scope_id} deleted", "deletedId": payload["deletedId"]}

    def scope_rules(
        self,
        action: str,
        allowlist: list[str] | None = None,
        denylist: list[str] | None = None,
        scope_id: str | None = None,
        scope_name: str | None = None,
    ) -> dict[str, Any]:
        handlers: dict[str, Callable[[], dict[str, Any]]] = {
            "list": self._handle_scope_list,
            "get": lambda: self._handle_scope_get(scope_id),
            "create": lambda: (
                {"error": "scope_name required for create"}
                if not scope_name
                else self._handle_scope_create(scope_name, allowlist, denylist)
            ),
            "update": lambda: (
                {"error": "scope_id and scope_name required"}
                if not scope_id or not scope_name
                else self._handle_scope_update(scope_id, scope_name, allowlist, denylist)
            ),
            "delete": lambda: (
                {"error": "scope_id required for delete"}
                if not scope_id
                else self._handle_scope_delete(scope_id)
            ),
        }

        handler = handlers.get(action)
        if not handler:
            return {
                "error": f"Unsupported action: {action}. Use 'get', 'list', 'create', "
                f"'update', or 'delete'"
            }

        try:
            result = handler()
        except (TransportQueryError, ValueError, KeyError) as e:
            return {"error": f"Scope operation failed: {e}"}
        else:
            return result

    def list_sitemap(
        self,
        scope_id: str | None = None,
        parent_id: str | None = None,
        depth: str = "DIRECT",
        page: int = 1,
        page_size: int = 30,
    ) -> dict[str, Any]:
        try:
            skip_count = (page - 1) * page_size

            if parent_id:
                query = gql("""
                    query GetSitemapDescendants($parentId: ID!, $depth: SitemapDescendantsDepth!) {
                        sitemapDescendantEntries(parentId: $parentId, depth: $depth) {
                            edges {
                                node {
                                    id kind label hasDescendants
                                    request { method path response { statusCode } }
                                }
                            }
                            count { value }
                        }
                    }
                """)
                result = self.client.execute(
                    query, variable_values={"parentId": parent_id, "depth": depth}
                )
                data = result.get("sitemapDescendantEntries", {})
            else:
                query = gql("""
                    query GetSitemapRoots($scopeId: ID) {
                        sitemapRootEntries(scopeId: $scopeId) {
                            edges { node {
                                id kind label hasDescendants
                                metadata { ... on SitemapEntryMetadataDomain { isTls port } }
                                request { method path response { statusCode } }
                            } }
                            count { value }
                        }
                    }
                """)
                result = self.client.execute(query, variable_values={"scopeId": scope_id})
                data = result.get("sitemapRootEntries", {})

            all_nodes = [edge["node"] for edge in data.get("edges", [])]
            count_data = data.get("count") or {}
            total_count = count_data.get("value", 0)

            paginated_nodes = all_nodes[skip_count : skip_count + page_size]
            cleaned_nodes = []

            for node in paginated_nodes:
                cleaned = {
                    "id": node["id"],
                    "kind": node["kind"],
                    "label": node["label"],
                    "hasDescendants": node["hasDescendants"],
                }

                if node.get("metadata") and (
                    node["metadata"].get("isTls") is not None or node["metadata"].get("port")
                ):
                    cleaned["metadata"] = node["metadata"]

                if node.get("request"):
                    req = node["request"]
                    cleaned_req = {}
                    if req.get("method"):
                        cleaned_req["method"] = req["method"]
                    if req.get("path"):
                        cleaned_req["path"] = req["path"]
                    response_data = req.get("response") or {}
                    if response_data.get("statusCode"):
                        cleaned_req["status"] = response_data["statusCode"]
                    if cleaned_req:
                        cleaned["request"] = cleaned_req

                cleaned_nodes.append(cleaned)

            total_pages = (total_count + page_size - 1) // page_size

            return {
                "entries": cleaned_nodes,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "total_count": total_count,
                "has_more": page < total_pages,
                "showing": (
                    f"{skip_count + 1}-{min(skip_count + page_size, total_count)} of {total_count}"
                ),
            }

        except (TransportQueryError, ValueError, KeyError) as e:
            return {"error": f"Failed to fetch sitemap: {e}"}

    def _process_sitemap_metadata(self, node: dict[str, Any]) -> dict[str, Any]:
        cleaned = {
            "id": node["id"],
            "kind": node["kind"],
            "label": node["label"],
            "hasDescendants": node["hasDescendants"],
        }

        if node.get("metadata") and (
            node["metadata"].get("isTls") is not None or node["metadata"].get("port")
        ):
            cleaned["metadata"] = node["metadata"]

        return cleaned

    def _process_sitemap_request(self, req: dict[str, Any]) -> dict[str, Any] | None:
        cleaned_req = {}
        if req.get("method"):
            cleaned_req["method"] = req["method"]
        if req.get("path"):
            cleaned_req["path"] = req["path"]
        response_data = req.get("response") or {}
        if response_data.get("statusCode"):
            cleaned_req["status"] = response_data["statusCode"]
        return cleaned_req if cleaned_req else None

    def _process_sitemap_response(self, resp: dict[str, Any]) -> dict[str, Any]:
        cleaned_resp = {}
        if resp.get("statusCode"):
            cleaned_resp["status"] = resp["statusCode"]
        if resp.get("length"):
            cleaned_resp["size"] = resp["length"]
        if resp.get("roundtripTime"):
            cleaned_resp["time_ms"] = resp["roundtripTime"]
        return cleaned_resp

    def view_sitemap_entry(self, entry_id: str) -> dict[str, Any]:
        try:
            query = gql("""
                query GetSitemapEntry($id: ID!) {
                    sitemapEntry(id: $id) {
                        id kind label hasDescendants
                        metadata { ... on SitemapEntryMetadataDomain { isTls port } }
                        request { method path response { statusCode length roundtripTime } }
                        requests(first: 30, order: {by: CREATED_AT, ordering: DESC}) {
                            edges { node { method path response { statusCode length } } }
                            count { value }
                        }
                    }
                }
            """)

            result = self.client.execute(query, variable_values={"id": entry_id})
            entry = result.get("sitemapEntry")

            if not entry:
                return {"error": f"Sitemap entry {entry_id} not found"}

            cleaned = self._process_sitemap_metadata(entry)

            if entry.get("request"):
                req = entry["request"]
                cleaned_req = {}
                if req.get("method"):
                    cleaned_req["method"] = req["method"]
                if req.get("path"):
                    cleaned_req["path"] = req["path"]
                if req.get("response"):
                    cleaned_req["response"] = self._process_sitemap_response(req["response"])
                if cleaned_req:
                    cleaned["request"] = cleaned_req

            requests_data = entry.get("requests", {})
            request_nodes = [edge["node"] for edge in requests_data.get("edges", [])]

            cleaned_requests = [
                req
                for req in (self._process_sitemap_request(node) for node in request_nodes)
                if req is not None
            ]

            count_data = requests_data.get("count") or {}
            cleaned["related_requests"] = {
                "requests": cleaned_requests,
                "total_count": count_data.get("value", 0),
                "showing": f"Latest {len(cleaned_requests)} requests",
            }

            return {"entry": cleaned} if cleaned else {"error": "Failed to process sitemap entry"}  # noqa: TRY300

        except (TransportQueryError, ValueError, KeyError) as e:
            return {"error": f"Failed to fetch sitemap entry: {e}"}

    def close(self) -> None:
        pass


_PROXY_MANAGER: ProxyManager | None = None


def get_proxy_manager() -> ProxyManager:
    if _PROXY_MANAGER is None:
        return ProxyManager()
    return _PROXY_MANAGER
