"""Regression tests for tool failures that recurred across production scans."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from caido_sdk_client.errors.graphql import OperationUserError

from strix.skills import resolve_requested_skills, validate_requested_skills
from strix.tools.proxy import caido_api
from strix.tools.proxy import tools as proxy_tools
from strix.tools.reporting.tool import _validate_identifiers
from strix.tools.web_search import tool as web_tool


def test_gql_execute_timeout_is_raised_above_the_ten_second_default() -> None:
    gql_client = SimpleNamespace(execute_timeout=10)
    client: Any = SimpleNamespace(graphql=SimpleNamespace(_http_client=gql_client))

    caido_api.extend_graphql_timeout(client)

    assert gql_client.execute_timeout == caido_api.GRAPHQL_TIMEOUT_SECONDS


def test_a_proxy_timeout_is_reported_as_a_timeout_not_an_empty_source() -> None:
    # What the SDK raises when gql's execute timeout fires: both messages empty.
    exc = OperationUserError("").with_source(TimeoutError())
    assert str(exc).strip() == "Source:"

    error = json.loads(proxy_tools._err("list_requests", exc))["error"]

    assert "did not answer in time" in error
    assert "Source:" not in error


def test_a_messageless_wrapped_error_names_its_type() -> None:
    exc = OperationUserError("").with_source(ConnectionResetError())

    assert "ConnectionResetError" in proxy_tools._describe(exc)


async def test_a_read_only_proxy_call_is_sent_once_more_after_a_timeout() -> None:
    gql_client = SimpleNamespace(execute_timeout=10)
    client: Any = SimpleNamespace(graphql=SimpleNamespace(_http_client=gql_client))
    calls: list[int] = []

    async def flaky(_client: Any) -> str:
        calls.append(gql_client.execute_timeout)
        if len(calls) == 1:
            raise OperationUserError("").with_source(TimeoutError())
        return "ok"

    assert await proxy_tools._call(client, flaky, read_only=True, timeout=20) == "ok"
    assert calls == [20, 20]


async def test_a_call_that_sends_traffic_is_not_repeated_after_a_timeout() -> None:
    client: Any = SimpleNamespace(graphql=SimpleNamespace(_http_client=SimpleNamespace()))
    calls: list[int] = []

    async def replay(_client: Any) -> str:
        calls.append(1)
        raise OperationUserError("").with_source(TimeoutError())

    with pytest.raises(OperationUserError):
        await proxy_tools._call(client, replay)
    assert calls == [1]


async def test_an_invalid_filter_is_not_retried_and_is_reported_once() -> None:
    client: Any = SimpleNamespace(graphql=SimpleNamespace(_http_client=SimpleNamespace()))
    calls: list[int] = []
    detail = "{'message': 'Invalid HTTPQL query'}"

    async def bad_filter(_client: Any) -> str:
        calls.append(1)
        raise OperationUserError(detail).with_source(detail)

    with pytest.raises(OperationUserError) as caught:
        await proxy_tools._call(client, bad_filter, read_only=True)
    assert calls == [1]
    assert proxy_tools._describe(caught.value) == detail


async def test_request_summaries_query_asks_for_no_raw_bytes() -> None:
    seen: dict[str, Any] = {}

    async def query(document: str, variables: dict[str, Any]) -> dict[str, Any]:
        seen.update(document=document, variables=variables)
        return {"requests": {"edges": [], "pageInfo": {}}}

    client: Any = SimpleNamespace(graphql=SimpleNamespace(query=query))
    await caido_api.list_request_summaries_with_client(
        client, httpql_filter='req.host.cont:"x"', sort_by="status_code", sort_order="asc"
    )

    assert "raw" not in seen["document"]
    assert seen["variables"]["filter"] == {"code": 'req.host.cont:"x"'}
    assert seen["variables"]["order"] == {"by": "RESP_STATUS_CODE", "ordering": "ASC"}


@pytest.mark.parametrize(
    ("cve", "cwe", "expected"),
    [
        ("null", "CWE-79", (None, "CWE-79")),
        ("N/A", None, (None, None)),
        ("CWE-863", None, (None, "CWE-863")),
        ("CWE-91", "CWE-79", (None, "CWE-79")),
        ("CVE-2024-12345", "CWE-79", ("CVE-2024-12345", "CWE-79")),
    ],
)
def test_placeholder_and_misplaced_identifiers_are_not_rejected(
    cve: str, cwe: str | None, expected: tuple[str | None, str | None]
) -> None:
    assert _validate_identifiers(cve, cwe) == (*expected, [])


def test_a_malformed_cve_is_still_rejected() -> None:
    assert _validate_identifiers("CVE-24-1", None)[2]


def test_a_wrong_category_resolves_to_the_exact_skill_name() -> None:
    resolved = resolve_requested_skills(["technologies/nextjs", "vulnerabilities/idor"])

    assert resolved == ["nextjs", "vulnerabilities/idor"]
    assert validate_requested_skills(resolved) is None


def test_a_misspelled_skill_name_is_rejected_with_a_suggestion() -> None:
    assert resolve_requested_skills(["tooling/nuklei", "bogus"]) == ["tooling/nuklei", "bogus"]

    error = validate_requested_skills(["tooling/nuklei"])

    assert error is not None
    assert "Did you mean: {'tooling/nuklei': ['nuclei']}?" in error
    assert "Did you mean" not in (validate_requested_skills(["bogus"]) or "")


def test_page_fetch_with_no_content_reports_why_and_does_not_say_try_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def post(_key: str, endpoint: str, _payload: dict[str, Any], **_kw: Any) -> dict[str, Any]:
        calls.append(endpoint)
        return {
            "results": [],
            "statuses": [
                {
                    "id": "https://x.test/a",
                    "status": "error",
                    "error": {"tag": "CRAWL_NOT_FOUND", "httpStatusCode": 404},
                }
            ],
        }

    monkeypatch.setattr(web_tool, "_exa_post", post)
    settings = SimpleNamespace(
        integrations=SimpleNamespace(exa_api_key="k", web_search_provider="exa")
    )
    monkeypatch.setattr(web_tool, "load_settings", lambda: settings)

    result = web_tool._do_get_contents(["https://x.test/a"])

    assert result["success"] is False
    assert "CRAWL_NOT_FOUND (HTTP 404)" in result["error"]
    assert "Try again" not in result["error"]
    assert len(calls) == 1  # a permanent failure is not retried


def test_page_fetch_retries_once_when_the_failure_may_be_transient(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bodies = [
        {"results": [], "statuses": []},
        {"results": [{"url": "https://x.test/a", "title": "T", "text": "hello"}]},
    ]
    monkeypatch.setattr(web_tool, "_exa_post", lambda *_a, **_k: bodies.pop(0))

    text, fetched = web_tool._exa_page_text("k", ["https://x.test/a"])

    assert "hello" in text
    assert fetched == {"https://x.test/a"}


async def test_a_read_only_proxy_call_fits_two_attempts_inside_the_tool_deadline() -> None:
    gql_client = SimpleNamespace(execute_timeout=10)
    client: Any = SimpleNamespace(graphql=SimpleNamespace(_http_client=gql_client))
    seen: list[int] = []

    async def read(_client: Any) -> str:
        seen.append(gql_client.execute_timeout)
        return "ok"

    await proxy_tools._call(client, read, read_only=True)
    await proxy_tools._call(client, read)

    await proxy_tools._call(client, read, read_only=True)
    assert gql_client.execute_timeout == caido_api.GRAPHQL_TIMEOUT_SECONDS  # restored
    seen.pop()
    assert seen == [caido_api.GRAPHQL_READ_TIMEOUT_SECONDS, caido_api.GRAPHQL_TIMEOUT_SECONDS]
    assert 2 * caido_api.GRAPHQL_READ_TIMEOUT_SECONDS < 60


def test_page_fetch_attempts_share_one_time_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [0.0]
    timeouts: list[float] = []
    elapsed = [200.0]

    def post(*_a: Any, timeout: float) -> dict[str, Any]:
        timeouts.append(timeout)
        clock[0] += elapsed[0]
        return {"results": [], "statuses": []}

    monkeypatch.setattr("time.monotonic", lambda: clock[0])
    monkeypatch.setattr(web_tool, "_exa_post", post)

    with pytest.raises(web_tool._NoPageContentError):
        web_tool._exa_page_text("k", ["https://x.test/a"])
    assert timeouts == [300, 100]

    clock[0], elapsed[0] = 0.0, 290.0
    timeouts.clear()
    with pytest.raises(web_tool._NoPageContentError):
        web_tool._exa_page_text("k", ["https://x.test/a"])
    assert timeouts == [300]  # too little time left to retry
