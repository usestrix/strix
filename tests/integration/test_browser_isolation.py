import pytest

from . import console as ui
from .helpers import Fail, act_parallel


pytestmark = [pytest.mark.integration, pytest.mark.browsers(2)]


def test_session_objects_are_distinct(browsers):
    from strix.tools.browser.browser_manager import _manager

    a, b = browsers
    session_a = _manager.sessions.get(a._agent_id)
    session_b = _manager.sessions.get(b._agent_id)

    if not session_a or not session_b:
        Fail().error("one or both sessions missing from manager")
        return
    if session_a is session_b:
        Fail().error("both agents share the same session object")
    if session_a.browser_context_id == session_b.browser_context_id:
        Fail().expected("different browser_context_ids").got(
            f"A={session_a.browser_context_id}, B={session_b.browser_context_id}"
        )


def test_parallel_navigate_isolated(browsers):
    a, b = browsers
    ui.status("isolation → navigating both agents concurrently")
    result_a, result_b = act_parallel(
        [
            (a, {"action": "navigate", "url": "https://example.com"}),
            (b, {"action": "navigate", "url": "https://www.iana.org"}),
        ]
    )
    ui.log(f"agent A → {result_a.get('url')}")
    ui.log(f"agent B → {result_b.get('url')}")

    if "example.com" not in result_a.get("url", ""):
        Fail(result_a).expected("url containing 'example.com'").got(result_a.get("url"))
    if "iana.org" not in result_b.get("url", ""):
        Fail(result_b).expected("url containing 'iana.org'").got(result_b.get("url"))

    state_a, state_b = act_parallel(
        [
            (a, {"action": "screenshot"}),
            (b, {"action": "screenshot"}),
        ]
    )

    if "example.com" not in state_a.get("url", ""):
        Fail(state_a).expected("agent A still on example.com").got(state_a.get("url"))
    if "iana.org" not in state_b.get("url", ""):
        Fail(state_b).expected("agent B still on iana.org").got(state_b.get("url"))


def test_cookie_isolation(browsers):
    a, b = browsers
    a.navigate(url="https://example.com")
    a.evaluate(code="document.cookie = 'agent=A; path=/'")

    b.navigate(url="https://example.com")
    result_b = b.evaluate(code="document.cookie")
    cookie_b = str(result_b.get("result", ""))
    ui.log(f"agent B cookies: {cookie_b}")

    if "agent=A" in cookie_b:
        Fail(result_b).expected("no cookie leakage").got(cookie_b)

    result_a = a.evaluate(code="document.cookie")
    cookie_a = str(result_a.get("result", ""))
    ui.log(f"agent A cookies: {cookie_a}")

    if "agent=A" not in cookie_a:
        Fail(result_a).expected("cookie 'agent=A' present").got(cookie_a)


def test_concurrent_mixed_actions(browsers):
    a, b = browsers
    a.navigate(url="https://example.com")
    b.navigate(url="https://www.iana.org")

    ui.status("isolation → mixed actions concurrently")
    results = act_parallel(
        [
            (a, {"action": "scroll", "direction": "down", "amount": 3}),
            (b, {"action": "screenshot"}),
            (a, {"action": "screenshot"}),
            (b, {"action": "evaluate", "code": "document.title"}),
        ]
    )

    for r in results:
        if "error" in r:
            Fail(r).error(r["error"])
