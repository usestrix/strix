from concurrent.futures import ThreadPoolExecutor

import pytest

from . import console as ui
from .helpers import Browser, Fail, act_parallel


pytestmark = [pytest.mark.integration, pytest.mark.browsers(2)]


def test_session_objects_are_distinct(browsers: list[Browser]) -> None:
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


def test_parallel_navigate_isolated(browsers: list[Browser]) -> None:
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


def test_cookie_isolation(browsers: list[Browser]) -> None:
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


def test_concurrent_mixed_actions(browsers: list[Browser]) -> None:
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


def test_session_close_does_not_affect_other(browsers: list[Browser]) -> None:
    a, b = browsers
    a.navigate(url="https://example.com")
    b.navigate(url="https://www.iana.org")

    a.close_browser()
    ui.log("agent A closed")

    result = b.navigate(url="https://example.com")
    ui.log(f"agent B navigation result: {result}")
    if "error" in result:
        Fail(result).error(f"agent B broken after A closed: {result['error']}")
    if "example.com" not in result.get("url", ""):
        Fail(result).expected("url containing 'example.com'").got(result.get("url"))


def test_relaunch_parallel_no_side_effects(browsers: list[Browser]) -> None:
    a, b = browsers
    a.navigate(url="https://example.com")
    b.navigate(url="https://www.iana.org")

    # close A, verify B is unaffected
    a.close_browser()
    b_check = b.screenshot()
    if "iana.org" not in b_check.get("url", ""):
        Fail(b_check).expected("agent B still on iana.org").got(b_check.get("url"))

    # relaunch A
    a.launch()
    a.navigate(url="https://example.com")

    # parallel actions on both after relaunch
    results = act_parallel(
        [
            (a, {"action": "evaluate", "code": "document.title"}),
            (b, {"action": "evaluate", "code": "document.title"}),
            (a, {"action": "screenshot"}),
            (b, {"action": "screenshot"}),
        ]
    )

    for r in results:
        if "error" in r:
            Fail(r).error(r["error"])

    # verify no cross-contamination after relaunch (use url, titles vary)
    a_state, b_state = results[2], results[3]
    if "example.com" not in a_state.get("url", ""):
        Fail(a_state).expected("agent A on example.com").got(a_state.get("url"))
    if "iana.org" not in b_state.get("url", ""):
        Fail(b_state).expected("agent B on iana.org").got(b_state.get("url"))


def test_dialog_does_not_block_other_agent(browsers: list[Browser]) -> None:
    a, b = browsers
    a.navigate(url="https://example.com")
    b.navigate(url="https://example.com")

    a._call("evaluate", code="setTimeout(() => alert('blocked'), 0)")

    result = b._call("evaluate", code="document.title")
    ui.log(f"agent B after A's alert: {result}")
    if "error" in result:
        Fail(result).error(f"agent B blocked by A's dialog: {result['error']}")


def test_close_during_active_operation(browsers: list[Browser]) -> None:
    a, b = browsers
    a.navigate(url="https://example.com")
    b.navigate(url="https://example.com")

    def slow_b():
        return b._call(
            "evaluate", code="new Promise(r => setTimeout(() => r(document.title), 2000))"
        )

    def close_a():
        import time

        time.sleep(0.5)
        return a._call("close_browser")

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_b = pool.submit(slow_b)
        fut_a = pool.submit(close_a)
        fut_a.result(timeout=10)
        result_b = fut_b.result(timeout=10)

    ui.log(f"agent B after A closed mid-action: {result_b}")
    if "error" in result_b:
        Fail(result_b).error(f"agent B broke when A closed mid-action: {result_b['error']}")


def test_concurrent_context_disposal(browsers: list[Browser]) -> None:
    a, b = browsers
    a.navigate(url="https://example.com")
    b.navigate(url="https://example.com")

    def dispose_a():
        return a._call("close_browser")

    def new_tab_b():
        return b._call(
            "evaluate", code="window.open('https://example.com', '_blank'); document.title"
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(dispose_a)
        fut_b = pool.submit(new_tab_b)
        fut_a.result(timeout=10)
        result_b = fut_b.result(timeout=10)

    ui.log(f"agent B after concurrent disposal: {result_b}")
    if "error" in result_b:
        Fail(result_b).error(f"B's tab creation broke during A's disposal: {result_b['error']}")


def test_duplicate_launch_race(browsers: list[Browser]) -> None:
    a, _ = browsers
    a.close_browser()

    def launch():
        return a._call("launch")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [f.result(timeout=30) for f in [pool.submit(launch), pool.submit(launch)]]

    ui.log(f"race launch results: {[r.get('message') for r in results]}")
    for r in results:
        if "error" in r:
            Fail(r).error(f"race launch failed: {r['error']}")

    result = a._call("navigate", url="https://example.com")
    if "error" in result:
        Fail(result).error(f"session unusable after race: {result['error']}")
    if "example.com" not in result.get("url", ""):
        Fail(result).expected("url containing 'example.com'").got(result.get("url"))
