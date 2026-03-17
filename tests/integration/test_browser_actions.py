import pytest

from . import console as ui
from .helpers import Fail


pytestmark = pytest.mark.integration


def test_navigate(browser):
    ui.status("test_navigate → example.com")
    result = browser.navigate(url="https://example.com")
    ui.log(f"navigate → url={result.get('url')} title={result.get('title')}")

    if "example.com" not in result.get("url", "").lower():
        Fail(result).expected("url containing 'example.com'").got(result.get("url"))
    if "example" not in result.get("title", "").lower():
        Fail(result).expected("title containing 'example'").got(result.get("title"))


def test_click(browser):
    ui.status("test_click → example.com link")
    browser.navigate(url="https://example.com")

    result = browser.click(index=1)
    ui.log(f"click → url={result.get('url')}")


def test_go_back(browser):
    ui.status("test_go_back → navigate to iana.org, then back")
    browser.navigate(url="https://example.com")
    browser.navigate(url="https://www.iana.org")

    result = browser.go_back()
    url = result.get("url", "")
    ui.log(f"go_back → url={url}")

    if "example.com" not in url.lower():
        Fail(result).expected("url containing 'example.com'").got(url)


def test_scroll(browser):
    ui.status("test_scroll → example.com")
    browser.navigate(url="https://example.com")

    result = browser.scroll(direction="down", amount=3)
    result_keys = list(result.keys()) if isinstance(result, dict) else type(result)
    ui.log(f"scroll → {result_keys}")


def test_extract(browser):
    ui.status("test_extract → example.com")
    browser.navigate(url="https://example.com")

    result = browser.extract(query="What is on this page?")
    ui.log(f"extract → {str(result)[:120]}")

    if "example" not in str(result).lower():
        Fail(result).expected("content containing 'example'").got(str(result)[:200])


def test_find_text(browser):
    ui.status("test_find_text → 'example'")
    browser.navigate(url="https://example.com")

    result = browser.find_text(text="example")
    result_keys = list(result.keys()) if isinstance(result, dict) else type(result)
    ui.log(f"find_text → {result_keys}")


def test_evaluate(browser):
    ui.status("test_evaluate → document.title")
    browser.navigate(url="https://example.com")

    result = browser.evaluate(code="document.title")
    ui.log(f"evaluate → {str(result)[:120]}")

    if "example" not in str(result).lower():
        Fail(result).expected("result containing 'example'").got(str(result)[:200])


def test_screenshot(browser):
    ui.status("test_screenshot → example.com")
    browser.navigate(url="https://example.com")

    result = browser.screenshot()
    ui.log(f"screenshot → {result.get('screenshot')}")

    if result.get("screenshot") != "[Image]":
        Fail(result).error("expected screenshot in response")


def test_input(browser):
    ui.status("test_input → example.com")
    browser.navigate(url="https://example.com")

    result = browser.input(index=1, text="integration test")
    result_keys = list(result.keys()) if isinstance(result, dict) else type(result)
    ui.log(f"input → {result_keys}")


def test_send_keys(browser):
    ui.status("test_send_keys → Tab")
    browser.navigate(url="https://example.com")

    result = browser.send_keys(keys="Tab")
    result_keys = list(result.keys()) if isinstance(result, dict) else type(result)
    ui.log(f"send_keys → {result_keys}")


def test_run(browser):
    ui.status("test_run → asking agent to read example.com title")
    browser.navigate(url="https://example.com")

    result = browser.run(task="What is the title of this page? Return only the title text.")
    ui.log(f"run → {str(result.get('result', ''))[:120]}")

    if "example" not in str(result.get("result", "")).lower():
        Fail(result).expected("result containing 'example'").got(
            str(result.get("result", ""))[:200]
        )


def _tab_id(tab_info):
    return getattr(tab_info, "target_id", "")[-4:]


def test_switch_and_close_tab(browser):
    ui.status("test_switch_and_close_tab → open, switch, close")
    result = browser.navigate(url="https://example.com")
    tabs = result.get("tabs", [])
    original = _tab_id(tabs[0]) if tabs else None

    ui.status("test_switch_and_close_tab → opening new tab")
    result = browser.evaluate(code="window.open('https://example.com', '_blank')")
    tabs = result.get("tabs", [])
    ui.log(f"obtained tabs {tabs}")
    new = _tab_id(tabs[-1]) if tabs else None

    if new:
        ui.status("test_switch_and_close_tab → switching to new tab")
        result = browser.switch(tab_id=new)
        ui.log(f"switch → url={result.get('url')}")

    if original:
        ui.status("test_switch_and_close_tab → switching back")
        browser.switch(tab_id=original)
