from __future__ import annotations

import asyncio
import base64
import json
import logging
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _ensure_browser_started(bs: Any) -> None:
    """Ensure the BrowserSession has an active CDP connection and watchdogs.

    Checks both the root CDP client and session manager, which are required
    by ``get_or_create_cdp_session()``.  Calls ``start()`` if either is
    missing — ``start()`` is idempotent and safe to call when already connected.
    """
    has_cdp = getattr(bs, "_cdp_client_root", None) is not None
    has_manager = getattr(bs, "session_manager", None) is not None
    if has_cdp and has_manager:
        return
    await bs.start()


async def _execute_js(bs: Any, js: str) -> Any:
    """Execute JavaScript in the browser via CDP."""
    cdp_session = await bs.get_or_create_cdp_session(target_id=None, focus=False)
    if not cdp_session:
        raise RuntimeError("No active browser session")
    result = await cdp_session.cdp_client.send.Runtime.evaluate(
        params={"expression": js, "returnByValue": True},
        session_id=cdp_session.session_id,
    )
    return result.get("result", {}).get("value")


async def _get_element_center(bs: Any, node: Any) -> tuple[float, float] | None:
    """Get the center coordinates of an element."""
    try:
        cdp_session = await bs.cdp_client_for_node(node)
        session_id = cdp_session.session_id
        backend_node_id = node.backend_node_id

        try:
            await cdp_session.cdp_client.send.DOM.scrollIntoViewIfNeeded(
                params={"backendNodeId": backend_node_id}, session_id=session_id
            )
            await asyncio.sleep(0.05)
        except Exception:  # noqa: BLE001
            logger.debug("scrollIntoViewIfNeeded failed", exc_info=True)

        element_rect = await bs.get_element_coordinates(backend_node_id, cdp_session)
    except Exception:
        logger.exception("Failed to get element center")
        return None
    else:
        if element_rect:
            center_x = element_rect.x + element_rect.width / 2
            center_y = element_rect.y + element_rect.height / 2
            return center_x, center_y
        return None


async def _get_node_or_error(
    bs: Any, index: int | None
) -> tuple[Any | None, dict[str, Any] | None]:
    """Look up a DOM node by index, returning (node, None) or (None, error_dict)."""
    if index is None:
        return None, {"error": "index parameter is required"}
    node = await bs.get_element_by_index(index)
    if node is None:
        return None, {"error": f"Element index {index} not found - page may have changed"}
    return node, None


# ---------------------------------------------------------------------------
# Command dispatcher
# ---------------------------------------------------------------------------


async def handle_command(action: str, bs: Any, **params: Any) -> dict[str, Any]:
    """Dispatch a granular browser command.

    Parameters are passed as keyword args — each action uses only the keys it
    needs and ignores the rest.
    """
    await _ensure_browser_started(bs)

    if action == "open":
        return await _cmd_open(bs, **params)
    if action == "click":
        return await _cmd_click(bs, **params)
    if action == "type":
        return await _cmd_type(bs, **params)
    if action == "input":
        return await _cmd_input(bs, **params)
    if action == "scroll":
        return await _cmd_scroll(bs, **params)
    if action == "back":
        return await _cmd_back(bs)
    if action == "screenshot":
        return await _cmd_screenshot(bs, **params)
    if action == "state":
        return await _cmd_state(bs)
    if action == "switch":
        return await _cmd_switch(bs, **params)
    if action in ("close_tab", "close-tab"):
        return await _cmd_close_tab(bs, **params)
    if action == "keys":
        return await _cmd_keys(bs, **params)
    if action == "select":
        return await _cmd_select(bs, **params)
    if action == "eval":
        return await _cmd_eval(bs, **params)
    if action == "extract":
        return await _cmd_extract(**params)
    if action == "hover":
        return await _cmd_hover(bs, **params)
    if action == "dblclick":
        return await _cmd_dblclick(bs, **params)
    if action == "rightclick":
        return await _cmd_rightclick(bs, **params)
    if action == "cookies":
        return await _cmd_cookies(bs, **params)
    if action == "wait":
        return await _cmd_wait(bs, **params)
    if action == "get":
        return await _cmd_get(bs, **params)
    raise ValueError(f"Unknown browser command: {action}")


# ---------------------------------------------------------------------------
# Individual commands
# ---------------------------------------------------------------------------


async def _cmd_open(bs: Any, *, url: str | None = None, **_: Any) -> dict[str, Any]:
    if not url:
        return {"error": "url parameter is required for open action"}
    if not url.startswith(("http://", "https://", "file://")):
        url = "https://" + url
    from browser_use.browser.events import NavigateToUrlEvent

    await bs.event_bus.dispatch(NavigateToUrlEvent(url=url))
    result: dict[str, Any] = {"url": url}
    if getattr(bs, "browser_profile", None) and bs.browser_profile.use_cloud and bs.cdp_url:
        from urllib.parse import quote

        result["live_url"] = f"https://live.browser-use.com/?wss={quote(bs.cdp_url, safe='')}"
    return result


async def _cmd_click(
    bs: Any,
    *,
    index: int | None = None,
    x: float | None = None,
    y: float | None = None,
    **_: Any,
) -> dict[str, Any]:
    if x is not None and y is not None:
        from browser_use.browser.events import ClickCoordinateEvent

        await bs.event_bus.dispatch(ClickCoordinateEvent(coordinate_x=x, coordinate_y=y))
        return {"clicked_coordinate": {"x": x, "y": y}}
    if index is not None:
        from browser_use.browser.events import ClickElementEvent

        node, err = await _get_node_or_error(bs, index)
        if err:
            return err
        await bs.event_bus.dispatch(ClickElementEvent(node=node))
        return {"clicked": index}
    return {"error": "Provide index or (x, y) coordinates"}


async def _cmd_type(bs: Any, *, text: str | None = None, **_: Any) -> dict[str, Any]:
    if not text:
        return {"error": "text parameter is required for type action"}
    cdp_session = await bs.get_or_create_cdp_session(target_id=None, focus=False)
    if not cdp_session:
        return {"error": "No active browser session"}
    await cdp_session.cdp_client.send.Input.insertText(
        params={"text": text}, session_id=cdp_session.session_id
    )
    return {"typed": text}


async def _cmd_input(
    bs: Any, *, index: int | None = None, text: str | None = None, **_: Any
) -> dict[str, Any]:
    if not text:
        return {"error": "text parameter is required for input action"}
    from browser_use.browser.events import ClickElementEvent, TypeTextEvent

    node, err = await _get_node_or_error(bs, index)
    if err:
        return err
    await bs.event_bus.dispatch(ClickElementEvent(node=node))
    await bs.event_bus.dispatch(TypeTextEvent(node=node, text=text))
    return {"input": text, "element": index}


async def _cmd_scroll(
    bs: Any,
    *,
    direction: str | None = None,
    amount: int | None = None,
    **_: Any,
) -> dict[str, Any]:
    from browser_use.browser.events import ScrollEvent

    d = direction or "down"
    a = amount or 500
    await bs.event_bus.dispatch(ScrollEvent(direction=d, amount=a))
    return {"scrolled": d, "amount": a}


async def _cmd_back(bs: Any) -> dict[str, Any]:
    from browser_use.browser.events import GoBackEvent

    await bs.event_bus.dispatch(GoBackEvent())
    return {"back": True}


async def _cmd_screenshot(
    bs: Any, *, full: bool = False, path: str | None = None, **_: Any
) -> dict[str, Any]:
    data = await bs.take_screenshot(full_page=full)
    if path:
        p = Path(path)
        p.write_bytes(data)
        return {"saved": str(p), "size": len(data)}
    return {"screenshot": base64.b64encode(data).decode(), "size": len(data)}


async def _cmd_state(bs: Any) -> dict[str, Any]:
    state = await bs.get_browser_state_summary()
    assert state.dom_state is not None
    state_text = state.dom_state.llm_representation()
    if state.page_info:
        pi = state.page_info
        header = (
            f"viewport: {pi.viewport_width}x{pi.viewport_height}\n"
            f"page: {pi.page_width}x{pi.page_height}\n"
            f"scroll: ({pi.scroll_x}, {pi.scroll_y})\n"
        )
        state_text = header + state_text
    return {"_raw_text": state_text}


async def _cmd_switch(bs: Any, *, tab: int | None = None, **_: Any) -> dict[str, Any]:
    if tab is None:
        return {"error": "tab parameter is required for switch action"}
    from browser_use.browser.events import SwitchTabEvent

    page_targets = bs.session_manager.get_all_page_targets() if bs.session_manager else []
    if tab < 0 or tab >= len(page_targets):
        return {"error": f"Invalid tab index {tab}. Available: 0-{len(page_targets) - 1}"}
    target_id = page_targets[tab].target_id
    await bs.event_bus.dispatch(SwitchTabEvent(target_id=target_id))
    return {"switched": tab}


async def _cmd_close_tab(bs: Any, *, tab: int | None = None, **_: Any) -> dict[str, Any]:
    from browser_use.browser.events import CloseTabEvent

    page_targets = bs.session_manager.get_all_page_targets() if bs.session_manager else []
    if tab is not None:
        if tab < 0 or tab >= len(page_targets):
            return {"error": f"Invalid tab index {tab}. Available: 0-{len(page_targets) - 1}"}
        target_id = page_targets[tab].target_id
    else:
        focused = bs.session_manager.get_focused_target() if bs.session_manager else None
        if not focused:
            return {"error": "No focused tab to close"}
        target_id = focused.target_id
    await bs.event_bus.dispatch(CloseTabEvent(target_id=target_id))
    return {"closed": tab}


async def _cmd_keys(bs: Any, *, keys: str | None = None, **_: Any) -> dict[str, Any]:
    if not keys:
        return {"error": "keys parameter is required"}
    from browser_use.browser.events import SendKeysEvent

    await bs.event_bus.dispatch(SendKeysEvent(keys=keys))
    return {"sent": keys}


async def _cmd_select(
    bs: Any, *, index: int | None = None, value: str | None = None, **_: Any
) -> dict[str, Any]:
    if not value:
        return {"error": "value parameter is required for select action"}
    from browser_use.browser.events import SelectDropdownOptionEvent

    node, err = await _get_node_or_error(bs, index)
    if err:
        return err
    await bs.event_bus.dispatch(SelectDropdownOptionEvent(node=node, text=value))
    return {"selected": value, "element": index}


async def _cmd_eval(bs: Any, *, js: str | None = None, **_: Any) -> dict[str, Any]:
    if not js:
        return {"error": "js parameter is required for eval action"}
    result = await _execute_js(bs, js)
    return {"result": result}


async def _cmd_extract(**params: Any) -> dict[str, Any]:
    query = params.get("query")
    if not query:
        return {"error": "query parameter is required for extract action"}
    return {"query": query, "error": "extract requires agent mode — use action='run'"}


async def _cmd_hover(bs: Any, *, index: int | None = None, **_: Any) -> dict[str, Any]:
    node, err = await _get_node_or_error(bs, index)
    if err:
        return err
    coords = await _get_element_center(bs, node)
    if not coords:
        return {"error": "Could not get element coordinates for hover"}
    cx, cy = coords
    cdp_session = await bs.cdp_client_for_node(node)
    await cdp_session.cdp_client.send.Input.dispatchMouseEvent(
        params={"type": "mouseMoved", "x": cx, "y": cy},
        session_id=cdp_session.session_id,
    )
    return {"hovered": index}


async def _cmd_dblclick(bs: Any, *, index: int | None = None, **_: Any) -> dict[str, Any]:
    node, err = await _get_node_or_error(bs, index)
    if err:
        return err
    coords = await _get_element_center(bs, node)
    if not coords:
        return {"error": "Could not get element coordinates for double-click"}
    cx, cy = coords
    cdp_session = await bs.cdp_client_for_node(node)
    sid = cdp_session.session_id
    send = cdp_session.cdp_client.send.Input.dispatchMouseEvent
    await send(params={"type": "mouseMoved", "x": cx, "y": cy}, session_id=sid)
    await asyncio.sleep(0.05)
    await send(
        params={"type": "mousePressed", "x": cx, "y": cy, "button": "left", "clickCount": 2},
        session_id=sid,
    )
    await asyncio.sleep(0.05)
    await send(
        params={"type": "mouseReleased", "x": cx, "y": cy, "button": "left", "clickCount": 2},
        session_id=sid,
    )
    return {"double_clicked": index}


async def _cmd_rightclick(bs: Any, *, index: int | None = None, **_: Any) -> dict[str, Any]:
    node, err = await _get_node_or_error(bs, index)
    if err:
        return err
    coords = await _get_element_center(bs, node)
    if not coords:
        return {"error": "Could not get element coordinates for right-click"}
    cx, cy = coords
    cdp_session = await bs.cdp_client_for_node(node)
    sid = cdp_session.session_id
    send = cdp_session.cdp_client.send.Input.dispatchMouseEvent
    await send(params={"type": "mouseMoved", "x": cx, "y": cy}, session_id=sid)
    await asyncio.sleep(0.05)
    await send(
        params={"type": "mousePressed", "x": cx, "y": cy, "button": "right", "clickCount": 1},
        session_id=sid,
    )
    await asyncio.sleep(0.05)
    await send(
        params={"type": "mouseReleased", "x": cx, "y": cy, "button": "right", "clickCount": 1},
        session_id=sid,
    )
    return {"right_clicked": index}


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------


async def _cmd_cookies(bs: Any, **params: Any) -> dict[str, Any]:
    sub = params.get("subcommand")
    if sub == "get":
        return await _cookies_get(bs, **params)
    if sub == "set":
        return await _cookies_set(bs, **params)
    if sub == "clear":
        return await _cookies_clear(bs, **params)
    if sub == "export":
        return await _cookies_export(bs, **params)
    if sub == "import":
        return await _cookies_import(bs, **params)
    return {"error": "subcommand required: get, set, clear, export, import"}


def _filter_cookies_by_url(cookie_list: list[dict[str, Any]], url: str) -> list[dict[str, Any]]:
    from urllib.parse import urlparse

    domain = urlparse(url).netloc
    return [
        c
        for c in cookie_list
        if domain.endswith(str(c.get("domain", "")).lstrip("."))
        or str(c.get("domain", "")).lstrip(".").endswith(domain)
    ]


def _cookie_to_dict(c: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "name": c.get("name", ""),
        "value": c.get("value", ""),
        "domain": c.get("domain", ""),
        "path": c.get("path", "/"),
        "secure": c.get("secure", False),
        "httpOnly": c.get("httpOnly", False),
    }
    if "sameSite" in c:
        d["sameSite"] = c.get("sameSite")
    if "expires" in c:
        d["expires"] = c.get("expires")
    return d


async def _cookies_get(bs: Any, **params: Any) -> dict[str, Any]:
    cookies = await bs._cdp_get_cookies()
    cookie_list = [_cookie_to_dict(c) for c in cookies]
    url = params.get("url")
    if url:
        cookie_list = _filter_cookies_by_url(cookie_list, url)
    return {"cookies": cookie_list}


async def _cookies_set(bs: Any, **params: Any) -> dict[str, Any]:
    from cdp_use.cdp.network import Cookie

    cookie_dict: dict[str, Any] = {
        "name": params.get("name", ""),
        "value": params.get("value", ""),
        "path": params.get("path", "/"),
        "secure": params.get("secure", False),
        "httpOnly": params.get("http_only", False),
    }
    if params.get("domain"):
        cookie_dict["domain"] = params["domain"]
    if params.get("same_site"):
        cookie_dict["sameSite"] = params["same_site"]
    if params.get("expires"):
        cookie_dict["expires"] = params["expires"]
    if not params.get("domain"):
        hostname = await _execute_js(bs, "window.location.hostname")
        if hostname:
            cookie_dict["domain"] = hostname
    try:
        cookie_obj = Cookie(**cookie_dict)
        await bs._cdp_set_cookies([cookie_obj])
        return {"set": params.get("name"), "success": True}
    except Exception as e:
        logger.exception("Failed to set cookie")
        return {"set": params.get("name"), "success": False, "error": str(e)}


async def _cookies_clear(bs: Any, **params: Any) -> dict[str, Any]:
    url = params.get("url")
    if url:
        from urllib.parse import urlparse

        cookies = await bs._cdp_get_cookies()
        domain = urlparse(url).netloc
        cdp_session = await bs.get_or_create_cdp_session(target_id=None, focus=False)
        if cdp_session:
            for cookie in cookies:
                cookie_domain = str(cookie.get("domain", "")).lstrip(".")
                if domain.endswith(cookie_domain) or cookie_domain.endswith(domain):
                    await cdp_session.cdp_client.send.Network.deleteCookies(
                        params={
                            "name": cookie.get("name", ""),
                            "domain": cookie.get("domain"),
                            "path": cookie.get("path", "/"),
                        },
                        session_id=cdp_session.session_id,
                    )
    else:
        await bs._cdp_clear_cookies()
    return {"cleared": True, "url": url}


async def _cookies_export(bs: Any, **params: Any) -> dict[str, Any]:
    file_path = params.get("file")
    if not file_path:
        return {"error": "file parameter is required for cookies export"}
    cookies = await bs._cdp_get_cookies()
    cookie_list = [_cookie_to_dict(c) for c in cookies]
    url = params.get("url")
    if url:
        cookie_list = _filter_cookies_by_url(cookie_list, url)
    p = Path(file_path)
    p.write_text(json.dumps(cookie_list, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"exported": len(cookie_list), "file": str(p)}


async def _cookies_import(bs: Any, **params: Any) -> dict[str, Any]:
    file_path = params.get("file")
    if not file_path:
        return {"error": "file parameter is required for cookies import"}
    p = Path(file_path)
    if not p.exists():
        return {"error": f"File not found: {p}"}
    cookies = json.loads(p.read_text())
    cdp_session = await bs.get_or_create_cdp_session(target_id=None, focus=False)
    if not cdp_session:
        return {"error": "No active browser session"}
    cookie_list = []
    for c in cookies:
        cookie_params: dict[str, Any] = {
            "name": c["name"],
            "value": c["value"],
            "domain": c.get("domain"),
            "path": c.get("path", "/"),
            "secure": c.get("secure", False),
            "httpOnly": c.get("httpOnly", False),
        }
        if c.get("sameSite"):
            cookie_params["sameSite"] = c["sameSite"]
        if c.get("expires"):
            cookie_params["expires"] = c["expires"]
        cookie_list.append(cookie_params)
    try:
        await cdp_session.cdp_client.send.Network.setCookies(
            params={"cookies": cookie_list},
            session_id=cdp_session.session_id,
        )
        return {"imported": len(cookie_list), "file": str(p)}
    except Exception as e:  # noqa: BLE001
        return {"error": f"Failed to import cookies: {e}"}


# ---------------------------------------------------------------------------
# Wait
# ---------------------------------------------------------------------------


async def _cmd_wait(bs: Any, **params: Any) -> dict[str, Any]:
    sub = params.get("subcommand")
    if sub == "selector":
        return await _wait_selector(bs, **params)
    if sub == "text":
        return await _wait_text(bs, **params)
    return {"error": "subcommand required: selector, text"}


async def _wait_selector(bs: Any, **params: Any) -> dict[str, Any]:
    selector = params.get("selector")
    if not selector:
        return {"error": "selector parameter is required"}
    timeout_ms = params.get("timeout", 30000)
    timeout_s = timeout_ms / 1000.0
    wait_state = params.get("state", "visible")
    poll = 0.1
    elapsed = 0.0

    js_map = {
        "attached": f"document.querySelector({json.dumps(selector)}) !== null",
        "detached": f"document.querySelector({json.dumps(selector)}) === null",
        "visible": (
            f"(function(){{ const el = document.querySelector({json.dumps(selector)});"
            " if (!el) return false; const s = window.getComputedStyle(el);"
            " const r = el.getBoundingClientRect();"
            " return s.display !== 'none' && s.visibility !== 'hidden'"
            " && s.opacity !== '0' && r.width > 0 && r.height > 0; }})()"
        ),
        "hidden": (
            f"(function(){{ const el = document.querySelector({json.dumps(selector)});"
            " if (!el) return true; const s = window.getComputedStyle(el);"
            " const r = el.getBoundingClientRect();"
            " return s.display === 'none' || s.visibility === 'hidden'"
            " || s.opacity === '0' || r.width === 0 || r.height === 0; }})()"
        ),
    }
    check_js = js_map.get(wait_state, js_map["attached"])

    while elapsed < timeout_s:
        if await _execute_js(bs, check_js):
            return {"selector": selector, "found": True}
        await asyncio.sleep(poll)
        elapsed += poll
    return {"selector": selector, "found": False}


async def _wait_text(bs: Any, **params: Any) -> dict[str, Any]:
    text = params.get("text")
    if not text:
        return {"error": "text parameter is required"}
    timeout_s = params.get("timeout", 30000) / 1000.0
    poll = 0.1
    elapsed = 0.0
    check_js = f"document.body.innerText.includes({json.dumps(text)})"

    while elapsed < timeout_s:
        if await _execute_js(bs, check_js):
            return {"text": text, "found": True}
        await asyncio.sleep(poll)
        elapsed += poll
    return {"text": text, "found": False}


# ---------------------------------------------------------------------------
# Get
# ---------------------------------------------------------------------------


async def _cmd_get(bs: Any, **params: Any) -> dict[str, Any]:
    sub = params.get("subcommand")
    if sub == "title":
        title = await _execute_js(bs, "document.title")
        return {"title": title or ""}
    if sub == "html":
        selector = params.get("selector")
        if selector:
            js = (
                f"(function(){{ const el = document.querySelector({json.dumps(selector)});"
                " return el ? el.outerHTML : null; }})()"
            )
        else:
            js = "document.documentElement.outerHTML"
        html = await _execute_js(bs, js)
        return {"html": html or ""}
    if sub == "text":
        return await _get_text(bs, **params)
    if sub == "value":
        return await _get_value(bs, **params)
    if sub == "attributes":
        return await _get_attributes(bs, **params)
    if sub == "bbox":
        return await _get_bbox(bs, **params)
    return {"error": "subcommand required: title, html, text, value, attributes, bbox"}


async def _get_text(bs: Any, **params: Any) -> dict[str, Any]:
    index = params.get("index")
    node, err = await _get_node_or_error(bs, index)
    if err:
        return err
    text = node.get_all_children_text(max_depth=10) if node else ""
    return {"index": index, "text": text}


async def _get_value(bs: Any, **params: Any) -> dict[str, Any]:
    index = params.get("index")
    node, err = await _get_node_or_error(bs, index)
    if err:
        return err
    assert node is not None
    try:
        cdp_session = await bs.cdp_client_for_node(node)
        resolve_result = await cdp_session.cdp_client.send.DOM.resolveNode(
            params={"backendNodeId": node.backend_node_id},
            session_id=cdp_session.session_id,
        )
        object_id = resolve_result["object"].get("objectId")
        if object_id:
            value_result = await cdp_session.cdp_client.send.Runtime.callFunctionOn(
                params={
                    "objectId": object_id,
                    "functionDeclaration": "function() { return this.value; }",
                    "returnByValue": True,
                },
                session_id=cdp_session.session_id,
            )
            val = value_result.get("result", {}).get("value")
            return {"index": index, "value": val or ""}
    except Exception:
        logger.exception("Failed to get element value")
    return {"index": index, "value": ""}


async def _get_attributes(bs: Any, **params: Any) -> dict[str, Any]:
    index = params.get("index")
    node, err = await _get_node_or_error(bs, index)
    if err:
        return err
    assert node is not None
    attrs = node.attributes or {}
    return {"index": index, "attributes": dict(attrs)}


async def _get_bbox(bs: Any, **params: Any) -> dict[str, Any]:
    index = params.get("index")
    node, err = await _get_node_or_error(bs, index)
    if err:
        return err
    assert node is not None
    try:
        cdp_session = await bs.cdp_client_for_node(node)
        box_result = await cdp_session.cdp_client.send.DOM.getBoxModel(
            params={"backendNodeId": node.backend_node_id},
            session_id=cdp_session.session_id,
        )
        model = box_result["model"]
        content = model.get("content", [])
        if len(content) >= 8:
            x = min(content[0], content[2], content[4], content[6])
            y = min(content[1], content[3], content[5], content[7])
            w = max(content[0], content[2], content[4], content[6]) - x
            h = max(content[1], content[3], content[5], content[7]) - y
            return {"index": index, "bbox": {"x": x, "y": y, "width": w, "height": h}}
    except Exception:
        logger.exception("Failed to get element bbox")
    return {"index": index, "bbox": {}}
