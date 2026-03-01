"""Human-in-the-Loop (HIL) file-based input manager for operator-assisted workflows.

Replaces fragile copy-paste via terminal input() / Caido proxy with a
file-drop inbox.  The agent writes a request file, the operator drops a
response file, and the agent picks it up -- works for arbitrarily large
tool outputs (Nmap, Burp, Metasploit, etc.).
"""

from strix.hil.input_manager import (
    HILTimeoutError,
    InputManager,
    clear_inbox,
    get_inbox_path,
    list_pending_requests,
    request_input,
    wait_for_response,
)


__all__ = [
    "HILTimeoutError",
    "InputManager",
    "clear_inbox",
    "get_inbox_path",
    "list_pending_requests",
    "request_input",
    "wait_for_response",
]
