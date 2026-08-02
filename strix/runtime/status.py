"""Startup phase reporting.

Scan startup does several slow things (container create, workspace mount,
proxy bootstrap, first model call) before any agent event exists to render.
A ``StatusSink`` lets those phases surface in the UI so a slow step reads as
progress rather than a frozen spinner.
"""

from __future__ import annotations

from collections.abc import Callable


StatusSink = Callable[[str], None]
