"""Startup phase reporting."""

from __future__ import annotations

from collections.abc import Callable


StatusSink = Callable[[str], None]
