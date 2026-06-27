"""Start the bundled subscription proxy and wire Strix's LLM env to it."""

from __future__ import annotations

import atexit
import logging
import os

from rich.console import Console

from strix.config import invalidate_settings_cache
from strix.subscription._ui import fail, notice
from strix.subscription.proxy import ProxyStartupError, SubscriptionProxy
from strix.subscription.registry import BACKENDS


logger = logging.getLogger(__name__)

_PLACEHOLDER_API_KEY = "strix-subscription"


def maybe_start_subscription_proxy(sub: str | None) -> SubscriptionProxy | None:
    """Start the proxy for ``sub`` and point Strix's LLM config at it.

    Returns ``None`` when ``sub`` is falsy so callers can invoke it
    unconditionally. The proxy is torn down automatically at interpreter exit.
    """
    if not sub:
        return None

    console = Console()
    backend = BACKENDS[sub]
    backend.preflight(console)

    proxy = SubscriptionProxy(backend.build_app())
    try:
        proxy.start()
    except ProxyStartupError as exc:
        fail(console, "Subscription proxy failed to start", str(exc))

    atexit.register(proxy.stop)
    _wire_env(sub, backend.default_model, proxy.base_url)
    invalidate_settings_cache()

    notice(
        console,
        f"Using your {sub} subscription via a local proxy "
        "(experimental; ensure provider terms-of-service compliance).",
    )
    logger.info("Subscription backend '%s' ready at %s", sub, proxy.base_url)
    return proxy


def _wire_env(sub: str, default_model: str, api_base: str) -> None:
    if not os.environ.get("STRIX_LLM"):
        os.environ["STRIX_LLM"] = default_model

    previous_base = os.environ.get("LLM_API_BASE")
    if previous_base and previous_base != api_base:
        logger.warning("--sub %s overrides LLM_API_BASE (%s -> %s)", sub, previous_base, api_base)
    os.environ["LLM_API_BASE"] = api_base
    os.environ.setdefault("LLM_API_KEY", _PLACEHOLDER_API_KEY)
