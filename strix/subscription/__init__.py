"""Subscription-backed LLM providers exposed through ``strix --sub <backend>``."""

from __future__ import annotations

from strix.subscription.bringup import maybe_start_subscription_proxy


__all__ = ["maybe_start_subscription_proxy"]
