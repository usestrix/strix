"""Shared error type for bounty program loaders."""

from __future__ import annotations


class BountyLoadError(RuntimeError):
    """Raised when a bug-bounty program cannot be loaded, parsed, or validated."""
