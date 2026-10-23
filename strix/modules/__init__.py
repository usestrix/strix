"""Scanning modules and registry for Strix."""

from __future__ import annotations

from strix.modules.registry import (
    ModuleRegistry,
    PriorityTier,
    ScanModule,
    default_registry,
    get_module,
    list_modules,
    register_module,
)


__all__ = [
    "ModuleRegistry",
    "PriorityTier",
    "ScanModule",
    "default_registry",
    "get_module",
    "list_modules",
    "register_module",
]
