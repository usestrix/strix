"""Utility helpers for reading persisted Strix configuration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from platformdirs import user_config_dir


CONFIG_NAMESPACE = "strix"
CONFIG_AUTHOR = "usestrix"
CONFIG_FILENAME = "config.json"


def _config_path() -> Path:
    base_dir = Path(user_config_dir(CONFIG_NAMESPACE, CONFIG_AUTHOR))
    return base_dir / CONFIG_FILENAME


def load_config() -> dict[str, Any]:
    """Load the persisted user configuration if it exists."""

    try:
        path = _config_path()
        if not path.exists():
            return {}

        with path.open("r", encoding="utf-8") as stream:
            data = json.load(stream)
            if isinstance(data, dict):
                return data
    except (OSError, json.JSONDecodeError, ValueError):
        return {}

    return {}


def get_budget_defaults() -> dict[str, Any]:
    """Return persisted budget defaults (if configured)."""

    config = load_config()
    budgets = config.get("budgets", {})
    return budgets if isinstance(budgets, dict) else {}
