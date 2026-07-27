"""Update notifications and self-update for the strix CLI.

Follows the pattern used by tools like gh, uv, and pip: a background,
rate-limited (once per 24h) check against the release source, a cached
result in ``~/.strix``, a non-intrusive notice with the upgrade command
for the detected install method, and a ``strix --update`` self-update
path for the standalone binary install.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import cast

import requests
from rich.console import Console
from rich.prompt import Prompt

from strix.telemetry._common import get_version


logger = logging.getLogger(__name__)

GITHUB_REPO = "usestrix/strix"
PYPI_PACKAGE = "strix-agent"
INSTALL_SCRIPT_URL = "https://strix.ai/install"
CHECK_INTERVAL_SECONDS = 24 * 60 * 60
REQUEST_TIMEOUT_SECONDS = 5

_CACHE_PATH = Path.home() / ".strix" / "update-check.json"

_background_thread: threading.Thread | None = None


def _is_disabled() -> bool:
    return bool(os.environ.get("STRIX_NO_UPDATE_CHECK")) or any(
        os.environ.get(key)
        for key in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILDKITE", "CIRCLECI")
    )


def is_binary_install() -> bool:
    return bool(getattr(sys, "frozen", False))


def get_install_method() -> str:
    if is_binary_install():
        return "binary"
    prefix = str(Path(sys.prefix)).replace("\\", "/")
    if "/pipx/" in prefix or prefix.endswith("/pipx"):
        return "pipx"
    if "/uv/tools/" in prefix:
        return "uv"
    return "pip"


def get_upgrade_command(method: str | None = None) -> str:
    method = method or get_install_method()
    commands = {
        "binary": "strix --update",
        "pipx": "pipx upgrade strix-agent",
        "uv": "uv tool upgrade strix-agent",
        "pip": "pip install --upgrade strix-agent",
    }
    return commands[method]


def _parse_version(value: str) -> tuple[int, ...] | None:
    parts = value.strip().lstrip("v").split(".")
    try:
        return tuple(int(part) for part in parts)
    except ValueError:
        return None


def _is_newer(latest: str, current: str) -> bool:
    latest_parts = _parse_version(latest)
    current_parts = _parse_version(current)
    if latest_parts is None or current_parts is None:
        return False
    return latest_parts > current_parts


def _fetch_latest_version() -> str | None:
    try:
        if is_binary_install():
            response = requests.get(
                f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest",
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            tag = response.json().get("tag_name", "")
            return tag.lstrip("v") or None
        response = requests.get(
            f"https://pypi.org/pypi/{PYPI_PACKAGE}/json",
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        version = response.json().get("info", {}).get("version")
        return str(version) if version else None
    except Exception:  # noqa: BLE001
        logger.debug("update check failed", exc_info=True)
        return None


def _read_cache() -> dict[str, object]:
    try:
        with _CACHE_PATH.open(encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return cast("dict[str, object]", data)
    except Exception:  # noqa: BLE001, S110
        pass  # nosec B110
    return {}


def _write_cache(**fields: object) -> None:
    try:
        cache = _read_cache()
        cache.update(fields)
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_PATH.write_text(json.dumps(cache), encoding="utf-8")
    except Exception:  # noqa: BLE001, S110
        pass  # nosec B110


def skip_version(version: str) -> None:
    """Remember not to prompt again for this version (newer releases still notify)."""
    _write_cache(skipped_version=version)


def _refresh_cache() -> None:
    latest = _fetch_latest_version()
    if latest:
        _write_cache(latest_version=latest, checked_at=time.time())


def start_background_check() -> None:
    """Refresh the cached latest-version info in a daemon thread (at most once per 24h)."""
    global _background_thread  # noqa: PLW0603
    if _is_disabled():
        return
    cache = _read_cache()
    checked_at = cache.get("checked_at")
    if isinstance(checked_at, int | float) and time.time() - checked_at < CHECK_INTERVAL_SECONDS:
        return
    _background_thread = threading.Thread(target=_refresh_cache, daemon=True)
    _background_thread.start()


def get_available_update(*, respect_skip: bool = True) -> str | None:
    """Return the newer version from the cache, or None if up to date / unknown."""
    if _is_disabled():
        return None
    if _background_thread is not None:
        _background_thread.join(timeout=0.2)
    cache = _read_cache()
    latest = cache.get("latest_version")
    current = get_version()
    if not isinstance(latest, str) or current == "unknown" or not _is_newer(latest, current):
        return None
    if respect_skip and cache.get("skipped_version") == latest:
        return None
    return latest


def notify_update(console: Console) -> None:
    latest = get_available_update()
    if not latest:
        return
    console.print(
        f"[#eab308]A new version of strix is available:[/] "
        f"[dim]{get_version()}[/] [dim]→[/] [bold #22c55e]{latest}[/]"
        f"  [dim]·[/]  [#60a5fa]{get_upgrade_command()}[/]"
    )
    console.print()


def run_package_upgrade(console: Console, method: str) -> bool:
    """Upgrade a package-manager install by running its upgrade command."""
    command = get_upgrade_command(method).split()
    console.print(f"[dim]Running[/] [#60a5fa]{' '.join(command)}[/]")
    try:
        result = subprocess.run(command, check=False)  # noqa: S603
    except OSError as e:
        console.print(f"[bold red]Update failed:[/] {e}")
        return False
    if result.returncode != 0:
        console.print(
            f"[bold red]Update failed[/] [dim](exit code {result.returncode}).[/] "
            f"Run it manually: [#60a5fa]{get_upgrade_command(method)}[/]"
        )
        return False
    console.print("[#22c55e]✓ strix updated — restart the scan to use the new version[/]")
    return True


def prompt_update_if_available(console: Console) -> bool:
    """Offer an interactive update before a scan starts.

    Returns True if strix was updated (caller should re-exec / exit).
    """
    latest = get_available_update()
    if not latest or not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    console.print()
    console.print(
        f"[#eab308]A new version of strix is available:[/] "
        f"[dim]{get_version()}[/] [dim]→[/] [bold #22c55e]{latest}[/]"
    )
    console.print(
        "[dim]  y — update now    n — not now (ask again next run)    s — skip this version[/]"
    )
    choice = Prompt.ask("Update strix?", choices=["y", "n", "s"], default="n")
    console.print()
    if choice == "s":
        skip_version(latest)
        return False
    if choice != "y":
        return False
    method = get_install_method()
    if method == "binary":
        return self_update(console, version=latest)
    return run_package_upgrade(console, method)


def _run_installer(version: str, console: Console) -> None:
    """Update the binary install by re-running the hosted install script."""
    response = requests.get(  # nosec B113
        INSTALL_SCRIPT_URL,
        timeout=REQUEST_TIMEOUT_SECONDS * 12,
    )
    response.raise_for_status()
    console.print(f"[dim]Running[/] [#60a5fa]VERSION={version} curl {INSTALL_SCRIPT_URL} | bash[/]")
    command = ["bash", "-s"]
    result = subprocess.run(  # noqa: S603
        command,
        input=response.text,
        text=True,
        env={**os.environ, "VERSION": version},
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"install script exited with code {result.returncode}")


def self_update(console: Console | None = None, version: str | None = None) -> bool:
    """Update the standalone binary install by re-running the install script.

    Returns True on success. For package-manager installs this only
    prints the right upgrade command and returns False.
    """
    console = console or Console()

    if not is_binary_install():
        method = get_install_method()
        console.print(
            f"[#eab308]This strix was installed via {method};[/] "
            f"upgrade it with: [#60a5fa]{get_upgrade_command(method)}[/]"
        )
        return False

    latest = version or _fetch_latest_version()
    if not latest:
        console.print("[bold red]Could not determine the latest strix version.[/]")
        return False

    current = get_version()
    if current != "unknown" and not _is_newer(latest, current):
        console.print(f"[#22c55e]strix {current} is already the latest version.[/]")
        return True

    try:
        _run_installer(latest, console)
    except Exception as e:  # noqa: BLE001
        logger.debug("self-update failed", exc_info=True)
        console.print(f"[bold red]Update failed:[/] {e}")
        console.print(
            "[dim]You can reinstall manually with:[/] "
            f"[#60a5fa]curl -sSL {INSTALL_SCRIPT_URL} | bash[/]"
        )
        return False

    _write_cache(latest_version=latest, checked_at=time.time())
    console.print(f"[#22c55e]✓ Updated strix to {latest}[/]")
    return True
