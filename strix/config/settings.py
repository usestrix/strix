"""Telemetry opt-in patch for strix — drop-in replacement.

Drop-in replacement for:

  strix/config/settings.py
    class TelemetrySettings(BaseSettings):
        enabled: bool = Field(default=True, alias="STRIX_TELEMETRY")

  strix/interface/cli.py
    def _validate_environment() -> None: ...   # first-run disclosure goes here

This module exists to make the change testable in isolation. The actual
patch is in 02_PR_strix_telemetry_optin.md.
"""
from __future__ import annotations

import os
import warnings
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


_BASE_CONFIG = SettingsConfigDict(
    case_sensitive=False,
    populate_by_name=True,
    extra="ignore",
)


class TelemetrySettings(BaseSettings):
    """Telemetry is OPT-IN by default.

    Penetration testing tools are run against sensitive target environments
    under non-disclosure relationships. Default-on analytics creates
    compliance friction (SOC 2, ISO 27001, FedRAMP) and operational
    disclosure (the mere fact of a network call during a sensitive
    window).

    Users who want to contribute anonymous metrics should opt in
    explicitly with `STRIX_TELEMETRY=1`.
    """

    model_config = _BASE_CONFIG

    enabled: bool = Field(default=False, alias="STRIX_TELEMETRY")


# ── First-run disclosure banner ─────────────────────────────────────────
def _first_run_telemetry_disclosure() -> None:
    """One-time disclosure when telemetry is enabled.

    The intent is to make the opt-in explicit: when a user (or admin) has
    set ``STRIX_TELEMETRY=1``, they get a one-shot notice describing what
    is sent and how to turn it off.

    The banner is suppressed if:
    - Telemetry is off (it would be confusing to show).
    - The user has already seen it once (controlled by a dotfile).
    - Running under non-TTY (CI smoke tests should not see it).
    """
    if os.environ.get("STRIX_TELEMETRY", "0") != "1":
        return
    if not sys.stderr.isatty():
        return

    marker = Path.home() / ".strix" / ".telemetry-banner-shown"
    if marker.exists():
        return
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    except OSError:
        # Don't let a filesystem failure silence the banner entirely.
        pass

    warnings.warn(
        "Telemetry is enabled. Strix sends anonymous scan metrics to "
        "PostHog (us.i.posthog.com) and Scarf (strix.gateway.scarf.sh).\n"
        "Disable:  export STRIX_TELEMETRY=0",
        UserWarning,
        stacklevel=2,
    )


# Local imports for the smoke test
import sys  # noqa: E402


if __name__ == "__main__":
    # Default-OFF assertion
    s_default = TelemetrySettings()
    assert s_default.enabled is False, (
        "Telemetry should be OFF by default per the privacy-first change."
    )
    print("OK: default-OFF telemetry")

    # Opt-in via env
    os.environ["STRIX_TELEMETRY"] = "1"
    s_optin = TelemetrySettings()
    assert s_optin.enabled is True, "STRIX_TELEMETRY=1 should opt in"
    print("OK: opt-in via STRIX_TELEMETRY=1")

    # Falsy values
    for v in ("0", "false", "False", "no"):
        os.environ["STRIX_TELEMETRY"] = v
        s = TelemetrySettings()
        assert s.enabled is False, f"value {v!r} should opt-out"
    print("OK: 0/false/False/no all opt-out")
    # Truthy
    for v in ("1", "true", "TRUE", "yes", "y"):
        os.environ["STRIX_TELEMETRY"] = v
        s = TelemetrySettings()
        assert s.enabled is True, f"value {v!r} should opt-in"
    print("OK: 1/true/TRUE/yes/y all opt-in")
    # Empty string is treated as not-set (defensive — note that this
    # mirrors the original strix behavior: an empty STRIX_TELEMETRY would
    # have been rejected by pydantic too. If we want to opt-out on empty,
    # we need to add a pre-validator.)
    os.environ["STRIX_TELEMETRY"] = ""
    try:
        TelemetrySettings()
        print("OK: empty STRIX_TELEMETRY treated as default (False)")
    except Exception as exc:
        # Pydantic rejects empty for boolean; this is the same behavior
        # as the current strix master branch. Document the gap.
        print(f"NOTE: empty STRIX_TELEMETRY raises ({type(exc).__name__}); "
              "consider adding a pre-validator if you want empty == OFF")
