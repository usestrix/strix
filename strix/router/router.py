"""Per-role model router: choose a cheap model for recon-only child agents.

Opt-in via ``STRIX2_ROUTER=1`` + ``STRIX2_RECON_MODEL=<litellm id>``. The routing
decision is a pure function of the agent's skills; the root orchestrator and any
exploitation/validation child keep the main model (a conservative bias — we never
under-power exploitation). Disabled ⇒ every resolve returns the caller's default
(``None`` ⇒ the global provider default), so behavior is unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


if TYPE_CHECKING:
    from collections.abc import Iterable


Role = Literal["recon", "default"]

_CONFIG = SettingsConfigDict(case_sensitive=False, populate_by_name=True, extra="ignore")


class RouterSettings(BaseSettings):
    """Env-driven config for the per-role model router."""

    model_config = _CONFIG

    enabled: bool = Field(default=False, alias="STRIX2_ROUTER")
    recon_model: str | None = Field(default=None, alias="STRIX2_RECON_MODEL")


def load_router_settings() -> RouterSettings:
    return RouterSettings()


# Skill-name markers for cheap recon / enumeration / mapping work. Deliberately
# narrow: a domain *pentest* skill (which includes exploitation) is NOT here, so it
# keeps the frontier model. Matching is substring, case-insensitive.
_RECON_MARKERS: tuple[str, ...] = (
    "reconnaissance",
    "asset_discovery",
    "infrastructure_lifecycle",
    "mapping",
    "subfinder",
    "httpx",
    "katana",
    "naabu",
    "dnsx",
    "recon",
)


def role_for_skills(skills: Iterable[str] | None) -> Role:
    """Classify an agent as ``recon`` (cheap) or ``default`` (frontier) by its skills.

    Conservative: only a clearly recon/enumeration skill routes to ``recon``;
    anything else — including every domain pentest skill — stays ``default``.
    """
    for skill in skills or []:
        low = skill.lower()
        if any(marker in low for marker in _RECON_MARKERS):
            return "recon"
    return "default"


def select_model(
    role: Role, *, settings: RouterSettings | None = None, default: str | None = None
) -> str | None:
    """Model id for ``role``, or ``default`` when routing is off / unset for the role."""
    settings = settings or load_router_settings()
    if not settings.enabled:
        return default
    if role == "recon" and settings.recon_model:
        return settings.recon_model
    return default


def resolve_agent_model(
    skills: Iterable[str] | None,
    *,
    is_root: bool = False,
    settings: RouterSettings | None = None,
    default: str | None = None,
) -> str | None:
    """Model id for a child agent, or ``default`` (``None`` ⇒ the global default).

    The root orchestrator always uses the main model. Routing is opt-in; disabled ⇒
    always ``default``, so behavior is unchanged.
    """
    settings = settings or load_router_settings()
    if is_root or not settings.enabled:
        return default
    return select_model(role_for_skills(skills), settings=settings, default=default)
