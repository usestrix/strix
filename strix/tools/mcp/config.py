"""The connection-config contract for the MCP client.

Describes one MCP server the client can connect to: its transport, endpoint or
launch command, optional auth, and an optional tool allowlist. Field names are
stable; callers build against them.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class BearerAuth(BaseModel):
    """Header-token auth, sent as ``Authorization: Bearer <token>``."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["bearer"] = "bearer"
    token: str = Field(min_length=1, repr=False)


McpAuth = Annotated[BearerAuth, Field(discriminator="kind")]


class McpConnectionConfig(BaseModel):
    """One MCP server the client can connect to.

    Two transports are supported: streamable ``http`` (a remote endpoint) and
    ``stdio`` (a local server launched as a subprocess).
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    """Namespaced tool prefix, unique per run (e.g. ``github``)."""

    transport: Literal["http", "stdio"] = "http"
    """``http`` for a streamable HTTP endpoint, ``stdio`` for a local subprocess."""

    url: str | None = Field(default=None, min_length=1)
    """The MCP server endpoint. Required for ``http``."""

    auth: McpAuth | None = None
    """Bearer token for the server. Optional; a local stdio server usually
    needs none."""

    command: str | None = Field(default=None, min_length=1)
    """The executable to launch for ``stdio``. Required for ``stdio``."""

    args: list[str] = Field(default_factory=list)
    """Arguments passed to ``command`` (stdio only)."""

    env: dict[str, str] = Field(default_factory=dict)
    """Extra environment variables for the stdio subprocess."""

    allowed_tools: list[str] | None = None
    """Tool allowlist, applied after the server lists its tools. ``None`` (the
    default) exposes every tool the server lists; a list restricts to it."""

    notes: str | None = None
    """Free-text notes for the agent describing what this connection is and how
    to use it. When set, the runner collects the notes of every connection into
    a single block on the root task, so a note describes its connection once
    rather than being repeated onto each of its tools."""

    @model_validator(mode="after")
    def _check_transport_fields(self) -> McpConnectionConfig:
        if self.transport == "http" and not self.url:
            raise ValueError("an http MCP connection requires 'url'")
        if self.transport == "stdio" and not self.command:
            raise ValueError("a stdio MCP connection requires 'command'")
        return self
