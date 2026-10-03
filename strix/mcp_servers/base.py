"""Shared harness for Strix 2's host-side MCP wrapper servers.

Strix 2 wraps host-side security tooling (cloud first) as ``stdio`` MCP servers
the pentest agent reaches through the generic MCP bridge (``call_mcp``). Each
server runs as a subprocess in Strix's own virtualenv, so it reuses this package
and the scope engine in-process, and — unlike the sandbox — it can hold the
operator's credentials on the host without shipping them into the container.

Two things every wrapper needs are centralized here:

- **Scope enforcement, fail-closed.** The new intrusive domains (network / cloud /
  infra / api) must refuse to act when no authorized scope is loaded, unlike
  upstream's web/MCP boundary which is a deliberate no-op without a ``scope.yaml``
  (so upstream web behavior stays unchanged). A host-side wrapper only ever serves
  the new domains, so :meth:`ScopeGuard.check` denies when no policy is loaded and
  otherwise evaluates the target against the policy (including the intrusive gate).
- **A stdout-safe result shape.** A ``stdio`` MCP server speaks its protocol on
  stdout, so a wrapper must never ``print``. Tool results are JSON strings that
  carry a ``success`` flag, matching the native candidate/scope tools, and all
  human-readable logging goes to stderr.

A wrapper builds a server with :func:`build_server`, registers read-only tools,
and calls :meth:`ScopeGuard.check` at the top of each tool before touching a
target.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from strix.scope.enforcement import get_active_policy, load_active_policy


logger = logging.getLogger(__name__)


def result(*, success: bool, **fields: Any) -> str:
    """Serialize a tool result as a JSON string with a top-level ``success`` flag.

    JSON strings (not bare dicts) keep the result stdout-safe and match the shape
    the native tools return; ``success`` lets the interfaces render a failed call
    as failed.
    """
    payload: dict[str, Any] = {"success": success}
    payload.update(fields)
    return json.dumps(payload, ensure_ascii=False, default=str)


def ok(**fields: Any) -> str:
    """A successful tool result carrying ``fields``."""
    return result(success=True, **fields)


def error(message: str, **fields: Any) -> str:
    """A failed tool result carrying an ``error`` message and any extra ``fields``."""
    return result(success=False, error=message, **fields)


class ScopeGuard:
    """Loads the run's scope policy in this subprocess and gates targets fail-closed.

    Build one at server start with :meth:`load` (which reads ``scope.yaml`` /
    ``$STRIX_SCOPE_CONFIG`` and honors ``$STRIX_ALLOW_INTRUSIVE``). :meth:`check`
    reads the active policy live on each call, so tests can set a policy directly
    with :func:`strix.scope.enforcement.set_active_policy` and use a plain
    ``ScopeGuard()``.
    """

    @classmethod
    def load(cls) -> ScopeGuard:
        """Load the active scope policy for this subprocess and return a guard."""
        load_active_policy()
        return cls()

    def check(self, target: str, *, domain: str, intrusive: bool = False) -> str | None:
        """Gate an action against ``target``; return an error result, or ``None`` to allow.

        Fail-closed: with **no** scope policy loaded, the action is refused (the new
        intrusive domains require an explicit authorized scope). With a policy, an
        out-of-scope target — or an intrusive action when ``allow_intrusive`` is
        off — is refused. The returned string is a ready-to-return tool result the
        wrapper hands back to the agent unchanged.
        """
        policy = get_active_policy()
        if policy is None:
            logger.warning("Refusing %s action on %r: no scope policy loaded", domain, target)
            return error(
                f"Refused: no authorized scope is loaded, so {domain} actions are not "
                f"permitted. Point Strix at a scope.yaml (via --scope-config / "
                f"STRIX_SCOPE_CONFIG) that authorizes {target!r}.",
                refused="no_scope",
                target=target,
                domain=domain,
            )
        decision = policy.evaluate(target, intrusive=intrusive)
        if not decision.allowed:
            logger.warning("Refusing %s action on %r: %s", domain, target, decision.reason)
            return error(
                f"Refused (out of scope): {decision.reason}",
                refused="out_of_scope",
                target=target,
                domain=domain,
                intrusive=intrusive,
            )
        return None


def build_server(name: str, instructions: str) -> FastMCP:
    """Construct a ``FastMCP`` stdio server for a wrapper.

    Logging is set to WARNING so a wrapper's boot chatter does not drown the run's
    own output; the transport itself is chosen when the caller invokes ``run()``.
    """
    return FastMCP(name=name, instructions=instructions, log_level="WARNING")
