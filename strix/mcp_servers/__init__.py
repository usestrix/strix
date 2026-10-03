"""Strix 2 host-side MCP wrapper servers.

Each module here is a small, standalone `stdio` MCP server that wraps host-side
security tooling (cloud first) and is reached by the pentest agent through the
generic MCP bridge (``call_mcp``). Unlike the in-sandbox tools, these run as
subprocesses in Strix's own virtualenv, so they:

- reuse the scope engine (:mod:`strix.scope`) in-process and enforce it
  **fail-closed** for the new intrusive domains (network/cloud/infra/api); and
- can hold the operator's credentials on the host, so cloud secrets never enter
  the sandbox container.

:mod:`strix.mcp_servers.base` is the shared harness; :mod:`strix.mcp_servers.aws`
is the first concrete wrapper; :mod:`strix.mcp_servers.registry` emits the
``McpConnectionConfig`` entries that point Strix at these servers.
"""
