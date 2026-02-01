# ADR-001: Migration to Single-Container Architecture

**Status**: Accepted  
**Date**: August 18, 2025  
**Author**: Ahmed Allam (@0xallam)  
**Commit**: `cb57426` - "Running all agents under same container (#12)"

---

## Context

Strix launched as an open-source Alpha on August 8, 2025, with an architecture that provisioned **one Docker container per agent**. This seemed like the "correct" microservices approach—each agent gets isolated resources, individual monitoring, and clean separation of concerns.

The original architecture:

```python
# Original multi-container approach
container_name = f"strix-{agent_id}"
labels = {
    STRIX_AGENT_LABEL: agent_id,      # Individual agent tracking
    STRIX_SCAN_LABEL: scan_id,
}
volumes = {volume_name: {"bind": "/shared_workspace", "mode": "rw"}}
```

Each agent container included:
- Dedicated workspace volume (`strix-workspace-{scan_id}`)
- Individual tool server (FastAPI HTTP server)
- Per-agent port allocation
- Container lifecycle tied to agent lifecycle

---

## Problem

Within 10 days of launch, production usage revealed critical issues:

### 1. Resource Explosion

A typical security scan spawns 5-10 agents. With the multi-container architecture:
- Each container = 500MB+ base RAM
- 10 agents = 5-10GB RAM just for containers
- Tool servers, browsers, and Python runtimes duplicated per container

### 2. Tool Server Proliferation

Every container ran its own tool server:
```python
tool_server_port = self._find_available_port()
# Each agent needed unique ports for:
# - Tool server API
# - Browser proxy (Caido)
# - Future services
```

This created:
- Port exhaustion on busy hosts
- Complex port management logic
- Health check multiplication (N containers to monitor)

### 3. Workspace Coordination Complexity

Agents needed to share codebases, notes, and findings. The solution was `/shared_workspace`:

```python
def _get_workspace_volume_name(self, scan_id: str) -> str:
    return f"strix-workspace-{scan_id}"

volumes_config = {volume_name: {"bind": "/shared_workspace", "mode": "rw"}}
```

But this required:
- Volume creation/management overhead
- File copying between host and containers
- Permission management (`chown -R pentester:pentester`)

### 4. Container Lifecycle Chaos

Tracking containers by labels proved unreliable:

```python
def _get_sandbox_by_agent_id(self, agent_id: str) -> Container | None:
    containers = self.client.containers.list(
        filters={"label": f"{STRIX_AGENT_LABEL}={agent_id}"}
    )
    if len(containers) > 1:
        logger.warning("Multiple sandboxes found for agent ID %s", agent_id)
```

Docker's eventual consistency caused race conditions where:
- Containers appeared in list before they were ready
- Label queries returned stale data
- Cleanup logic missed orphaned containers

---

## Decision

**Consolidate all agents in a single scan to one shared container.**

### Key Changes

#### 1. Container Scope: Per-Scan, Not Per-Agent

```python
# After: One container per scan
container = self.client.containers.run(
    STRIX_IMAGE,
    name=f"strix-scan-{scan_id}",  # Shared across all agents
    labels={"strix-scan-id": scan_id},
    # Agents are logical, not physical boundaries
)
```

#### 2. Simplified Filesystem

Removed the dual-workspace complexity:

```diff
# Dockerfile
- RUN mkdir -p /shared_workspace /workspace
+ RUN mkdir -p /workspace

# docker-entrypoint.sh
- echo "Starting tool server..."
- poetry run uvicorn strix.runtime.tool_server:app --port ${STRIX_TOOL_SERVER_PORT} &
+ echo "Container initialization complete"
```

#### 3. Shared Tool Server

Instead of N tool servers (one per agent), a single tool server handles all agents with context isolation via `ContextVar`:

```python
# Tool server now manages multiple agents
class ToolServer:
    def __init__(self):
        self._agent_contexts: dict[str, AgentContext] = {}
    
    async def execute_tool(self, agent_id: str, tool_name: str, params: dict):
        context = self._agent_contexts.get(agent_id)
        # Execute with agent-specific context
```

---

## Consequences

### Positive

1. **Dramatic Resource Reduction**: 10 agents now use ~500MB instead of 5GB
2. **Simplified Operations**: One health check, one log stream, one lifecycle
3. **Faster Startup**: Single container creation vs. N container orchestration
4. **Reliable Workspace Sharing**: Agents naturally share `/workspace` without volume mounts
5. **Easier Debugging**: All agent activity in one place

### Negative

1. **Reduced Isolation**: Agents share the same filesystem and processes
2. **Single Point of Failure**: Container crash affects all agents in scan
3. **Security Considerations**: Less sandboxing between agents

### Mitigations

- Agents still operate with logical isolation via `ContextVar`
- Tool server maintains per-agent state dictionaries
- Python/browser/terminal managers isolate resources by agent ID

---

## Implementation Details

### Migration Statistics

```
544 insertions, 290 deletions across 13 files
- strix/runtime/docker_runtime.py: Complete rewrite
- strix/runtime/tool_server.py: Multi-agent support added
- containers/docker-entrypoint.sh: Simplified startup
- strix/agents/StrixAgent/system_prompt.jinja: Path updates
```

### Breaking Changes

- Environment variables simplified (`STRIX_TOOL_SERVER_PORT` no longer needed)
- Workspace path changed from `/shared_workspace` to `/workspace`
- Container naming convention changed

---

## Follow-up Issues

The single-container architecture wasn't without ongoing challenges:

| Date | Commit | Issue |
|------|--------|-------|
| Sep 9, 2025 | `500b987` | "Fix docker container creation issue" - Race conditions in container startup |
| Jan 16, 2026 | `61dea70` | "Simplify container initialization and fix startup reliability" - Continued refinement |
| Jan 16, 2026 | `26b0786` | "Replace pgrep with health check for tool server validation" - Better health checking |
| Jan 17, 2026 | `918a151` | "Simplify tool server to asyncio tasks" - Moved from multiprocessing to asyncio |

---

## Lessons Learned

### 1. Start Simple, Add Complexity Only When Needed

We initially chose multi-container architecture because it seemed "more correct" for microservices patterns. In practice, it added overhead without benefit since agents in the same scan need to collaborate anyway.

### 2. Docker Containers Are Not VMs

Containers are lightweight process isolation, not full virtual machines. The overhead of 10 containers vs. 1 container is significant for a tool that spawns many short-lived agents.

### 3. Operational Simplicity Beats Theoretical Purity

A single container is easier to:
- Debug (one set of logs)
- Monitor (one health endpoint)
- Reason about (one lifecycle)
- Clean up (one object to destroy)

### 4. Context Isolation > Process Isolation

For our use case, logical isolation via `ContextVar` and state dictionaries provides sufficient separation. Each agent gets its own:
- Terminal session
- Browser context
- Python namespace
- Proxy intercept

Without the overhead of separate processes.

---

## References

- Original PR: [#12](https://github.com/usestrix/strix/pull/12)
- Commit: `cb57426cc6b9f6cffd45a85bf6897a10482b4a23`
- Related: Tool server simplification (`918a151`)
- Related: Container reliability fixes (`61dea70`, `26b0786`)

---

## Decision Record Template

**Inspired by**: [Architecture Decision Records](https://adr.github.io/)  
**Status**: Accepted and stable as of v0.7.0  
**Last Updated**: January 2026
