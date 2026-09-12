---
name: agentic-system-security
description: Security testing for authorized AI agents and MCP-style tool ecosystems, covering effective authority, tool/resource/prompt inventory, confused-deputy behavior, side-effect authorization, cross-tenant isolation, executable component supply chain, shadow integrations, and repeatable safety regression
---

# Agentic System Security

Use this skill when an AI system can select tools, retrieve resources, invoke remote/local services, maintain memory, delegate to other agents, or install skills/plugins. Pair it with `llm_prompt_injection` for instruction attacks and classic vulnerability skills for the downstream HTTP, cloud, filesystem, identity, or code-execution sink.

Prompt text is not an authorization boundary. Treat the agent runtime as a confused deputy whose effective authority is bounded by the union of its credentials, tools, resources, network reach, filesystem access, delegated agents, and approval policy, then reduce that upper bound to the actually reachable subset by tracing token audience, scopes, routing, target authorization, environment, and approval flow.

## Effective-Authority Map

Draw the complete path:

```text
user / external content
  -> model context and memory
  -> planner / router / policy
  -> tool or delegated agent
  -> credential and target system
  -> side effect / returned data
```

Inventory, for each node:

- trust source and tenant/user ownership
- immutable component identity, package/server name, version, and transport
- tools, resources, prompts, model endpoints, plugins, skills, and MCP servers
- credential identity, issuer, audience/resource, subject, tenant, scopes/roles, expiry, downstream token exchange, environment, and where it is injected
- readable data and write/execute capabilities
- network/listener exposure and test-versus-production target
- argument validation, authorization point, approval point, schema/argument digest, delegated principal propagation, and audit log
- data returned to the model and whether it can contain new instructions

Test from the lowest-privileged realistic user and device. The key comparison is the user's authority versus the agent/tool credential's authority.

## Core Test Areas

### Shadow Agent and AI Discovery

Do not assume the approved application inventory contains every agent, model endpoint, browser extension, local MCP server, or AI API integration. Correlate multiple independent signals:

- DNS/proxy/egress logs for first-seen model, agent, vector database, plugin, and AI SaaS domains
- OAuth/SSO grants, enterprise-app consent, service principals, API tokens, and unusual delegated scopes
- endpoint processes, browser extensions/native messaging, listening loopback ports, and MCP client/server configuration
- repository, CI/CD, secrets-manager, and container/image references to model providers, tool servers, and AI credentials
- cloud-hosted model endpoints, notebooks, functions, gateways, and procurement/expense/SaaS inventory

Baseline local discovery from the host before interpreting network or SSO signals:

```bash
# macOS
lsof -nP -iTCP -sTCP:LISTEN
ps -axo pid,ppid,user,command

# Linux
ss -lntp
ps -eo pid,ppid,user,args

# Windows PowerShell
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
Get-Process | Select-Object Id,ProcessName,Path

# Cross-platform config and credential leads
rg -l 'mcpServers|modelContextProtocol|OPENAI_API_KEY|ANTHROPIC_API_KEY|AZURE_OPENAI_ENDPOINT' <reviewed-roots>
```

Correlate each listener or config hit to PID/container, parent process, binary hash/version, launch command, config file, destination, and credential reference before calling it an active agent component. A loopback listener is a lead, not proof of reachable authority.

Classify each discovered integration by data read, data write, external communication, execution, identity/admin, and production reach. Human-validate attribution before treating a domain or key name as active AI use. Inspect unauthenticated local MCP/agent listeners separately; network inventory tools often miss loopback-only services.

### Tool Discovery and Argument Boundaries

- Enumerate advertised and conditionally available tools, resources, prompts, schemas, annotations, and delegated agents.
- Compare what the UI exposes with what the protocol/runtime accepts directly.
- Test missing, extra, duplicate, nested, oversized, alternate-type, and cross-tenant identifiers in tool arguments.
- Validate scheme/host/path, filesystem paths, cloud resource IDs, recipient identities, SQL/query fields, and command arguments at the tool boundary.
- Treat tool descriptions, names, examples, resource metadata, and returned content as attacker-influenceable unless provenance is enforced.
- Canonicalize tool identity as `server identity/version + endpoint/transport + tool name + schema digest`; do not collapse two identically named tools from different servers into one trust decision.
- Treat protocol hints such as `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint` as untrusted metadata, not authorization.
- Verify that unknown tools or schema-invalid calls fail closed without falling back to a broader handler.

### Confused Deputy and Consequential Actions

- Ask whether untrusted user/document/tool text can choose the tool, target, identity, or action.
- Test read-to-write escalation: a summarizer should not send, publish, delete, purchase, deploy, or modify because retrieved text requests it.
- Test whether approval binds the exact server identity/version, tool name, schema digest, normalized arguments, credential, target, side effect, and expiry. Revalidate those fields immediately before execution; a generic “continue?” is weak if arguments can change after approval.
- Exercise replay, retry, parallel calls, partial failure, cancellation, and delegated execution for duplicate or bypassed actions.
- Prove impact at the actual target and audit log. Model narration or a fabricated tool result is not evidence.
- Use dry-run/no-op/read-only operations first; require explicit human approval for consequential operations.

### Identity, Tenant, and Environment Isolation

- Vary user, workspace, tenant, session, conversation, and delegated-agent identity independently.
- Test whether one tenant can reference another tenant's resources, tool sessions, caches, vector entries, files, or credentials.
- Check whether development/test tools or credentials can reach production, and whether local tools inherit broad workstation authority.
- Verify credential scoping at the target service, not only in the agent's application logic.
- Confirm memory and cached tool results are partitioned and revoked when identity or role changes.

### MCP and Local Tool Servers

- Inventory stdio, streamable HTTP, SSE/legacy, and custom transports; record bind address, origin/auth controls, process command, environment, and lifecycle.
- Look for unauthenticated loopback services reachable from browsers, containers, local users, SSRF, port forwarding, or shared hosts.
- Compare `tools/list`, `resources/list`, and `prompts/list` results across identities, but do not assume listing means calling is authorized.
- For each tool, validate the same authorization and argument checks through every supported transport.
- Treat server-launched subprocess configuration, environment variables, and working directories as sensitive executable configuration.
- For HTTP/SSE transports, validate OAuth issuer, signature, expiry, audience/resource, tenant, and scope claims at the server boundary. Reject tokens minted for the wrong audience, and do not treat a session ID as identity.
- For downstream APIs, do not pass through the same bearer token unless the target explicitly authorizes that audience and principal. Separate upstream MCP authentication from downstream target authorization.
- For browser or loopback OAuth, review redirect URI, state/PKCE handling, localhost binding, and consent proxying. Treat metadata fetches and tool discovery on remote servers as SSRF-relevant surfaces.
- For stdio servers, the launch command and environment are already code execution. Discovery must not execute an unreviewed server binary or mutable package tag.

### Executable Component Supply Chain

Every skill, plugin, MCP server, model adapter, package, and update channel is an executable or behavior-shaping dependency. Record:

- canonical source, publisher, package namespace, pinned version and integrity/provenance
- install/update mechanism, manifest/lockfile/config source, mutable tags, automatic updates, and rollback path
- declared and effective permissions, credentials, filesystem/network access
- transitive dependencies and lifecycle scripts
- review/approval ownership and last verification date

In agent and MCP configs, inspect `command: npx` with `-y` and a bare package or
binary name. The process can fetch code without an interactive prompt and then
run it with the agent's authority. Load `npx_confusion` to determine whether the
name resolves locally, becomes a public package spec, and belongs to the
intended publisher.

Test missing/private-name fallback, typosquatting exposure, mutable remote instructions, compromised-update blast radius, and whether an “instruction-only” component can invoke tools or modify executable files. Resolve `latest`, floating git refs, and mutable image tags to immutable versions or digests before launch. Do not claim or publish contestable package names as proof, and do not execute unknown packages just to discover what they are.

Load `infrastructure_lifecycle` when a skill, plugin, MCP server, model adapter, tool-schema origin, package namespace, or update endpoint is retired, mutable, or externally reassignable. Passive receipt of an agent heartbeat or catalog request does not authorize returning tool definitions, prompts, commands, or executable content.

### Output, Telemetry, and Failure Modes

- Validate model/tool output before it reaches HTML, shell, SQL, URLs, file paths, templates, or a second agent.
- Ensure logs record initiating user, tool/server identity, sanitized arguments, approval, target, result, and correlation ID without storing secrets.
- Test timeout, tool error, truncated output, malformed result, model retry, and policy-service failure. Failures should not silently switch to a more privileged tool or credential.
- Verify kill switches, credential revocation, and disabling a component actually terminate active sessions and queued work.

## Safe Testing Workflow

1. **Map** every capability and trust boundary before injecting prompts.
2. **Classify** tools as read, write, execute, communicate, identity/admin, or external-cost.
3. **Establish controls** with dedicated test tenants, synthetic data, read-only credentials, budgets, and target allowlists.
4. **Probe one boundary** at a time: selection, arguments, authorization, approval, execution, result handling.
5. **Validate the side effect** in the target system and audit trail; compare denied and allowed identities.
6. **Chain confirmed primitives** using the effective-authority and capability map from this skill.
7. **Clean up and revoke** created data, sessions, tokens, and local servers.
8. **Turn each confirmed case into a regression** across relevant models, prompts, tools, roles, and environments.

## MCP Inspector (Conditional)

Use the official [MCP Inspector](https://github.com/modelcontextprotocol/inspector) only against a reviewed local/test server:

```bash
npx @modelcontextprotocol/inspector@<reviewed-version> --cli \
  --config reviewed-mcp.json --server test-server \
  --method tools/list --format json
```

- Current upstream requirements should be checked before pinning; as of August 12, 2026, MCP Inspector 2.1.0 requires Node.js `>=22.19.0`.
- Prefer CLI/TUI and loopback binding over exposing the web UI.
- Preserve the generated API token; never disable authentication or bind the process-spawning backend to an external interface.
- Do not publish ports 6274/6277 or pass through the Docker socket/host devices.
- `tools/list` is protocol-read-only, but launching/initializing an arbitrary stdio server executes it and list handlers can still have process-side effects. Review the server command/config first. Calling a tool can perform real external actions.
- Treat the inspected server command/config as executable; `npx` also downloads code, so pin a reviewed package version for repeatable or sensitive work.

## Regression With Promptfoo (Conditional)

[Promptfoo](https://github.com/promptfoo/promptfoo) can encode a bounded model/tool safety matrix after manual validation:

```bash
npx promptfoo@<reviewed-version> eval
```

- Current upstream engine constraints should be checked before pinning; as of August 12, 2026, Promptfoo documents Node.js `^20.20.0` or `>=22.22.0`.
- Use synthetic prompts/data and a dedicated test provider/project.
- Provider calls transmit data externally and can incur cost even when evaluation orchestration is local. Set request/concurrency and spending ceilings.
- Pin model, provider, prompt, tool schema, retrieval corpus revision, and evaluator versions.
- Include allowed and denied controls across roles/tenants; use multiple runs for nondeterministic outcomes.
- Automated red-team labels are leads, not findings. Confirm the real tool call, data access, or side effect manually.
- Store redacted results; evaluation logs can contain system prompts, secrets, retrieved data, and tool arguments.

## Validation

A report must include:

1. initiating identity, tenant, model/runtime, and exact component versions
2. effective-authority map and relevant tool/resource schema
3. untrusted input source and decision boundary crossed
4. exact target-side operation or data access, with redacted audit evidence
5. denied identity/input and allowed control results across repeat runs
6. credential, feature, approval, environment, and user-interaction prerequisites
7. cleanup/revocation and a bounded regression case

## False Positives

- The model claims a tool ran but the target and audit log show no action.
- A listed tool cannot be invoked by the tested identity or validates arguments safely.
- A safety refusal changes wording but effective capability remains denied.
- Cross-session output is synthetic, cached public data, or hallucinated rather than another user's data.
- A scanner flags an instruction string without showing that it reaches a privileged decision or sink.
- A component has broad declared permissions but the runtime credential/network policy prevents the claimed access.

## Summary

Agent security is capability security. Map the real authority carried through models, tools, credentials, plugins, and delegated agents; validate authorization and approval at the target-side effect; treat every installed component as executable supply chain; and preserve each confirmed boundary failure as a bounded regression.
