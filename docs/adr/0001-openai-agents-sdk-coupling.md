# 1. Coupling to the openai-agents SDK's internal sandbox implementation

## Status

Accepted

## Context

Strix's agent runtime is built directly on OpenAI's `agents` SDK (PyPI:
`openai-agents`, imported as `agents`), pinned in `pyproject.toml` as
`openai-agents[litellm]>=0.19.0,<0.20`. The SDK provides the agent run loop,
the sandbox abstraction (Docker-backed containers with a filesystem/manifest
model), and built-in sandbox "capability" tool sets (`Shell`, `Filesystem`)
that implement shell execution, patch application (`apply_patch`), and file
operations.

Building on the SDK rather than writing Strix's own agent loop and sandbox
tooling was the right call: it gets Strix a maintained, security-conscious
sandbox implementation, a documented Responses/Chat-Completions-compatible
tool-calling loop, and shell/filesystem tools for free, instead of Strix
having to build and maintain all of that itself. Rewriting Strix off the SDK
is out of scope for this decision — that would be a multi-month effort with
its own substantial risk, for a problem that a narrower fix (below) already
addresses.

The problem: some of what Strix needs from the SDK is not exposed through a
documented, versioned public API. Two files in particular reach into
internal or undocumented SDK shapes:

- `strix/runtime/docker_client.py` (`StrixDockerSandboxClient`) subclasses
  the SDK's `DockerSandboxClient` and **reimplements `_create_container`
  verbatim** from the SDK's source, because the SDK gives no extension hook
  for the container-creation kwargs. It also imports four underscore-prefixed
  (private) helper functions from `agents.sandbox.sandboxes.docker`, and
  reaches through `SandboxSession._inner` (a private attribute) to swap in a
  custom session subclass and to read the container id for teardown.
- `strix/agents/factory.py` wires up the SDK's `Shell` and `Filesystem`
  sandbox capabilities — which supply the `exec_command`, `write_stdin`,
  `apply_patch`, and filesystem tools an agent actually calls — and then
  pattern-matches on those tools' names and monkeypatches their
  `on_invoke_tool` callables to add result-bounding, argument coercion, and
  error-as-result behavior. This assumes tool names and attribute shapes that
  are not part of a documented contract.

The concrete, current list of every such dependency is maintained in
[`strix/runtime/sdk_compat.py`](../../strix/runtime/sdk_compat.py)'s module
docstring — that file is the canonical checklist, not this ADR, so the list
stays in one place and next to the code it describes.

**The risk**: a maintainer bumping the `openai-agents` version (even a patch
bump, since none of this is covered by semver on the private surface) can
silently change or break sandbox networking, container capabilities, or tool
behavior with no compile-time signal. The failure would show up as a scan
misbehaving mid-run — wrong network capabilities, a hung entrypoint, a tool
that stops accepting the arguments Strix sends it — rather than as an
upgrade-time error pointing at the cause.

## Decision

Add an explicit, checked compatibility boundary instead of leaving the
coupling implicit:

1. `strix/runtime/sdk_compat.py` declares `SUPPORTED_AGENTS_SDK_RANGE`,
   matching the `pyproject.toml` constraint, and exposes
   `assert_compatible_sdk_version()`, which reads the installed `agents`
   package version and raises a clear `RuntimeError` — naming the installed
   version, the supported range, and this file — if it's out of range.
2. `assert_compatible_sdk_version()` is called once, early, in
   `strix.interface.main.main()`, before any sandbox or agent code runs, so
   an incompatible SDK version fails at startup with an actionable message
   instead of failing unpredictably mid-scan.
3. `sdk_compat.py`'s module docstring documents, concretely, every place
   `docker_client.py` and `factory.py` depend on SDK internals beyond the
   public API, plus a numbered checklist of what to re-verify when bumping
   the SDK version (re-diff the verbatim `_create_container` copy, re-check
   the four private helper functions still exist with the same signatures,
   re-check `session._inner` still resolves the same way, re-check the
   `Shell`/`Filesystem` toolsets still expose the same tool names).

This is deliberately **documentation plus a version guard, not a refactor**.
The patching code in `docker_client.py` and `factory.py` is working,
carefully-commented code solving real problems (entrypoint preservation,
NET_ADMIN/NET_RAW for raw-socket tools, output bounding, argument coercion).
Moving it under time pressure risks breaking it, which is worse than leaving
it in place with a guard rail and a checklist.

## Consequences

- An SDK version outside the supported range now fails immediately at
  startup with a message naming the installed version, the supported range,
  and where to look — instead of surfacing as a confusing runtime failure
  partway through a scan.
- Bumping the SDK version now has one required first step (update
  `SUPPORTED_AGENTS_SDK_RANGE` in lockstep with `pyproject.toml`) and one
  concrete checklist to work through (in `sdk_compat.py`'s docstring) before
  merging, rather than relying on someone remembering the tribal knowledge in
  `docker_client.py`'s header comment.
- The guard only catches *version* mismatches, not *behavioral* drift within
  a version bump that stays inside the declared range (e.g. if a future
  0.19.x patch release changes `_create_container`'s body without a version
  bump outside the pin). The checklist and the existing tests
  (`tests/test_docker_client_delete.py`, `tests/test_agent_factory_shell.py`,
  `tests/test_sdk_compat.py`) are the mitigation for that gap, not the
  version guard itself.
- This does not reduce the actual coupling — Strix's sandbox networking and
  tool behavior still depend on SDK internals. It converts a silent failure
  mode into a loud one and gives it a fixed address in the codebase.

## Future direction

Not committed now, but worth considering if the SDK's private surface keeps
moving underneath Strix:

- **Own the `Shell`/`Filesystem` tool implementations directly.** If Strix
  implements `exec_command`, `write_stdin`, `apply_patch`, and file
  operations itself (as it already does for every other tool in
  `strix/tools/`), the coupling in `factory.py` disappears entirely and the
  SDK is used only for its documented agent run loop and tool-calling
  contract. This is a real chunk of work — reimplementing a sandboxed shell
  and patch-apply tool safely — so it should only be taken on if the
  maintenance cost of tracking the SDK's private surface exceeds the cost of
  owning these tools.
- **Ask upstream for an extension hook.** The specific gap that forces the
  verbatim `_create_container` copy is the lack of a way to extend
  `create_kwargs` before `containers.create()` runs. If the SDK adds such a
  hook, `docker_client.py` could subclass and override just the delta
  instead of duplicating the whole method body — the comment in that file
  already flags this as the ideal fix ("Track upstream for an injection
  hook").
