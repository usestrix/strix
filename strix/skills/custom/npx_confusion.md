---
name: npx-confusion
description: Test package and executable identity confusion in npx, npm exec, and bunx fallback, plus explicit auto-fetch runners such as pnpm/yarn dlx and deno run npm:, with runner-specific resolution analysis, registry-state controls, reporting gates, and false-positive elimination
---

# npx Confusion

Use this skill when a package runner may execute code from a package other than the publisher or package the workflow intended. For `npx`, `npm exec`, and `bunx`, the recurring case is a missing local executable being reinterpreted as a remotely fetched package spec. Explicit auto-fetch runners such as `pnpm dlx`, `yarn dlx`, and `deno run npm:` have different semantics; analyze them as an adjacent package-identity problem rather than pretending they share npm's fallback order.

Load `dependency_cve_scanning` for known vulnerable versions, `infrastructure_lifecycle` for abandoned domains or registry resources, `agentic_system_security` for the authority of an MCP/agent process, and `semantic_confusion` for the general lookup-order model.

## Core Condition

Choose the branch that matches the runner.

For local-first fallback (`npx`, `npm exec`, or `bunx`), require all of the following:

1. A target-controlled workflow invokes a bare executable or ambiguous package token.
2. The intended package and its executable name differ, or other evidence establishes the expected publisher/package.
3. The executable is not resolved in the workflow's real local, workspace, global, or cache context as applicable to that runner.
4. The runner consequently selects an unintended remote package spec from its configured registry.
5. The affected workflow reaches that package's executable with security-relevant authority.

For explicit auto-fetch runners (`pnpm dlx`/`pnx`/`pnpx`, `yarn dlx`, or `deno run npm:`), do not require or claim a missing-local-binary fallback. Require evidence that the command names or infers a package different from the one the workflow intended, such as a scoped-package/bin mismatch, typo, generated configuration error, or wrong publisher. Then prove the exact fetched package, chosen binary/module, execution path, and inherited authority.

A public package merely being outside the target's ownership is not a vulnerability. Third-party packages are normal; the mismatch between intended executable provenance and actual registry resolution is the finding.

## Resolution Model

Record the npm version because `npx` has used `npm exec` since npm 7 and resolver behavior changes between releases. For npm, model these decisions:

```text
bare command
  -> executable in ancestor node_modules/.bin?
  -> executable in global bin?
  -> matching local/global package and usable bin?
  -> matching environment in the npx cache?
  -> treat the command token as a package spec
  -> fetch its manifest from the configured registry
  -> infer one executable from package.json#bin
  -> install into the npx cache and execute
```

Also record:

- working directory and workspace root
- local dependency tree and generated `node_modules/.bin` links
- global prefix/bin directory and npx cache
- `registry`, scope-specific registry rules, proxy and authentication configuration
- command form, flags, package spec/version, TTY/CI state, and `yes` policy
- npm's executable-inference result when the package exposes zero, one, or several `bin` entries

Do not collapse package-name lookup and bin selection into one step. npm can fetch a manifest yet fail because it cannot infer exactly one executable.

### Runner distinctions

Record the exact runner and version. Do not reuse npm's local/global/cache ordering for another implementation.

| Runner | Resolution behavior to model | Package binding / fetch control |
|---|---|---|
| `npx` / `npm exec` | Local/workspace/global/cache resolution followed by package-spec fallback; executable inference depends on `package.json#bin` | `--package <pkg>` binds the provider; `--no` rejects an install prompt |
| `bunx` | Checks a locally installed package, then can install from npm into Bun's cache | `--package <pkg>` binds the provider; `--no-install` forbids installation |
| `yarn dlx` | Downloads the command-named package into a temporary environment by default; this is not a local-bin fallback | `--package <pkg>` selects a different provider package |
| `pnpm dlx` / `pnx` / `pnpx` | Fetches and hotloads a registry package, then runs its default binary; project trust policies are version-dependent | `--package=<pkg>` selects the provider; prefer declared dependencies plus `pnpm exec` when remote fetch is unintended |
| `deno run npm:<pkg>` | Uses an explicit npm package spec and cache; a subpath can select a binary | Pin the package/subpath and model lock, cache, lifecycle-script, and Deno permission settings |

Treat mutable tags and ranges such as `latest`, `next`, `@2`, caret, and tilde ranges as selectors, not pins. A privileged repeatable workflow needs an exact reviewed version plus lockfile/integrity enforcement where the runner supports it.

## High-Signal Patterns

### Bare executable fallback

```text
npx internal-tool
npx -y internal-tool
npm exec -- internal-tool
```

The signal is strongest in CI, release scripts, bootstrap commands, developer setup, and tool/agent configuration where the same command is run repeatedly.

### Scoped package versus unscoped bin

A scoped package can expose an unscoped executable:

```json
{
  "name": "@org/tooling",
  "bin": { "org-tool": "./bin/run.js" }
}
```

Inside a correctly installed workspace, `npx org-tool` may resolve `node_modules/.bin/org-tool`. Outside that tree, the same command can fall back to the public package named `org-tool`. Treat documentation, MCP configuration, and bootstrap scripts as separate execution contexts rather than assuming the repository-local result applies everywhere.

### Agent and MCP launchers

Inspect `.mcp.json`, editor/desktop agent configuration, devcontainers, and generated tool launchers for `command: npx` plus `-y` and a bare package or binary name. Combine this resolver analysis with `agentic_system_security` to determine the credentials, tools, files, and network access inherited by that process.

## Candidate Collection

Search executable surfaces and retain file, line, command, and execution context:

```bash
rg -n --no-heading -g '!node_modules' -g '!**/dist/**' \
  -e '\b(npx|npm\s+exec|bunx|pnx|pnpx|pnpm\s+dlx|yarn\s+dlx)\s+[^[:space:]]+' \
  -e '\bdeno\s+run\b[^\n]*\bnpm:' \
  -e '"command"\s*:\s*"(npx|bunx|pnx|pnpx|pnpm|yarn|deno)"' \
  -e '"args"\s*:\s*\[[^]]*"(dlx|npm:[^"]+|-y)"' \
  .
```

Search the source/configuration tree rather than a fixed file list: these commands also live in
`scripts/`, husky/lint-staged hooks, `turbo.json`/`nx.json` task definitions,
`.circleci/`, composite-action `action.yml`, devcontainer `postCreateCommand`,
nested workspace `package.json` files, and editor/agent config under
`.cursor/`, `.vscode/`, and `.mcp.json`. If generated output is itself shipped or executed, search its specific directory separately instead of globally including every `dist/` artifact.

Also inspect:

- package scripts and lifecycle hooks
- workspace package `name` and `bin` maps
- READMEs and generated setup instructions
- CI composite actions and reusable workflows
- source maps or bundled package metadata that reveal internal commands

Discard paths, shell variables, flags, Node built-ins, and text that is not executed or presented as an executable command.

## Establish the Actual Resolution

Prefer inspecting the existing dependency tree, lockfile, workspace packages, and `.bin` links. Do not run `npm ci` merely to decide whether a command is local: it changes the tree and can execute lifecycle scripts.

For a version-controlled reproduction environment, record npm's registry lookup without allowing a missing package to be installed:

```bash
npx --no --loglevel=http <candidate>
```

Interpret this carefully:

- a local executable may run immediately; `--no` only refuses missing-package installation
- an HTTP registry request shows fallback, not ownership or successful execution
- a cancellation naming the missing package shows npm's chosen package spec
- cache, global installs, parent directories, workspaces, and registry configuration can change the result

Repeat the resolution analysis in every context that matters: repository root, documented launch directory, CI checkout, generated agent configuration, and bootstrap-before-install flow. Do not substitute a clean empty directory for the target context except to understand npm's generic name mapping.

Do not apply `npx --no` as a generic dry-run flag. Use `bunx --no-install` only for Bun's local-resolution question. `dlx` and `deno run npm:` already name a remotely resolvable package, so validate their package spec, registry, cache/lock, selected binary or subpath, and permissions using that runner's own behavior.

## Ownership and Registry State

Query the exact registry selected by the target configuration, then distinguish:

- intended package owned by the expected publisher
- unrelated public package with the same name
- unregistered name (`404` from a functioning registry)
- private or access-controlled name (`401`/`403`)
- transient/rate-limited/blocked lookup (`429`, `5xx`, timeout)
- placeholder, reserved, disputed, or previously unpublished name

Before trusting any of those states, check whether the target's lookup path can distinguish a known existing package from a newly generated negative control. Resolve the registry from the same working directory and configuration used by the target:

```bash
# Public npm example; use a known package from the actual registry when different.
task_registry="$(npm config get registry)"
npm view --registry="$task_registry" lodash name --json
npm view --registry="$task_registry" "$(openssl rand -hex 12)" name --json
```

Run the pair through the same `.npmrc`, scope routing, authentication, proxy, and egress path as the candidate. Direct `curl` requests to the public registry are a separate observation unless the target runner uses that exact route. A successful pair establishes coarse positive/negative discrimination, not authenticity of every candidate response; verify that returned documents name the requested package and contain plausible registry metadata.

If the pair fails or returns indistinguishable responses, mark the target-path registry state `UNKNOWN`. An independently verified public-registry response may characterize public state, but it does not prove what the target runner resolves. Re-confirm candidate absence before relying on it.

A `404` proves absence from that registry at that time; it does not by itself prove that registration would be accepted. Registry similarity, trademark, reservation, security-hold, and unpublish rules remain separate facts. Two concrete cases to check rather than infer:

- A registry-owned security placeholder occupies the name even when its only version is `0.0.1-security`. Do not identify one from the version alone: inspect the packument, description, dist-tags, top-level and version-level maintainers, and version publisher such as `_npmUser`.
- npm rejects new unscoped names that collide with an existing package after `.`, `-`, and `_` are removed. Normalize both the candidate and existing names: looking up only the candidate's stripped form catches `some-tool` versus `sometool`, but misses the reverse direction when the existing package contains punctuation. Treat this as registry-policy eligibility evidence, not a guarantee that registration would otherwise succeed.

When a candidate name is already registered, distinguish the target's own
organization from an unrelated party before calling it a clash. Correlate `npm owner ls <name>`, version-level publisher metadata, known target-controlled npm organizations, and independently verified repository provenance. Repository/homepage fields are self-asserted supporting evidence and do not settle ownership alone. If publisher identity remains ambiguous, mark it `UNKNOWN`.

## Validation and Impact

Demonstrate the complete resolver statement:

```text
target-controlled invocation and context
  -> intended executable absent
  -> exact public package spec selected
  -> package ownership/availability state
  -> execution trigger and inherited authority
```

Do not report an unregistered name without an execution path, or an execution path whose command is satisfied locally in every relevant context. Derive impact from the environment that executes the package: developer workstation, CI job, release pipeline, agent runtime, container build, or documentation-only workflow.

## Reporting

There is no CVE and no vulnerable installed version here, so this does not go through `create_dependency_report`; that tool requires an advisory-matched CVE. Use `create_vulnerability_report` only after the applicable core condition is fully verified.

A registry lookup or `404` alone is candidate evidence, not a working PoC. The report must preserve the target invocation and execution context, show the exact selected package and binary/module, demonstrate the runner's execution transition in a representative controlled setup without publishing the contested name, and establish the authority inherited by that process. When source is available, include the responsible invocation/configuration and concrete fix in `code_locations`.

Do not file documentation/comment-only references, locally satisfied commands, unregisterable names, ambiguous ownership, or chains that stop before package execution. Retain them as investigation notes only when useful.

Derive CVSS from the demonstrated path rather than a fixed severity label. Account for required developer/user action, registry and configuration prerequisites, runner permissions, credential availability, and the confidentiality, integrity, and availability actually exposed. A CI, release, container-build, or agent context can be severe, but the context name alone does not establish High or Critical impact.

Deduplicate by root cause, affected asset/workflow, and remediation. Combine call sites when the same configuration mistake and fix apply; keep separate findings when the same candidate name affects different products, tenants, runner semantics, authority, or fixes.

## False Positives

- The executable is provided by a declared dependency in every real execution context.
- `npx --package @scope/pkg <bin>` explicitly binds the executable to the intended package.
- A versioned package spec or scope-specific registry points to the intended publisher.
- The public package is the deliberately selected third-party tool.
- npm fetches the manifest but cannot infer or execute a bin.
- The reference appears only in generated/minified text with no executable call site.
- A registry/proxy error is misread as an unregistered name, or the target-path control pair is inconclusive.
- A package is absent but registry policy prevents the contested registration.
- The command resolves to the deliberately selected ecosystem tool and expected publisher.
- The already-registered name belongs to the target's own organization.
- An explicit `dlx` or `npm:` package spec is treated as missing-local fallback without evidence of a package/publisher mismatch.

## Remediation

- Install the intended package and invoke its local executable through an npm script.
- For npm, bind and pin the provider: `npx --package @org/tool@<version> org-tool`; use `--no` when a missing dependency must fail.
- For Bun, use `bunx --package @org/tool@<version> org-tool` and `--no-install` when remote installation is not intended.
- Replace `yarn dlx`/`pnpm dlx` in repeatable or privileged workflows with a declared, locked dependency plus the runner's local `exec` command. When ephemeral execution is required, bind and pin the provider package explicitly.
- For Deno, pin the `npm:` package and binary subpath, retain a reviewed lockfile, use cache-only operation where appropriate, and grant only the permissions the command requires.
- Route private scopes to the intended registry and prevent public fallback.
- Pin package versions and lockfiles in privileged workflows.
- Replace bare `npx -y <name>` agent launchers with reviewed, publisher-qualified, version-pinned package specs.

## Summary

Treat package-runner confusion as an identity and execution-context bug. Prove the runner-specific transition, distinguish binary names from package names, verify registry and publisher state without equating absence with eligibility, and report only a complete execution path under the affected workflow's actual authority.
