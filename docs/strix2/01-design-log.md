# Strix 2 — Design Log

A running log of decisions, tradeoffs, and **every core-file change** (with a one-line justification),
per build-brief §2 and §6. Newest entries at the bottom of each phase.

Fork base: `usestrix/strix` @ `ae38fe70` (`main`), version 1.6.2. Working branch: `strix2`.
Upstream kept as git remote `upstream` for rebasing; `origin` intentionally unset until the maintainer
decides where to push (creating a GitHub fork is an outward action — deferred to an explicit go-ahead).

## Conventions
- **Additive-first.** New capability = new module/skill/agent. Editing an upstream file requires an
  entry in the "Core-file changes" table below with a one-line reason.
- New files carry the Apache-2.0 header used by the file's neighbours.
- Every new tool/agent/validator rule ships with a test; CI stays green.

## Core-file changes (upstream files we edited)
| File | Change | Reason | Phase |
|---|---|---|---|
| `strix/core/runner.py` | +1 import, +1 call to `install_strix2_extensions(run_dir)` after `set_scan_id` in `run_strix_scan` | Single, idempotent hook to register Strix 2's additive tools/stores at run start via the built-in `register_agent_tools` seam (which had no upstream callers). 2 lines added, none changed. | 4 |
| `strix/core/runner.py` | Command-line MCP path wraps `load_user_mcp_configs()` in `configs_with_builtins(...)` (+1 lazy import) | Auto-attach Strix 2's applicable host-side wrappers (the AWS wrapper when the scope authorizes an AWS account) so the agent reaches them without hand-editing `~/.strix/mcp-servers.json`. No-op when nothing applies; user configs win name collisions; only the command-line branch (not the SaaS `mcp_connection_requests` path). | 1 |
| `strix/report/writer.py` | +2 imports, `write_executive_report` appends a best-effort "Leads (unvalidated)" section via new `_strix2_leads_section()` | Surface candidate leads in the report `strix view` renders. Guarded/no-op when the candidate store is absent or empty, so upstream-only runs are unchanged. | 4 |
| `strix/tools/mcp/agent_tools.py` | +1 import, `call_mcp` calls new `_scope_denial(arguments)` before dispatch | Enforce `scope.yaml` at the MCP boundary the brief names. No-op when no policy is loaded / no high-confidence target found, so upstream MCP behavior is unchanged. | 1 |
| `strix/interface/cli_args.py` | Added `--scope-config` and `--allow-intrusive` flags → set `STRIX_SCOPE_CONFIG` / `STRIX_ALLOW_INTRUSIVE` env (mirrors the existing `--mcp-*` pattern) | Let the operator point at a scope file and gate intrusive actions from the CLI. | 1 |
| `pyproject.toml` | +`boto3.*`/`botocore.*` to the mypy `ignore_missing_imports` overrides; +a ruff per-file `PLC0415` ignore for `strix/mcp_servers/aws.py` | boto3 ships no type stubs (mypy strict), and the wrapper imports boto3/botocore lazily so the main process never drags in the heavy SDK. Config-only; no product-code change. | 1 |
| `strix/agents/factory.py` | +1 import; `_wrap_exec_command` calls `enforce_shell_command(command)` before dispatch and returns a refusal string if out of scope | Enforce `scope.yaml` at the shell boundary for network-reaching in-sandbox CLIs (defense-in-depth, mirrors the `call_mcp` check). No-op without a policy or for non-network commands, so upstream behavior is unchanged. | 3 |
| `strix/agents/prompt.py` | `_resolve_skills` appends `coordination/strix2_domains` for the root agent (+docstring) | Load Strix 2's domain-delegation guidance into the root system prompt. The template already renders every loaded skill via a generic loop, so no template edit is needed; a logged skip if `skills2` isn't registered, so upstream is unchanged. | 3 |
| `strix/agents/factory.py` | +1 import; `SandboxAgent(model=…)` now `resolve_agent_model(skills, is_root=is_root)` instead of `None` | Per-role model routing (Phase 5). Returns `None` unless `STRIX2_ROUTER` is enabled → the SDK uses the global provider default, so behavior is unchanged by default. | 5 |
| `strix/core/runner.py` | `hooks = ReportUsageHooks(...)` → `hooks = build_run_hooks(...)` (swap constructor; import `build_run_hooks`, drop the now-unused `ReportUsageHooks` import) | Wire the opt-in no-progress guard into the SDK run-hooks lifecycle. `build_run_hooks` returns a plain `ReportUsageHooks` unless `STRIX2_PROGRESS_GUARD` is set, and the guard is a subclass, so the return type, `extend_budget`, and all budget/turn behavior are unchanged when the guard is off (3rd runner edit). | 5 |
| `strix/report/state.py` | `_write_artifacts` calls `enrich_run_sarif(run_dir)` right after `write_sarif` (+1 lazy import), inside the existing SARIF try/except | Fold the finding-annotation sidecar's ATT&CK/CIS/domain tags into the SARIF that was just written. No-op without annotations (upstream-only runs unchanged); the emitter (`sarif.py`) is untouched, and a failure can't harm the base SARIF already on disk. | 4 |

> As of Phase 0, **zero upstream files edited.** All Phase 0 additions are new files
> (`docs/strix2/*`, `scope.yaml`, `strix/scope/*`, `.github/workflows/ci.yml`, `THIRD_PARTY.md`,
> `tests/test_strix2_scope.py`). New tests use a flat `tests/test_strix2_*.py` naming (matches
> upstream's flat layout and avoids ruff `INP001`) rather than a `tests/strix2/` subdir.

---

## Phase 0 — Bootstrap

**Environment (2026-09-26, Windows 11 / PowerShell + Git Bash).**
- Tooling present: git 2.53, uv 0.11.7, Python 3.13.9, docker CLI 29.4.1, node 24. `nmap` **not** on host
  (expected — network tools live in the sandbox image, not on the host).
- `uv sync --dev` → OK. `uv run strix --version` → `strix 1.6.2`.
- **Test baseline (Windows host):** `2171 passed, 32 failed, 11 skipped, 3 xfailed` in ~9m. **All 32
  failures are POSIX-only test-harness assumptions, not product bugs**, verified by cause:
  `test_viewer_auth`/`test_config_loader` assert `0o600` file modes (`assert 438 == 384`, i.e. Windows'
  `0o666`); `test_threat_model_tool` (×21) hardcode `/usr/bin/env git` (`WinError 2`);
  `test_session_entries` uses symlinks; `test_completions` uses filenames with terminal-control chars
  Windows forbids; `test_workspace_files`/`test_local_sources` are path-separator sensitive. **Every seam
  Strix 2 builds on passes** (`test_cli_mcp_config`, `test_agent_tool_registration`, `test_dedupe_model`,
  `test_e2e_budget_lifecycle`, `test_agent_graph_coordination`). CI runs on Linux, where these pass; the
  local Windows baseline is "green modulo known POSIX-only cases."
- **Blocker for a live baseline scan:** the **Docker daemon is not running** (Docker Desktop Linux engine
  npipe not found), and a real scan additionally needs an LLM API key + spends budget. Deferred — see
  "Open decisions".

**Decision — git topology.** Cloned upstream into the working dir, renamed `origin`→`upstream`, created
branch `strix2`. Keeps history rebaseable; no GitHub fork created yet (outward/irreversible — needs
explicit go-ahead).

**Decision — where new code lives.** Confirmed the two clean seams from the codebase map:
`register_agent_tools()` (native tools) and `register_skill_dir()` (skills) let us extend without touching
`agents/factory.py` or the skill loader. Scope enforcement gets its own new package `strix/scope/`.

**Decision — `scope.yaml` schema (drafted + loaded, enforcement stubbed).** Added `strix/scope/` with a
pydantic v2 schema (`ScopePolicy`) and a fail-closed loader, plus a root-level `scope.yaml` template. The
schema models authorized **web** origins, **network** IPs/CIDRs/hostnames+ports, **cloud** account IDs
(AWS/Azure/GCP) and regions, **API** base URLs, and an `allow_intrusive` default (off). Enforcement
(`is_in_scope(target)` returning allow/deny + reason) is implemented as a pure function now; wiring it into
the MCP wrapper boundary and native tools is Phase 1. Rationale for doing the schema in Phase 0: the brief
makes scope a *precondition* for the scope-expansion phases, and a stubbed-but-real schema lets later
phases import a stable contract instead of inventing one ad hoc. See `docs/strix2/scope-schema.md`.

**Decision — CI.** Upstream ships only a tag-triggered release workflow, so `ci.yml` is net-new: it runs
`uv sync --dev`, `ruff check`, and `pytest` on push/PR (Linux, Python 3.12 + 3.13). Kept minimal and
non-duplicative of the release workflow.

**Correction to the brief (recorded for later phases).** Several mechanisms the brief lists as
missing already exist upstream and must not be rebuilt: `--max-budget-usd`, `--max-turns`,
per-turn loop/tool-call guard (`_TurnGuardModel`), LLM finding-dedup, and cloud/network *methodology*
skills. Phase 5 is therefore re-scoped to *model router + cross-run caching + no-progress detector*.
Full detail in `00-codebase-map.md` §7–§10.

### Open decisions / need maintainer input
- **Phase 4 PoC semantics (the crux).** ✅ **Signed off 2026-09-26** — all 8 decisions adopted at their
  recommended defaults (see `04-validator-semantics.md`). Candidate tier implemented (see Phase 4 below).
- **Live baseline scan.** Needs (a) Docker daemon started, (b) an LLM API key, (c) authorization to spend
  budget against a local vulnerable app. Maintainer confirmed **OpenRouter** as the intended provider —
  supported natively via LiteLLM (`openrouter/<model>` + `LLM_API_KEY`); still awaiting the key + a
  `--max-budget-usd` ceiling before running (won't spend unprompted).
- **GitHub fork / push target.** Where should `origin` point? (Still unset; CI unverified on a real Linux
  runner until a push happens.)

### Phase 0 acceptance status
- [x] Codebase map complete → `00-codebase-map.md`
- [x] Design log started → this file
- [x] `scope.yaml` schema drafted **and loaded** (enforcement stubbed) → `strix/scope/`, `scope.yaml`
- [x] CI runs upstream + new tests → `.github/workflows/ci.yml` (+ `tests/test_strix2_scope.py`)
- [ ] Baseline scan produces a validated web finding with a PoC → **blocked** (Docker daemon + API key + budget go-ahead)

---

## Phase 1 — Scope enforcement (core landed; MCP wrappers pending)

Enforcement engine + boundary wiring + CLI gate, all tested. **What's left of Phase 1: the actual MCP
wrapper servers** (nmap/naabu/masscan; prowler/ScoutSuite/CloudFox; nuclei/trivy/checkov; API contract)
with tight `allowed_tools` — a separate, larger chunk not yet started.

**Built:**
- `strix/scope/enforcement.py` — active-policy holder (`get/set_active_policy`), `load_active_policy`
  (reads `scope.yaml`/`$STRIX_SCOPE_CONFIG`, applies `--allow-intrusive`/`STRIX_ALLOW_INTRUSIVE`),
  conservative `extract_targets` (URLs/ARNs/IPv4/12-digit only — bare hostnames excluded to avoid
  false-positives), `enforce_target`, `enforce_arguments`.
- `strix/tools/scope/tools.py` — `check_scope(target, intrusive)` and `scope_status` agent tools.
- Wired into `call_mcp` (guarded, no-op without a policy) and loaded at run start in `strix2_ext`.
- `--scope-config` / `--allow-intrusive` CLI flags.
- Tests: `tests/test_strix2_scope_enforcement.py` (extraction, checks, intrusive gate, loading/overrides).

**Compatibility stance (documented):** enforcement is active only when a `scope.yaml` is loaded; absent,
upstream web/MCP behavior is unchanged. The "fail-closed without scope" requirement applies to the new
intrusive domains (network/cloud), enforced inside those tools when they land in Phase 3.

### Phase 1 (cont.) — host-side MCP wrapper framework + first cloud wrapper

**Architecture decision (brief vs. codebase-map — the map wins).** The brief lists Phase 1 as "stdio MCP
servers wrapping nmap/naabu/masscan (network), prowler/… (cloud), nuclei/trivy/checkov (infra)". Verified
against the code, an MCP `stdio` server is a **host-side subprocess** (`client._build_server` →
`MCPServerStdio` → `stdio_client` spawns `command` on the host, in Strix's own venv). So:
- **Cloud → host-side MCP wrapper.** Cloud tooling is genuinely absent from the sandbox and cloud creds
  must stay *off* the sandbox (codebase-map §8). A host-side subprocess is exactly right: it holds creds on
  the host and reuses `strix.scope` in-process. **This is where the MCP-wrapper mechanism pays off.**
- **Network/infra → NOT host-side MCP.** Those CLIs already live *in the sandbox* and are reached via
  `exec_command`; a host-side subprocess cannot see them. Wrapping them host-side would run against a host
  that doesn't have the tools. They instead get the scope + candidate discipline as **in-sandbox native
  tools / skills** (Phase 2/3), layered on the already-present CLIs — not as MCP wrappers.
- **API contract testing** is pure-Python and host-runnable; a candidate for a later host-side wrapper or a
  native tool. Deferred.

**Built (framework):** `strix/mcp_servers/base.py` — `ScopeGuard` (loads the policy *in the subprocess*
and gates targets **fail-closed for the new domains**: no `scope.yaml` ⇒ refuse, unlike the web/MCP
boundary), `ok`/`error`/`result` JSON-string helpers (a `stdio` server must never `print` — stdout is the
protocol), and `build_server` (a `FastMCP` stdio server). `mcp.server.fastmcp` and `boto3` are both already
present (the latter transitively via `litellm`). Tests: `tests/test_strix2_mcp_wrapper_base.py` (8).

**Built (AWS read-only wrapper):** `strix/mcp_servers/aws.py` — `aws_whoami` (STS identity → names the
principal per validator decision 4.3a), `s3_list_buckets`, `s3_get_bucket_public_status` (composes a
`looks_public` **candidate** signal from ACL/policy-status/public-access-block, read-only), and
`s3_get_object_head` (a bounded **≤1 KiB** object read capturing request + response head + SHA-256 — the
**validation evidence** per decisions 4.3b/5a). Every tool resolves the caller account via STS and refuses
unless it is in `cloud.aws_account_ids`; all tools are read-only (no state change). A client-factory seam
injects a fake boto3 in tests, so the suite needs no AWS creds or network. Tests:
`tests/test_strix2_mcp_aws.py` (15). This exercises the acceptance walk-through (§8 of the validator doc):
public-bucket signal → candidate; bounded read → validated evidence.

**Registration model.** `strix/mcp_servers/registry.py::aws_wrapper_config()` emits the
`McpConnectionConfig` (a `stdio` entry: `<python> -m strix.mcp_servers.aws`, tight `allowed_tools`,
forwards `STRIX_SCOPE_CONFIG`/`STRIX_ALLOW_INTRUSIVE` to the subprocess). An operator can still register it
by hand in `~/.strix/mcp-servers.json` (or `--mcp-config`). CI blocking gate extended to lint+typecheck
`strix/mcp_servers`.

**Auto-wire (done).** The command-line run path now attaches the applicable built-in wrappers automatically
via `configs_with_builtins(load_user_mcp_configs())` (one small, logged edit in `core/runner.py`).
`applicable_builtin_configs` is deliberately conservative: the AWS wrapper is attached **only when the
active scope authorizes an AWS account** (`cloud.aws_account_ids` non-empty) — so a pure web run never
spawns a cloud subprocess — never when the user already configured a `strix-aws` connection (theirs wins),
and never when `STRIX2_AUTO_WRAPPERS` is falsey. Scope is loaded first (`install_strix2_extensions` at
`runner.py:231`) so the policy is available when requests are built. The SaaS/pro path
(`mcp_connection_requests`) is untouched. Tests in `tests/test_strix2_mcp_aws.py`.

**Template fix (found via the Linux CI baseline, 2026-10-01).** The shipped `scope.yaml` template had
`cloud.aws_account_ids: ["123456789012"]` populated, so *every* run started from the repo root auto-attached
the AWS wrapper — which leaked into the upstream runner tests (`test_runner_mcp`, `test_runner_root_prompt`)
as an unexpected `mcp_available: True`. These had failed silently since Phase 1: the CI blocking job runs only
`test_strix2_*`, and the upstream pytest baseline never ran because the full-repo ruff step exited first (now
`continue-on-error`). Fix: ship the template with `aws_account_ids: []` (example moved to a comment), matching
the auto-wire's documented "only when the scope authorizes an AWS account" intent — a template should not
silently arm a cloud wrapper. No product-code change; the strix2 tests set their own policy and are unaffected.

**AWS wrapper — IAM read-only (added).** `iam_list_principals` (users/roles recon) and
`iam_analyze_principal(name, principal_type)` — reads a principal's attached managed + inline policies and
flags over-permissive `Allow` statements (a full action wildcard `*`, or a service wildcard like `s3:*` on
all resources; `admin` marks the classic `*`/`*`) as a **candidate** signal per validator §4.3 ("an IAM
policy granting `*`" is a candidate, not a finding — validate by demonstrating a should-be-denied action as
the least-priv principal). Read-only; the analysis helper is pure and handles IAM's URL-encoded policy
documents. `TOOL_NAMES` (single source of truth for the connection allowlist) updated; 12 more tests.

**AWS wrapper — EC2 + Secrets Manager read-only (added).** `ec2_list_open_security_groups(region)` flags
inbound rules open to `0.0.0.0/0` / `::/0` with the exposed protocol/port range (validator §4.3 explicitly
lists "a security group open to `0.0.0.0/0`" as a **candidate**); `secretsmanager_list_secrets(region)`
enumerates secret **names + metadata only** — it deliberately never calls `GetSecretValue` (reading a
secret value is sensitive exfiltration, out of scope for this read-only wrapper). Both regional, scope-gated,
read-only. 6 more tests (fake ec2/secretsmanager injected). The AWS wrapper now exposes 8 read-only tools
(S3 ×4, IAM ×2, EC2 ×1, Secrets ×1).

**Known verification gap.** The wrapper's *live* behavior (real subprocess spawn + MCP connect + real AWS)
is not covered by an automated test — it needs AWS creds and a lab account. Unit tests cover scope gating,
argument handling, evidence shaping, tool registration, and the config. A live integration test is
deferred to an environment with credentials (or the managed cloud). Also to verify there: that the `mcp`
`stdio` transport forwards the passthrough env and inherits CWD as assumed.

**AWS wrapper — RDS + EBS-snapshot + KMS read-only (added, depth increment).** Five more read-only,
scope-gated tools, same candidate framing and fake-injected tests (no creds/network), bringing the wrapper
to **13 tools** across S3/IAM/EC2/RDS/KMS/Secrets: `rds_list_public_instances` (flags
`PubliclyAccessible=True` DBs), `rds_list_public_snapshots` (manual snapshots whose `restore` attribute
includes `all`), `ec2_list_public_snapshots` (EBS snapshots whose `createVolumePermission` grants the `all`
group), `kms_list_keys` (keys + aliases recon), and `kms_analyze_key_policy` (flags an `Allow` with a
wildcard `Principal` and **no confining `Condition`** — a conditioned cross-account grant is intentional and
*not* flagged, mirroring the IAM analyzer's precision bias). Each is a **candidate** signal (public flag /
shared-attribute / open key policy), never auto-promoted to a finding — validation still needs a
demonstrated consequence per the validator semantics. `TOOL_NAMES` stays the single allowlist source, so the
connection config picks the new tools up automatically; `README.md` tool table + `registry.py` notes
updated. Zero upstream edits. 18 more tests in `tests/test_strix2_mcp_aws.py` (53 total).

### Baseline scan via 9Router (dogfooding) — Phase 0 pipeline verified + first self-found fix

**2026-09-30.** Ran the first real end-to-end scan now that Docker is up, using the operator's local
**9Router** (an OpenAI-compatible gateway) as the LLM instead of a paid OpenRouter key — verified
connectable and wired (see the `strix-llm-via-9router` note for the config: `STRIX_LLM=openai/<id>` **must**
keep the `openai/` prefix, `LLM_API_BASE=http://localhost:20128/v1`). Command:
`uv run strix -n -t ./ --scan-mode quick --max-turns 25` with `openai/cc/claude-sonnet-5`.

- **Pipeline works end-to-end through 9Router:** `status: completed`, 22 LLM requests with tool-calls, the
  sandbox built and the report/SARIF/`run.json` artifacts were written (`strix_runs/strix2_4ef2/`).
- **0 validated findings** — correct: no PoC was built (the run hit the 25-turn budget first), so nothing
  was filed. The no-false-positive discipline held.
- **The scan found a real bug in our own Phase 0 scope code** and, correctly, recorded it as a
  `needs_follow_up` lead rather than a finding: `strix/scope/schema.py::_url_prefix_matches` used a plain
  `startswith`, so an authorized `api.base_urls` entry `.../v1` also matched `.../v1extra` (same-host
  path-scope widening; also a look-alike-host prefix match when a base has no path). **Fixed**: the match
  now requires a `/`, `?`, `#`, or end-of-string boundary after the base. Regression tests added
  (`test_api_base_url_requires_path_boundary`, `test_api_base_url_without_path_rejects_lookalike_host`).
- **Cost/perf note:** $5.27 for 22 turns (2.5M input tokens). 9Router returned **no prompt-cache hits**
  (`cached_tokens: 0`), so each turn re-billed the full ~100–140 K context — expensive per turn. Keep
  `--max-turns` low over 9Router, prefer a cheaper model (`ds/*`) for routine runs, and note Strix's
  `--max-budget-usd` did track cost here but cannot be relied on for arbitrary gateway model ids.

Phase 0 acceptance ("a **validated** web finding with a PoC") still needs a **running vulnerable web app**
as target; `-t ./` is a code review and proved the pipeline, not that gate.

## Phase 2 — Internal skills playbooks (started)

The agent's methodology library lives at `strix/skills/<category>/<name>.md` (loaded by `load_skill`,
assigned per child via `create_agent(skills=[...])`). Strix 2 adds its own playbooks in a **separate**
registered root, `strix/skills2/`, wired via `register_skill_dir(get_strix_resource_path("skills2"))` in
`install_strix2_extensions` — additive and rebase-safe (new files, no edit to the upstream skills package;
same-name files would shadow, so ours use distinct names). Registered dirs are searched ahead of the
built-ins, and `strix/skills2/**/*.md` ships in the wheel like the other packaged non-`.py` resources.

**Landed (4 playbooks):** each is scoped, evidence-first, wired to Strix's actual tools + the two-tier model,
and ends with the validator §5 evidence bundle and the no-false-positive rules (read-only preferred,
intrusive gated, config/version/banner-only stays a candidate, out-of-scope ⇒ stop):
- `cloud/aws_pentest.md` — drives the `strix-aws` wrapper (principal → recon candidates → validated read).
- `network/network_pentest.md` — in-sandbox `nmap`/`naabu`/`httpx`/`nuclei`; open port/banner/version-CVE are
  candidates, a demonstrated live-service consequence with captured I/O is the finding.
- `infra/infra_pentest.md` — `trivy`/`semgrep` static hits are candidates; runtime demo or a reachable path
  (reusing the dependency reachability ladder) validates.
- `api/api_pentest.md` — OWASP API Top 10 on the Caido proxy; upstream's verified `http_exchange_ids` bar is
  unchanged, a captured cross-principal/forged-request impact is the finding.

Tests: `tests/test_strix2_skills.py` (discovery + load for all four).

**External-skill assessment (asked by the maintainer).** Reviewed `mukul975/Anthropic-Cybersecurity-Skills`
(818 skills, Apache-2.0, MITRE/NIST-mapped). Verdict: high-quality and directly relevant (network/api/infra/
cloud pentest), and license-compatible — but **not drop-in**: it's the agentskills/plugin format
(`skills/<name>/SKILL.md` + `scripts/agent.py`), generic and human-operator-oriented (Burp/Kali/RoE), and not
wired to Strix's tools, two-tier tiers, or scope engine; 818 of them would be noise. Decision: keep our
`skills2/` playbooks **original and tailored**, and **link** to the relevant external skills as further
reading (recorded in `THIRD_PARTY.md` as a referenced, non-vendored source). If we ever adapt substantive
text, we attribute it there and keep the Apache-2.0 notice.

## Phase 3 — Domain enforcement in the sandbox (started)

**Scope gate at the `exec_command` boundary.** The in-sandbox network CLIs (`nmap`/`naabu`/`nuclei`/`httpx`/
`curl`/…) are driven by the agent through the SDK's `exec_command` tool. A native tool that itself runs a CLI
in the sandbox was considered and **deferred**: the sandbox session lives inside the SDK's `Shell`-capability
closure (bound by the `SandboxAgent` runtime), not in Strix's run context, so a custom `@function_tool`
cannot cleanly reach it — reimplementing that would be deep, hard-to-test SDK coupling. Instead Strix 2 gates
**at the shell boundary**, mirroring the Phase 1 `call_mcp` check: `enforce_shell_command(command)`
(`strix/scope/enforcement.py`) is a no-op without a scope policy (upstream unchanged) and when the command
invokes no known network CLI; otherwise it scans the command for high-confidence targets (URLs/IPs/ARNs) and
refuses the first out-of-scope one. Wired into `factory._wrap_exec_command` (one small, logged edit); it
returns a clear refusal string, not an exception, so the agent adapts. This is **generic across every
in-sandbox network CLI**, not a single nmap tool.

Together with the `network_pentest` skill (candidate discipline) and the candidate tools, the in-sandbox
network CLIs now carry the Strix 2 scope + two-tier discipline. Tests:
`tests/test_strix2_scope_enforcement.py`.

**Pre-seeded domain specialists (done, prompt-level).** Specialization in this codebase is *name + task +
skills + prompt*, not subclasses, so the network/cloud/infra/api "specialist agents" are realized as
**delegation guidance in the root prompt**, not new classes. `strix/skills2/coordination/strix2_domains.md`
tells the root agent to read the scope and `create_agent(...)` one specialist per in-scope domain with the
matching skill (`cloud/aws_pentest`, `network/network_pentest`, `infra/infra_pentest`, `api/api_pentest`),
and to hold the two-tier discipline. It loads via a one-line append in `prompt._resolve_skills` (root only)
and renders through the template's existing generic skill loop — **no template edit**. The root prompt now
names all four specialists and the candidate→validated rule (verified in `tests/test_strix2_skills.py`).

**Deferred (needs an SDK sandbox seam):** structured native tools that themselves run a CLI in the sandbox
and parse its output (the sandbox session is not reachable from a custom `@function_tool`). The exec/MCP
boundary gates, the domain skills, and the root delegation guidance cover the discipline in the meantime.

## Phase 4 — Generalized finding + PoC validator (in progress)

Semantics signed off (`04-validator-semantics.md`, all defaults). Landed the **candidate (lead) tier** —
the low-bar half of the two-tier model — as an additive package plus one 2-line hook in `core/runner.py`.

**Built:**
- `strix/candidates/` — `Candidate` schema (pydantic, `extra=forbid`, `dedup_key`, status lifecycle) and
  `CandidateStore` (in-run store, `cand-NNNN` ids, structural dedup against open candidates *and* validated
  findings per decision 3a, persists `candidates.json` beside `vulnerabilities.json`, promote/dismiss).
- `strix/tools/candidates/tools.py` — `create_candidate`, `list_candidates`, `promote_candidate`,
  `dismiss_candidate` (`@function_tool`s). Deliberately omits `from __future__ import annotations` so the
  SDK resolves the `RunContextWrapper` context annotation at registration without a ruff `TC002` ignore.
- `strix/strix2_ext.py::install_strix2_extensions(run_dir)` — idempotent bootstrap that registers the
  candidate tools via the (previously caller-less) `register_agent_tools` seam and binds the store to the
  run dir. Wired in at the top of `run_strix_scan` (the single core edit).
- `tests/test_strix2_candidates.py` — 13 tests (schema, dedup incl. cross-tier, lifecycle, persistence,
  registration/idempotency). All green; ruff + mypy clean. CI blocking gate extended to lint+typecheck the
  new code.

**Design choices:** candidates are a *separate* store (no edit to `ReportState`) so they stay rebaseable;
they never enter the finding count; dedup is structural now (deterministic/testable), with semantic LLM
dedup as a follow-up. Attribution (`agent_id`/`agent_name`) is captured on each candidate.

**Leads rendering (decision 3b) — done.** `strix/candidates/writer.py` renders `LEADS.md` (written by the
store on every persist) and the "Leads (unvalidated)" section appended to `penetration_test_report.md`
(one guarded, logged `write_executive_report` edit — no-op for upstream-only runs). 5 more tests; report
writer + import-warmup suites stay green (119 passed).

**Finding-annotation sidecar (done) — optional ATT&CK/CIS/domain metadata.** Rather than edit the complex
upstream `create_vulnerability_report` / `ReportState` to add optional fields (high-risk surgery on the crux
module), Strix 2 adds an **additive sidecar** that mirrors the candidate store: `strix/findings2/`
(`FindingAnnotation` schema + `FindingAnnotationStore`) + the `annotate_finding` / `list_finding_annotations`
tools. After filing a finding with `create_vulnerability_report`, the agent calls `annotate_finding(vuln_report_id, domain, mitre_attack, cis_benchmark, notes)` to record the validator §6 optional metadata — MITRE ATT&CK
technique ids (validated `T####[.###]`), CIS control ids, the finding's domain, and a short pointer to the
captured domain evidence. It **never gates or changes a finding** (decision 6a); CVSS+CWE stay the required
rating on the finding itself. Persists `finding_annotations.json` + `FRAMEWORK_MAP.md` beside
`vulnerabilities.json`; wired in `strix2_ext`; **zero upstream edits**. Tests:
`tests/test_strix2_finding_annotations.py`.

The **domain evidence channel** itself is the finding's existing required `evidence` field (captured raw
I/O), which the domain skills already instruct the agent to fill (command+response, cloud
principal+policy+region, runtime repro); the sidecar's `notes` points at it and the `domain` tags the class.

**SARIF framework-tag emission (done).** `strix/findings2/sarif_enrich.py` folds the sidecar's ATT&CK/CIS/
domain tags into the written `findings.sarif`: it matches each SARIF result to its annotation by the finding
id (`result.properties.strix.id` == the `vuln-NNNN` the agent passes to `annotate_finding`), adds
`mitre:*` / `cis:*` / `domain:*` tags to that result's rule (so code-scanning / ASPM can filter by them) and
a per-finding `result.properties.strix.frameworks` block. It runs as a **post-write enrichment** of the
already-emitted file, so the upstream SARIF emitter (`sarif.py`) is **untouched**; the only wiring is one
guarded, logged line in `report/state.py` (no-op without annotations). Atomic rewrite, idempotent. Tests:
`tests/test_strix2_sarif_enrich.py` (8: tag/frameworks emission, CIS, unmatched-id + empty no-ops, file
round-trip + idempotency, end-to-end from the store).

**Not yet:** first-class network/cloud `finding_class` values inside the upstream schema (would need the
`_VALID_FINDING_CLASSES` whitelist + a `finding_class` param threaded through `create_vulnerability_report`
→ `add_vulnerability_report` → writer/SARIF — deferred as a deliberate, larger edit to the crux module; the
sidecar `domain` covers classification additively, and it now rides in the SARIF too); scope-coupled proof
helpers.

## Phase 5 — model router + no-progress guard (started)

Per the codebase map §7, the budget/turn/per-turn guards already exist upstream, so Phase 5 is *enhance*,
additive and opt-in.

**Per-role model router (`strix/router/`).** Mirrors the `DedupeSettings` precedent (a separate model for a
sub-task). `RouterSettings` (`STRIX2_ROUTER` to enable, `STRIX2_RECON_MODEL` for the cheap model);
`role_for_skills` classifies a child as `recon` (cheap) only for clearly recon/enumeration/mapping skills —
every domain *pentest* skill stays `default` (frontier), a conservative bias that never under-powers
exploitation; `resolve_agent_model(skills, is_root=…)` returns the routed model, with the **root always on
the main model**. Wired in `factory.build_strix_agent` (`SandboxAgent(model=resolve_agent_model(...))`);
returns `None` (⇒ global default) unless enabled, so default behavior is unchanged. This directly attacks the
9Router cost profile (no prompt caching → recon fan-out on a cheap model saves the most).

**No-progress guard (`strix/guard/`).** `NoProgressDetector` is a pure, in-memory detector for the missing
*cross-turn* signal: it flags a `repeated_call` (same tool + identical args N× in a row) or a `no_coverage`
window (a run of calls with no coverage growth). Advisory — the caller nudges then stops. Complements the
existing per-turn cap and budget/turn ceilings without rebuilding them.

Tests: `tests/test_strix2_router.py` (role classification, selection, resolution, env config, both stall
signals, reset). CI gate extended to `strix/router` + `strix/guard`.

**No-progress guard wired in (done, opt-in).** `NoProgressDetector` is now driven through the SDK
**run-hooks lifecycle** rather than the raw turn loop — the cleaner seam. `strix/guard/hooks.py` adds
`ProgressGuardHooks(ReportUsageHooks)`: `on_tool_start` feeds one detector per agent (keyed by `agent_id`,
since a single hooks instance is shared across every agent in a scan), fingerprinting on the tool **name**
(the SDK's `on_tool_start` does not expose call arguments); on a stall signal it injects an escalating
**advisory** message on the agent's next `on_llm_start` by appending to `input_items` — the exact mechanism
`ReportUsageHooks` already uses for budget/turn warnings. It is **advisory only** (never force-stops; the
turn/budget ceilings stay the hard stops) and self-limiting (`max_nudges` per agent, re-arming once per
stall) so the guard can never itself loop. `build_run_hooks(...)` returns the plain hooks unless
`STRIX2_PROGRESS_GUARD` is set (`STRIX2_PROGRESS_REPEAT` / `STRIX2_PROGRESS_MAX_NUDGES` tune it), wired via
the one logged `runner.py` swap above — so default behavior is unchanged. Tests:
`tests/test_strix2_progress_guard_hooks.py` (10: factory opt-in, threshold, alternating-tools negative,
per-agent isolation, cap, re-arm, final-nudge wrap-up advice, best-effort robustness).

**Cross-run recon caching (done, additive, scope-gated).** Recon (port scans, enumeration, cloud listings)
is expensive and repeats across runs; over a gateway with no prompt caching (9Router) every recon turn the
agent doesn't repeat is context it isn't re-billed for. `strix/cache/` is a **shared on-disk store** living
*outside* any run dir (default `~/.strix/recon_cache`, `$STRIX2_RECON_CACHE_DIR` to override), one atomic
JSON file per entry keyed by `(normalize_tool, normalize_target, params)` with a TTL (default 24h); disable
with `STRIX2_RECON_CACHE=0`. The agent reaches it through three `@function_tool`s (`recon_cache_get` /
`recon_cache_put` / `recon_cache_stats`) in `strix/tools/cache/`, each **scope-gated** via `enforce_target`
(an out-of-scope target is refused), registered via `strix2_ext` — **zero new upstream edits**. The tool
bodies live in plain `_do_*` helpers (directly unit-testable); the wrappers only pull caller identity.
**Deliberately not** auto-served at the `exec_command` boundary: transparently returning a cached scan would
present stale recon as fresh, so the cache is explicit and every hit is stamped with its age + a "re-verify
time-sensitive state" note. Wired into the methodology by short "reuse recon across runs" notes in the
network / cloud / infra playbooks (the cloud recon table also gained the new RDS/EBS/KMS tools). Tests:
`tests/test_strix2_recon_cache.py` (20: key normalization, TTL/max-age freshness, round-trip, too-large,
purge/clear/stats, disabled, scope refusal, registration). CI gate extended to `strix/cache` +
`strix/tools/cache`.

**Not yet:** native in-sandbox CLI tools that run+parse a scan remain deferred on the SDK sandbox seam
(Phase 3); auto-populating the recon cache from those tools' output would then be a natural follow-up.

## Phase 6 — evaluation lab + honest metrics (started)

The scoring **engine** (`strix/eval/`) is code; the eval **lab** (target apps + ground-truth files) is
documented in `docs/strix2/06-eval-lab.md`. `metrics.score(findings, ground_truth, candidates, cost)` returns
a `Scorecard`: finding-level **precision**, GT-level **recall**, **F1**, the two-tier **candidate recall**
(an issue surfaced as a lead counts here, not toward findings — so precision is never inflated by filing leads
as findings), and **$-per-finding / $-per-TP** from the run's real `llm_usage.cost`. A finding matches a
ground-truth entry on normalized target + optional `title_contains`/`cwe` refiners; a *candidate* matches on
target (+ title) only, since leads carry no CWE. `harness.score_run(run_dir, gt)` reads a completed run's
`vulnerabilities.json` / `candidates.json` / `run.json`, and `python -m strix.eval <run_dir> <gt.yaml>`
prints a markdown or `--json` scorecard. Pure + fully unit-tested (`tests/test_strix2_eval.py`), no run
required. CI gate extended to `strix/eval`.

**Ground-truth templates (added).** Shipped `eval/` with copy-ready ground-truth templates —
`ground_truth/juice-shop.example.yaml`, `dvwa.example.yaml`, `aws-cloud-lab.example.yaml` — plus
`eval/README.md` and a `targets/` placeholder. They are expected-finding **metadata only**: no target is
stood up and no account is authorized by them (authorization + the live lab stay the operator's, same rule
as any run). The `.example.yaml` naming signals "copy, re-target, prune." `tests/test_strix2_eval_examples.py`
discovers each template, asserts `id`/`target` present + unique ids, and scores a synthetic perfect run
against it so the targets provably normalize + match — guarding the templates against scoring-schema drift.
The cloud template deliberately exercises the new RDS/EBS/KMS checks. Zero upstream edits.

**Not yet:** committing concrete lab *targets* themselves (the operator's authorized labs), and a multi-run
trend/regression report across model/scope/scan-mode changes.
