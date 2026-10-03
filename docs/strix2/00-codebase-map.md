# Strix 2 — Codebase Map (Phase 0)

> Fork base: `usestrix/strix` @ `ae38fe70` (`main`, 818 commits, cloned 2026-09-26),
> upstream package version `strix-agent` **1.6.2**.
> This document is the ground-truth map required by Phase 0 §3 of the build brief.
> **Where this map disagrees with the brief, the map wins** — several mechanisms
> the brief calls missing already exist upstream (flagged as ⚠️ *brief-outdated*).

---

## 0. TL;DR — the seams that matter

| Concern | Where it lives | How Strix 2 plugs in (rebase-safe) |
|---|---|---|
| **Native tool registry** | `strix/agents/factory.py` → `_BASE_TOOLS` + `register_agent_tools()` / `_EXTRA_TOOLS` | Call `register_agent_tools(*tools)` at startup — no edit to `_BASE_TOOLS` needed. |
| **Graph of Agents** | `strix/tools/agents_graph/tools.py` + `strix/core/agents.py` (`AgentCoordinator`) | Agents are **dynamic** (`create_agent(name, task, skills)`), not per-domain classes. Specialize via skills + prompt, not subclasses. |
| **Finding + PoC gate** | `strix/tools/reporting/tool.py` (`create_vulnerability_report`) + `strix/report/state.py` (`ReportState`) | Single-tier today (`finding_class ∈ {dynamic, dependency_cve}`). Phase 4 adds a candidate tier here. |
| **MCP integration** | `strix/tools/mcp/*`, config at `~/.strix/mcp-servers.json` (a **JSON list**) | Add stdio/http server entries with tight `allowed_tools`. Phase 1 lever. |
| **Skills (methodology)** | agent-internal: `strix/skills/<category>/<name>.md`; plus `register_skill_dir()` | Drop new `.md` playbooks in a registered dir — no package edit. Phase 2 lever. |
| **Scope / authorization** | ❌ **does not exist** (only `interface/url_safety.py`, a web-URL sanity check) | Net-new `scope.yaml` + `strix/scope/` module + tool-boundary enforcement. |
| **Budget / turns / loop guard** | ⚠️ mostly exists: `--max-budget-usd`, `--max-turns`, `_TurnGuardModel` | Phase 5 becomes *enhance* (model router, caching), not *build from scratch*. |

---

## 1. Repository layout (verified)

```
strix2/
├─ strix/                     # main package (entry: strix.interface.main:main)
│  ├─ agents/                 # 3 files — factory.py, prompt.py  (NO per-domain agent classes)
│  ├─ config/                 # settings.py, models.py, loader.py, tool_call_limits.py …
│  ├─ core/                   # runner.py, execution.py, agents.py (AgentCoordinator), hooks.py …
│  ├─ interface/              # 45 files — CLI, TUI, cloud SaaS client, viewer, url_safety.py
│  ├─ llm/                    # compaction.py, context_budget.py, request_log.py, warmup.py
│  ├─ report/                 # state.py, writer.py, dedupe.py, sarif.py, coverage.py, pricing.py
│  ├─ runtime/                # docker_client.py, session_manager.py, backends.py, caido_* …
│  ├─ skills/                 # AGENT-INTERNAL skills (<category>/<name>.md) + loader (__init__.py)
│  ├─ telemetry/              # posthog, scarf, logging
│  ├─ tools/                  # 37 files — the native toolset (see §3)
│  └─ utils/                  # api_spec.py, resource_paths.py, secret_files.py
├─ skills/                    # TOP-LEVEL plugin/marketplace skills (SKILL.md per dir) — NOT agent-internal
├─ containers/                # Dockerfile (sandbox image) + docker-entrypoint.sh
├─ benchmarks/                # (upstream benchmark harness)
├─ tests/                     # 96 pytest files (asyncio_mode=auto)
├─ docs/                      # upstream docs + docs/strix2/ (ours)
├─ scripts/
├─ pyproject.toml             # Python >=3.12; deps incl. pyyaml, docker, cvss, openai-agents[litellm]
├─ uv.lock
└─ AGENTS.md                  # contributor guide
```

**Two distinct skill systems — do not confuse them:**
- `skills/<name>/SKILL.md` (top level, 9 dirs): Claude-Code-style *plugin* skills that describe how a
  human/host drives Strix (e.g. `penetration-testing-with-strix`, `api-security-testing`). External.
- `strix/skills/<category>/<name>.md` (60+ files): the **agent's** internal reference library, loaded by
  the `load_skill` tool and assigned per child via `create_agent(skills=[...])`. **This is Phase 2's target.**

---

## 2. The agent loop & run lifecycle

- **Entry**: `strix = strix.interface.main:main` → `interface/cli_args.py` (arg parsing) →
  `interface/scan_setup.py` (targets) → `core/runner.py` (orchestration) → `core/execution.py` (per-agent turn loop).
- **Agent construction**: `strix/agents/factory.py::build_strix_agent(...)` builds an
  `agents.sandbox.SandboxAgent` (from the vendored `openai-agents` SDK) with:
  - `instructions` = `agents/prompt.py::render_system_prompt(skills, scan_mode, is_whitebox, is_root, …)`
  - `tools` = `_BASE_TOOLS` + `_EXTRA_TOOLS` (registered) + lifecycle tool (`finish_scan` for root / `agent_finish` for child)
  - `capabilities` = `Filesystem` + `Shell` (these emit the sandbox-bound `exec_command`, `write_stdin`, file tools per run)
  - `tool_use_behavior` = `_finish_tool_use_behavior` — the run only ends when a **lifecycle tool** returns success.
- **Turn mechanics** live in the SDK; Strix wraps every model call in `config/models.py::_TurnGuardModel`
  (tool-call-per-turn cap, tool-call-id rewriting, stalled-stream idle timeout) and `StrixProvider`
  (LiteLLM routing, OpenRouter cost capture, ChatGPT-subscription backend).
- **Tool result hygiene**: `factory.py` wraps every FunctionTool with `_with_coerced_arguments`
  (JSON string↔object coercion for weak tool-callers), `_with_bounded_result` (size caps from
  `ContextSettings`), and `_function_tool_with_error_result` (errors returned as model-visible results,
  not exceptions). **Any native tool we add inherits this automatically** if registered as a `FunctionTool`.

---

## 3. The tool registry (native tools)

Declared as SDK `FunctionTool`s (via `@function_tool`) in `strix/tools/<family>/tool[s].py`, imported and
composed in `strix/agents/factory.py::_BASE_TOOLS`. Current families:

| Family | Module | Tools (abridged) |
|---|---|---|
| thinking | `tools/thinking/tool.py` | `think` |
| skills | `tools/load_skill/tool.py` | `load_skill` |
| todo | `tools/todo/tools.py` | `create_todo`, `list_todos`, … |
| notes | `tools/notes/tools.py` | `create_note`, `get_note`, … |
| coverage | `tools/coverage/tools.py` | `record_coverage`, `list_coverage`, `update_coverage` |
| threat model | `tools/threat_model/tools.py` | `save_threat_model`, `get_threat_model`, `amend_threat_model` |
| web search | `tools/web_search/tool.py` | `web_search`, `web_get_contents` |
| **reporting** | `tools/reporting/tool.py` | `create_vulnerability_report`, `create_dependency_report`, `update/delete_vulnerability_report`, `list_reports`, `get_report` |
| **proxy** (Caido) | `tools/proxy/tools.py` | `list_requests`, `view_request`, `repeat_request`, `list_sitemap`, `view_sitemap_entry`, `scope_rules` |
| **MCP bridge** | `tools/mcp/agent_tools.py` | `list_mcps`, `search_mcp_tools`, `get_mcp_tool_schema`, `describe_mcp`, `call_mcp` |
| **agent graph** | `tools/agents_graph/tools.py` | `create_agent`, `send_message_to_agent`, `wait_for_agents`, `view_agent_graph`, `stop_agent`, `agent_finish` |
| respond | `tools/respond/tool.py` | `respond_to_user` (interactive only) |
| finish | `tools/finish/tool.py` | `finish_scan` |

**Extension seam (Phase 3):** `register_agent_tools(*tools)` appends to `_EXTRA_TOOLS`, which every
root+child agent picks up. `registered_agent_tools()` reads them back. Names must be globally unique
(`_ensure_unique_tool_names`). This is the exact hook used by `runtime/backends.py::register_backend`, so
there is precedent for registering at startup without touching `factory.py`.

`proxy/tools.py` is the **exemplar for a sandbox-facing native tool** (talks to the in-sandbox Caido
proxy through the run context) — mirror it for structured network/cloud tools that need sandbox I/O.

---

## 4. Graph of Agents

- Backed by `core/agents.py::AgentCoordinator` (status map, parent map, per-agent inbox, message pump).
- **Agents are created dynamically at runtime**, not defined as classes. `create_agent(name, task,
  inherit_context, skills)` calls a runner-provided `spawn_child_agent` closure
  (`agents/factory.py::make_child_factory`) that builds another `SandboxAgent` with the requested skills.
- Specialization = **name + task + 1–5 skills + system prompt**, nothing more. So a "network-agent" or
  "cloud-agent" (Phase 3) is realized as: (a) the right skills exist (Phase 2), (b) optionally a
  pre-seeded spawn from the root prompt, (c) domain native tools registered globally (Phase 3).
- Coordination tools: `send_message_to_agent`, `wait_for_agents` (blocks on inbox), `view_agent_graph`,
  `stop_agent` (graceful cascade). Children report up via `agent_finish` → parent inbox; **filed
  vulnerability reports are read back from `ReportState`, not trusted from the child's prose.**

---

## 5. Finding model + the PoC gate (Phase 4 crux)

**Creation** — `tools/reporting/tool.py::create_vulnerability_report` (a `@function_tool`). The PoC-or-it-
didn't-happen ethos is enforced here as **hard-required, non-empty fields** (`_REQUIRED_FIELDS`):
`title, description, impact, target, technical_analysis, poc_description, **poc_script_code**,
remediation_steps, **evidence**, assumptions` — plus a mandatory adversarial-review triad
(`counterevidence`, `confidence`, `severity_change_conditions`; `confidence_rationale` required when
confidence≠high). CVSS v3.1 is computed from an 8-metric `cvss_breakdown` (via the `cvss` lib) — the
severity is derived, never model-picked. HTTP evidence (`http_exchange_ids`) is **verified against the
live Caido project** before being stored (`_verify_http_exchange_ids`).

**Classes today** (`_finding_class_of`): `dynamic` (dynamically PoC'd) and `dependency_cve` (via
`create_dependency_report`, for lockfile CVEs that can't be dynamically PoC'd — rated with *contextual*
CVSS). **There is no `candidate` vs `validated` tier** — every filed report is treated as validated, and
that gate is web/HTTP-shaped (Caido exchange IDs, `code_locations` for white-box).

**Storage / output** — `report/state.py::ReportState` (global singleton via `get_global_report_state()`):
`add/update/delete_vulnerability_report`, `get_existing_vulnerabilities`. Writers in `report/writer.py`
(executive report, `vulnerabilities.*`), `report/sarif.py` (SARIF), `report/coverage.py`.
**Dedup** — `report/dedupe.py::check_duplicate` is **LLM-based** and uses a *separate* configurable model
(`DedupeSettings`, see §7) — the precedent for a per-task model router.

> **Phase 4 implication.** The gate generalizes conceptually (demonstrated impact + captured I/O +
> counterevidence), but its *evidence hooks are web-specific* (Caido IDs, code_locations). Network/cloud/
> infra need their own evidence channels (captured request/response, attacker principal + policy, runtime
> repro) and a **candidate tier** so scanner/recon output is surfaced as a lead, not a finding. This is
> the design decision to confirm with the maintainer before coding (per brief §5).

---

## 6. MCP integration (Phase 1 lever)

- **Config file**: `~/.strix/mcp-servers.json` — a **JSON _list_** of server entries (NOT the
  `{"mcpServers": {...}}` object format used by some clients). Loader: `tools/mcp/loader.py`
  (`load_user_mcp_configs`); schema: `tools/mcp/config.py::McpConnectionConfig` (pydantic, `extra="forbid"`).
- **Per-entry fields**: `name` (namespaces the tools, unique per run), `transport` (`http`|`stdio`),
  `url` (http) or `command`+`args`+`env` (stdio), `auth` (bearer), **`allowed_tools`** (allowlist applied
  after listing — `None` = expose all), `active_tools` (ranked subset), `notes` (purpose line shown to the
  agent), and timeouts / `max_concurrent_calls`.
- **Overrides**: env `STRIX_MCP_CONFIG` (path), `STRIX_MCP_ONLY` / `STRIX_MCP_EXCLUDE` (per-run include/
  exclude by name); CLI flags `--mcp-config`, `--mcp-server`, `--mcp-exclude` set those env vars.
- **Loading is fail-open**: bad entries are logged & skipped; a missing file → no MCP connections.
- **Runtime**: `tools/mcp/{registry,client,session,loader}.py` hold live sessions; the agent reaches them
  via the MCP-bridge tools (`list_mcps`, `search_mcp_tools`, `call_mcp`, …) rather than one tool per
  server-tool. **Scope enforcement (Phase 1)** belongs at the wrapper/`call_mcp` boundary + inside each
  wrapper server.

---

## 7. Config, budgets, scan modes, model routing

`strix/config/settings.py` (pydantic-settings, env-driven):
- `LlmSettings` — `model` (`STRIX_LLM`), `reasoning_effort` (default `high`), `max_tool_calls_per_turn`
  (32), timeouts, prompt cache. Routing/provider logic in `config/models.py` (`StrixProvider`,
  LiteLLM/OpenRouter/Codex-subscription paths, `RECOMMENDED_MODEL_NAMES`, `FRONTIER_MODEL_PREFIXES`,
  `is_recommended_or_frontier_model`).
- `DedupeSettings` — **a separate model/endpoint just for the dedup judge** (`STRIX_DEDUPE_MODEL`, …).
  ⚠️ This is a working precedent for the Phase 5 model router (cheap model for a sub-task).
- `ContextSettings` — auto-compaction, tool-output caps (`tool_output_max_tokens/lines/bytes`).
- `RuntimeSettings` — sandbox `image` (`ghcr.io/usestrix/strix-sandbox:1.3.0`), `backend` (`docker`).

**Scan modes** (`-m/--scan-mode` = `quick|standard|deep`, default `deep`) select a methodology skill from
`strix/skills/scan_modes/{quick,standard,deep}.md`. `--scope-mode` (`auto|diff|full`) is **code-diff
scope**, *not* authorization scope — unrelated to `scope.yaml`.

⚠️ **Brief-outdated — these already exist** (`interface/cli_args.py`):
- **`--max-budget` / `--max-budget-usd`**: "scan stops cleanly when this limit is reached; graduated
  wrap-up warnings sent to all agents as it approaches." (tested: `tests/test_e2e_budget_lifecycle.py`).
- **`--max-turns`** (default 500) with graduated wrap-up warnings.
- **Loop/failure guardrails** partially exist: `_TurnGuardModel` (per-turn tool-call cap + stalled-stream
  idle timeout + tool-call-id repair), `config/tool_call_limits.py`, model retry policy in `config/models.py`.

So **Phase 5 = *enhance*, not *build***: add the recon-cheap/exploit-frontier **router**, tool-output
**caching/dedupe across runs** (only per-output size bounding + LLM finding-dedup exist today), and a
**no-progress / repeated-identical-call loop detector** (turn-level cap exists; a cross-turn progress
guard does not).

---

## 8. Sandbox image & tool availability (decides Phase 1 shape)

`containers/Dockerfile` (base `kalilinux/kali-rolling`) ships, in-sandbox, reachable via `exec_command`:
- **Network/recon**: `nmap` (+`cap_net_raw`), `ncat`, `ndiff`, `naabu`, `subfinder`, `httpx`, `katana`,
  `gospider`, `dnsutils`, `whois`, `interactsh-client`. (No `masscan`.)
- **Web/app**: `sqlmap`, `ffuf`, `wapiti`, `arjun`, `dirsearch`, `wafw00f`, `nuclei` (+templates),
  `agent-browser`/`chromium`, `jwt_tool`, Caido CLI (proxy).
- **Code/infra/secrets**: `semgrep`, `bandit`, `ast-grep`, `trivy`, `govulncheck`, `retire`, `trufflehog`,
  `gitleaks`, tree-sitter grammars. (No `checkov`.)
- **❌ No cloud tooling**: no `awscli`, `prowler`, `scoutsuite`, `cloudfox`, `az`, `gcloud`.

**Consequence.** Network + infra domains are largely *tooling-present, discipline-absent*: the tools exist
in-sandbox but there's no validation tier or specialist coordination. **Cloud is genuinely absent**: the
`strix/skills/cloud/aws.md` methodology (231 lines) assumes an `aws` CLI that isn't installed, and cloud
creds should **not** be shipped into the sandbox. → Cloud belongs in **host-side MCP wrappers / native
tools** holding the user's creds, gated by `scope.yaml` on account IDs. This shapes Phase 1/3.

Pre-existing internal skills relevant to the new domains already present under `strix/skills/`:
`cloud/{aws,azure,gcp,kubernetes}.md`, `reconnaissance/{asset_discovery,infrastructure_lifecycle}.md`,
`tooling/{nmap,naabu,nuclei,subfinder,httpx,katana,ffuf,sqlmap,semgrep,…}.md`. Phase 2 extends/sequences
these into end-to-end playbooks rather than starting from zero.

---

## 9. Tests & CI

- **Tests**: 96 files under `tests/` (pytest, `asyncio_mode=auto`). Relevant exemplars for our work:
  `test_agent_tool_registration.py`, `test_cli_mcp_config.py`, `test_dedupe_model.py`,
  `test_e2e_budget_lifecycle.py`, `test_agent_graph_coordination.py`, `test_finish_coverage_gate.py`.
- **CI**: only `.github/workflows/build-release.yml` (runs on `v*` tags — builds binaries/wheels).
  **There is no test/lint CI workflow.** → Phase 0 adds `.github/workflows/ci.yml` (net-new, additive).
- **Lint/type**: `ruff`, `mypy`, `pyright`, `bandit`, `pre-commit` (`.pre-commit-config.yaml`); `Makefile`
  wraps common targets. Dev tooling via `uv sync --dev`.

---

## 10. What's genuinely missing (the real Strix 2 backlog)

1. **Authorization scope** — no `scope.yaml`, no `--allow-intrusive`, no tool-boundary enforcement. *(net-new)*
2. **Candidate vs Validated finding tiers** + per-domain evidence channels (network/cloud/infra). *(Phase 4)*
3. **Cloud tooling & a cloud specialist** — host-side, creds-outside-sandbox, account-ID scoped. *(Phase 1/3)*
4. **Domain playbooks** that chain the existing tools into validated flows. *(Phase 2)*
5. **Model router** (recon-cheap / exploit-frontier) + **cross-run recon caching** + **no-progress loop guard**. *(Phase 5)*
6. **Honest multi-domain eval lab** + precision/recall/$-per-finding. *(Phase 6)*
7. **`THIRD_PARTY.md`** licenses for every wrapped external tool. *(ongoing)*

Already-present-and-reusable (do **not** rebuild): budget cap, turn cap, per-turn loop guard, LLM
finding-dedup, SARIF/report writers, MCP client, skill loader with `register_skill_dir`, agent-tool
`register_agent_tools`, in-sandbox network/web/infra tools.
