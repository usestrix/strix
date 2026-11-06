# Strix DSA Attack Path Analysis — Architecture (Phases 1–5)

Canonical copy also lives in the Project store at
`docs/strix-dsa-architecture.md` (agent store). Content below matches that plan.

## Purpose

Extend [Strix](https://github.com/usestrix/strix) (Apache-2.0 AI pentesting agent) with an **independent** graph DSA engine for attack-path analysis. Strix continues to discover and validate vulnerabilities; the DSA module ranks modeled reachability and choke points on a directed asset graph. This is a **thesis-layered module** beside Strix — not a rewrite of agents/scanners.

## Research summary (Strix)

| Area | Finding |
|------|---------|
| Stack | Python ≥3.12 (`uv`), Agents SDK / LiteLLM, Docker sandbox runtime, optional Go TUI sidecar, React local viewer |
| Agents | `strix/agents` + `strix/core/agents` coordinator; multi-agent graph via `strix/tools/agents_graph` |
| Findings | Agents call `create_vulnerability_report` (`strix/tools/reporting`); persisted by `ReportState` → `strix_runs/<run>/vulnerabilities.json`, markdown, CSV, `findings.sarif` |
| Key fields | `title`, `description`, `impact`, `target`, `endpoint`, CVSS/severity, evidence/PoC, `finding_class` (`dynamic` / `dependency_cve`) |
| Runtime | `strix/runtime` Docker sessions + Caido proxy for HTTP evidence |
| Dashboard | Local viewer (`strix/interface/viewer`) serves `/api/run`, `/api/vulnerabilities`, SPA under `static/` |
| Tests | `uv run pytest`; Makefile `check-all` |
| Integration hook | Post-scan read of `vulnerabilities.json` / SARIF; optional future `/api/attack-path` on the viewer — **do not** mutate Strix agent loops in Phase 1 |

Related prior art (ideas reused, not copied wholesale): local thesis project under `Downloads/Phan_tich_duong_tan_cong_DSA` (BFS hops, DFS simple paths with depth/path caps, Dijkstra on `-log(p)`, bottleneck by path frequency).

## High-level design

```
Strix scan / agent loops (unchanged)
    │
    ▼
strix_runs/<run>/{vulnerabilities.json, run.json}
    │
    │  explicit post-run CLI only (no agent hard-wire)
    ▼
Backend (Phase 3 ✓) → Bridge (Phase 2 ✓) → C++ engine (Phase 1 ✓)
    │
    ▼
strix_runs/<run>/attack_path/
  attack_graph.json | topology.txt | analysis.txt | meta.json
    │
    ▼
Viewer `/api/attack-path` + Attack path SPA tab (Phase 4 ✓)
```

- **Independent modules**: `dsa_attack_path/{,bridge/,backend/}`. Agent/scanner loops unchanged.
- **Thin Strix hook**: optional `strix attack-path` subcommand (`strix/interface/attack_path_cli.py`) delegates to the backend when present; missing module → friendly exit.
- **Product default**: `allow_simulated_lateral=False` (backend + UI checkbox off by default).
- **Simulated vs finding**: provenance + labels on every node/edge; never present modeled paths as confirmed multi-hop exploits.

## Graph data model

### Nodes (assets)

| Field | Role |
|-------|------|
| `id` | Stable integer key |
| `name`, `type`, `zone` | Display / topology grouping |
| `impact` | Business impact 0–100 (crown jewels) |
| `is_entry_point` | Likely attacker foothold |
| `is_crown_jewel` | High-value target |

Phase 2 mapping sketch: derive nodes from unique `target` / `endpoint` / host strings in Strix findings plus scan `targets_info`; severity/CVSS inform edge cost, not fabricated CVEs.

### Edges (access / exploit steps)

| Field | Role |
|-------|------|
| `from` → `to` | Directed modeled access |
| `protocol` | Context (HTTP, SSH, …) |
| `relation` | InternetExposed / CrossZoneAdmin / SameZoneData / LoggedJumpHost / Unclassified |
| `probability` | **Simulation weight** in (0,1] for ranking — not a real exploit probability |
| `status` | Active / Disabled / JumpHostForced (what-if scenarios) |

Cost for Dijkstra: `w = -log(p)` so maximum path-product probability ≡ shortest path. Edges with `p ≤ 0` are non-traversable.

### Analysis outputs

- **BFS**: reachability + fewest-hop path
- **DFS**: enumeration of simple paths (caps: `max_depth`, `max_paths`); truncation flags when incomplete
- **Dijkstra**: representative highest-product (lowest-cost) path + weakest link
- **Bottleneck**: edges ranked by frequency across enumerated paths (and crown-jewel reachability impact when marked)

## Python ↔ C++ boundary

**Phase 1:** native C++17 library + CLI. I/O: topology TXT + stdout summary.

**Phase 2 (bridge contract):** `dsa_attack_path/bridge/strix_dsa_bridge` (stdlib-only) reads Strix-shaped JSON and emits:

| Artifact | Role |
|----------|------|
| `attack_graph.json` | Full contract: disclaimer, counts, warnings, per-node/edge `provenance` + `finding_ids` + `labels` |
| `topology.txt` | Phase-1 C++ loader format; provenance encoded in name prefixes (`[SIM]`, `[FINDING]`, `[RUN]`) and header comments |

### Mapping heuristics

1. **Host nodes** from unique `target` hosts (`from_finding`); zone hint from URL (`DMZ` / `Lab` / `Internal`).
2. **Endpoint nodes** from `target` + `endpoint` when present (`from_finding`).
3. **Exploit-step edges** host → endpoint with probability from severity/CVSS (`from_finding`).
4. **Simulated entry node** `[SIM] External Attacker` → each host (`simulated`, opt-out via `--no-simulated-entry`).
5. **Optional simulated lateral** edges between hosts (`--allow-simulated-lateral`) — always warned + labeled.
6. **Run targets** without findings become `[RUN]` hosts (`FROM_RUN_TARGET`).
7. **Crown jewel**: highest-impact non-entry node marked `MODELED_CROWN_JEWEL` (modeling choice, not proof).

CLI: `python -m strix_dsa_bridge convert|analyze …`. Keep C++ free of Strix imports.

## Phase 3 backend integration

| Entry | Behavior |
|-------|----------|
| `python -m strix_dsa_backend <run\|path>` | Resolve `strix_runs/<run>/`, run bridge, optionally C++ engine, write `attack_path/` |
| `strix attack-path <run\|path>` | Same, via thin shim (checkout with `dsa_attack_path/` present) |

Persist layout (verified):

```text
strix_runs/<run>/
  vulnerabilities.json
  run.json
  attack_path/          # created by Phase 3; not written by agents
    attack_graph.json
    topology.txt
    analysis.txt
    meta.json
```

Engine discovery: `dsa_attack_path/build/strix_dsa_cli[.exe]` or `STRIX_DSA_ENGINE`. Missing engine still writes graph artifacts and records `engine.skipped_reason` in `meta.json`.

## Phase 4 dashboard (viewer)

| Piece | Role |
|-------|------|
| `GET /api/attack-path` | Reads `attack_path/{attack_graph.json,meta.json,analysis.txt}`; returns `{available, reason, graph, meta, analysis_text, disclaimer}` — **same schema**, no second model |
| SPA **Attack path** tab | React Flow graph with provenance badges; defense-priority list from `from_finding` edges; engine summary text |
| Missing artifacts | `available=false` + copy that explains how to generate; does not break Issues/Agents/Overview |
| Simulated lateral UI | Checkbox **off by default**; only reveals edges labeled `MODELED_LATERAL` |

How to run locally:

```powershell
# 1) Ensure a run has attack_path/ artifacts
python -m strix_dsa_backend path\to\strix_runs\my-run --engine dsa_attack_path\build\strix_dsa_cli.exe

# 2) Open the local viewer on that run
strix view my-run
# Sidebar / mobile tab: "Attack path"
```

## Phase 5 polish (eval / docs / disclaimer)

- **Canonical disclaimer:** `dsa_attack_path/bridge/strix_dsa_bridge/constants.py` (`DISCLAIMER` / `DISCLAIMER_BANNER`) — mirrored in backend analysis headers, viewer API fallback, and SPA copy.
- **`meta.json` → `modeled_paths`:** optional BFS node/edge id arrays for UI highlight (same graph, no schema fork). Sky “BFS” edges in the SPA are modeled fewest-hop aids, not confirmed pivots.
- **Runbook:** `dsa_attack_path/RUNBOOK.md`
- **Eval evidence:** `docs/eval-results.md`
- Framing: thesis-layered DSA module beside Strix — not a rewrite of Strix agents.

## Algorithm justification

| Algorithm | Why it earns its place |
|-----------|-------------------------|
| BFS | Hop-minimal reachability; baseline “can we get there?” |
| DFS (+ caps) | Enumerate alternative corridors for bottleneck stats |
| Dijkstra (`-log p`) | Prefer higher modeled traversal weight without inventing threat scores |
| Bottleneck frequency | Prioritize edges whose removal collapses many paths |

## License / attribution

Strix remains Apache-2.0. New DSA module files carry project attribution and note simulated data. Preserve upstream LICENSE; do not strip copyright headers.

## Phase boundaries

1. **Done:** graph model, C++ engine, CMake, unit tests, simulated demo CLI.
2. **Done:** Strix → graph bridge (`vulnerabilities.json` / `run.json` → labeled graph + C++ topology).
3. **Done:** Backend wiring into `strix_runs/<run>/attack_path/` + optional `strix attack-path` CLI.
4. **Done:** Viewer `/api/attack-path` + Attack path SPA visualization with provenance.
5. **Done:** Disclaimer alignment, `modeled_paths` highlight aid, runbook, eval evidence.
