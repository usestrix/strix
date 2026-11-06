# Strix DSA Attack Path Analysis — Architecture (Phase 1)

Canonical copy also lives in the Project store at
`docs/strix-dsa-architecture.md` (agent store). Content below matches that plan.

## Purpose

Extend [Strix](https://github.com/usestrix/strix) (Apache-2.0 AI pentesting agent) with an **independent** graph DSA engine for attack-path analysis. Strix continues to discover and validate vulnerabilities; the DSA module ranks modeled reachability and choke points on a directed asset graph. Phase 1 delivers the C++ core only — no live Strix coupling yet.

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
Strix scan (unchanged)
    │
    ▼
strix_runs/<run>/vulnerabilities.json   ← Phase 2 bridge (later)
    │
    ▼
Python adapter (Phase 2)  ──JSON──►  dsa_attack_path CLI / library (Phase 1 ✓)
    │                                         │
    ▼                                         ▼
Optional viewer API (Phase 3–4)         BFS / DFS / Dijkstra / bottleneck
```

- **Independent module**: `dsa_attack_path/` at repo root. Strix Python package is untouched.
- **Simulated graphs in Phase 1**: demo/tests use labeled synthetic topology only — never presented as real pentest output.

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

**Phase 1 (now):** native C++17 library + CLI. I/O: topology file + stdout text summary. Build with CMake + g++/MinGW.

**Phase 2 (planned):** thin Python wrapper invoking the CLI (or linking via `ctypes`/pybind11 later) with JSON graph payloads. Keep the C++ API pure (no Strix imports). The bridge owns Strix field → graph mapping and must label outputs as *modeled* paths from reported findings, not confirmed multi-hop exploits.

## Future dashboard hooks (Phases 3–4)

- Extend local viewer with read-only `/api/attack-path` returning analysis JSON next to `/api/vulnerabilities`.
- SPA panel: graph canvas, shortest/representative path highlight, bottleneck list — consume the same JSON schema as the CLI.
- Do not block Strix scan UX if the DSA binary is missing; degrade gracefully.

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

1. **Done in this delivery:** graph model, C++ engine, CMake, unit tests, simulated demo CLI, this architecture note.
2. **Next:** Strix → graph bridge from `vulnerabilities.json`.
3. Backend wiring into run artifacts.
4. Viewer visualization.
5. Eval/docs polish.
