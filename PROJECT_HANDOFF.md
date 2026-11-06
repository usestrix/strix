# PROJECT HANDOFF — Strix DSA Attack Path Analysis

**For the next agent/session.** Continue without needing prior chat history.

| Item | Value |
|------|--------|
| Workspace | `c:\Users\ADMIN\Documents\project-attt` |
| Goal | Thesis MVP: extend Strix with graph DSA attack-path analysis (BFS/DFS/Dijkstra/bottleneck), C++ core preferred, independent module |
| Upstream | https://github.com/usestrix/strix (Apache-2.0) |
| Fork remote | `fork` → https://github.com/nth1992007-boop/strix.git |
| Origin remote | `origin` → https://github.com/usestrix/strix.git (**no push access**) |
| Branch | `cursor/dsa-attack-path-phase1-ae73` |
| PR | https://github.com/usestrix/strix/pull/1666 |
| Last commit (Phase 5) | See git log on branch after Phase 5 push |
| Agent Store (docs) | `C:\Users\ADMIN\AppData\Local\Cursor\AgentStores\cursor_agent_stores\bc-9c633c18-02e3-48ad-ac01-70b368f20dea\files\docs\` |
| Tracker parent | PA-1 (thesis product); Phase tasks PA-2…PA-6 |

---

## 1. Project goals + current architecture

### Goals
- Keep Strix AI pentesting intact.
- Add **independent** attack-path analysis: directed asset graph + BFS reachability, DFS path enum, Dijkstra (`-log p`), bottleneck ranking.
- Clear separation: **finding-derived** vs **simulated** scaffolding — never present modeled paths as confirmed multi-hop exploits.
- Prefer C++ for algorithm core; Python bridge/backend; Strix local viewer for dashboard.

### Architecture (Phases 1–5 complete)

```
Strix scan / agent loops (unchanged)
        │
        ▼
strix_runs/<run>/{vulnerabilities.json, run.json}
        │  explicit post-run CLI only (no agent hard-wire)
        ▼
dsa_attack_path/backend  →  bridge  →  C++ engine (strix_dsa_cli)
        │
        ▼
strix_runs/<run>/attack_path/
  attack_graph.json | topology.txt | analysis.txt | meta.json
        │
        ▼
Viewer GET /api/attack-path  +  SPA "Attack path" tab
```

| Layer | Location | Role |
|-------|----------|------|
| C++ engine | `dsa_attack_path/` | Graph model, BFS/DFS/Dijkstra/bottleneck, CMake, CLI, unit tests |
| Bridge | `dsa_attack_path/bridge/` | `vulnerabilities.json` → labeled graph + topology.txt + `paths.py` |
| Backend | `dsa_attack_path/backend/` | Post-run: write `attack_path/` under a Strix run dir |
| Strix shim | `strix/interface/attack_path_cli.py` + `main.py` dispatch | Optional `strix attack-path` |
| Viewer | `strix/interface/viewer/` | `/api/attack-path` + Attack path SPA |

Canonical disclaimer: `dsa_attack_path/bridge/strix_dsa_bridge/constants.py` → `DISCLAIMER`.

Architecture narrative: `docs/strix-dsa-architecture.md` (also mirrored in Agent Store `docs/`).

---

## 2. Completed work

### Phase 1 — Graph model + C++ DSA engine (pushed `84fa87f`)
- Independent C++17 library + CLI + CMake + tests + simulated lab topology.
- Algorithms: BFS, DFS (caps), Dijkstra on `-log(p)`, bottleneck by path frequency.

### Phase 2 — Strix → DSA bridge (pushed `3a801cc`)
- Stdlib Python package maps finding-centric JSON → provenance-labeled graph.
- Simulated entry node; optional lateral (`--allow-simulated-lateral`, off by default).
- Fixtures + unittest suite.

### Phase 3 — Backend integration (pushed `1686b85`)
- Writes `strix_runs/<run>/attack_path/` artifacts.
- Product default: simulated lateral **OFF**.
- Thin `strix attack-path` shim; **no** ReportState/agent-loop hard-wire.

### Phase 4 — Dashboard visualization (pushed `1a923b3`)
- `GET /api/attack-path` reuses `attack_graph.json` + `meta.json` (+ `analysis.txt`).
- SPA Attack path tab: provenance badges, defense priority, lateral toggle off by default, graceful empty state.
- Viewer static bundle rebuilt and committed.

### Phase 5 — Eval / docs polish (**done**)
- Canonical disclaimer alignment across bridge/backend/C++ CLI/viewer/SPA.
- `paths.py` + `meta.modeled_paths` (BFS node/edge ids); SPA sky BFS highlight.
- `dsa_attack_path/RUNBOOK.md`, `docs/eval-results.md`, architecture Phase 5 section, CHANGELOG `0.5.0`.
- Viewer static rebuild: `index-B7ItA10z.js` / `index-BVQpdXLp.css`.
- Verified **25** checks green (ctest 1 + bridge 15 + backend 6 + viewer 3).

---

## 3. Key files

### DSA module
| Path | Purpose |
|------|---------|
| `dsa_attack_path/` | C++ engine + CMake + simulated lab |
| `dsa_attack_path/bridge/` | Findings → graph; `constants.py`, `paths.py` |
| `dsa_attack_path/backend/` | Post-run orchestrator |
| `dsa_attack_path/RUNBOOK.md` | Demo runbook |
| `dsa_attack_path/CHANGELOG.md` | Through `0.5.0` |

### Strix touchpoints (minimal)
| Path | Purpose |
|------|---------|
| `strix/interface/main.py` | Dispatch `strix attack-path` |
| `strix/interface/attack_path_cli.py` | Shim → backend |
| `strix/interface/viewer/attack_path.py` | Read artifacts for API |
| `strix/interface/viewer/server.py` | Route `/api/attack-path` |
| `strix/interface/viewer/frontend/src/components/AttackPathView.tsx` | SPA tab |
| `strix/interface/viewer/static/*` | Built SPA bundle |

### Docs / tests
| Path | Purpose |
|------|---------|
| `docs/strix-dsa-architecture.md` | Integration design (Phases 1–5) |
| `docs/eval-results.md` | Phase 5 pass-count evidence |
| `tests/test_attack_path_viewer.py` | Viewer reader unit tests |
| Agent Store `docs/` | Mirrored architecture + handoff |

---

## 4. Important technical decisions

1. **Independent modules** under `dsa_attack_path/` — do not rewrite Strix core; only thin optional hooks.
2. **No automatic post-scan in `ReportState`** — explicit CLI only (avoids agent-loop coupling).
3. **Provenance on every node/edge** (`from_finding` | `simulated`) + labels; TXT topology encodes prefixes `[SIM]`/`[FINDING]`/`[RUN]`.
4. **Simulated lateral OFF by default** (CLI flags + UI checkbox).
5. **Reuse one graph schema** — viewer API wraps existing JSON; `modeled_paths` is optional meta for UI.
6. **Push via fork** `nth1992007-boop/strix` → PR into `usestrix/strix` (origin push denied).
7. **Thesis framing** — layered module for attack-path research, not a hostile Strix rewrite.
8. **C++ toolchain on this machine:** TDM-GCC `g++`, CMake via winget (`C:\Program Files\CMake\bin`), generator `MinGW Makefiles`.
9. **Viewer SPA** must be rebuilt with `npm run build` in `strix/interface/viewer/frontend` and static output committed (Makefile target `viewer`).

---

## 5. Remaining gaps (non-blocking)

| Issue | Notes |
|-------|--------|
| Dijkstra not in `modeled_paths` | Only BFS fewest-hop ids; C++ still prints Dijkstra in `analysis.txt` |
| Full Strix `test_viewer.py` HTTP | Needs synced `uv` env; DSA gates on the 25-check matrix |
| Upstream merge destiny | Thesis module on PR #1666 — maintainers decide |
| Live desktop demo | Documented in RUNBOOK; not automated in CI |

---

## 6. Latest test results (2026-11-07, Phase 5)

| Suite | Result |
|-------|--------|
| C++ ctest | **1/1 passed** |
| Bridge unittest | **15 OK** |
| Backend unittest | **6 OK** |
| Viewer pytest | **3 passed** |
| **Combined** | **25** |

Details: `docs/eval-results.md`.

### Quick re-verify recipe
```powershell
$env:Path = "C:\Program Files\CMake\bin;C:\TDM-GCC-64\bin;" + $env:Path
$env:PYTHONPATH = "c:\Users\ADMIN\Documents\project-attt"

cd c:\Users\ADMIN\Documents\project-attt\dsa_attack_path
cmake --build build
ctest --test-dir build --output-on-failure

cd bridge
python -m unittest discover -s tests -v

cd ..\backend
python -m unittest discover -s tests -v

cd c:\Users\ADMIN\Documents\project-attt
python -m pytest tests/test_attack_path_viewer.py -q
```

---

## 7. Tracker / next steps

- PA-6 — Phase 5 polish complete; mark for-review / done once PR comment lands.
- Optional later: Dijkstra ids in `modeled_paths`; `uv` full viewer HTTP suite; maintainer merge discussion.
- **Do not** hard-wire attack-path into agent loops or invent fake CVE/pentest results.

### Local env reminders
- Git identity: `Hiếu Nguyễn Trung` / `nth1992007@gmail.com`
- GitHub credentials via git credential helper (`nth1992007-boop`); push to `fork` only
- CMake: `C:\Program Files\CMake\bin`; g++: `C:\TDM-GCC-64\bin`

---

## Related reading order

1. This file  
2. `dsa_attack_path/RUNBOOK.md`  
3. `docs/eval-results.md`  
4. `docs/strix-dsa-architecture.md`  
5. `dsa_attack_path/CHANGELOG.md`  
6. PR #1666  

*Handoff updated after Phase 5 completion.*
