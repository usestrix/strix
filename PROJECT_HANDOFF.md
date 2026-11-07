# PROJECT HANDOFF — Strix DSA Attack Path Analysis

**For the next agent/session.** Continue without needing prior chat history.

| Item | Value |
|------|--------|
| Workspace | `c:\Users\ADMIN\Documents\project-attt` |
| Goal | Thesis MVP: graph DSA attack-path (BFS/DFS/Dijkstra/bottleneck) beside Strix |
| Upstream | https://github.com/usestrix/strix (Apache-2.0) |
| Fork remote | `fork` → https://github.com/nth1992007-boop/strix.git |
| Origin remote | `origin` → https://github.com/usestrix/strix.git (**no push access**) |
| Branch | `cursor/dsa-attack-path-phase1-ae73` |
| PR | https://github.com/usestrix/strix/pull/1666 |
| Tip | `1169f34` — PA-12 one-click demo launcher |
| Agent Store docs | `C:\Users\ADMIN\AppData\Local\Cursor\AgentStores\cursor_agent_stores\bc-9c633c18-02e3-48ad-ac01-70b368f20dea\files\docs\` |
| Tracker | PA-1 parent; Phases PA-2…PA-6 done; PA-8…PA-11 follow-ons |

---

## 1. Architecture (unchanged shape)

```
Strix scan (unchanged) → strix_runs/<run>/{vulnerabilities.json,run.json}
        → dsa_attack_path backend/bridge → C++ strix_dsa_cli (optional)
        → <run>/attack_path/{attack_graph.json,topology.txt,analysis.txt,meta.json}
        → Viewer GET /api/attack-path + SPA "Attack path"
```

Canonical disclaimer: `dsa_attack_path/bridge/strix_dsa_bridge/constants.py`.

**How to demo (thesis):** double-click `dsa_attack_path/Run-Demo.bat` — details in `docs/demo-walkthrough.md`.  
Also: `dsa_attack_path/RUNBOOK.md`, `docs/eval-results.md`, `docs/strix-dsa-architecture.md`.

---

## 2. Completed work

### MVP phases (PR series)
| Phase | Commit (approx) | Status |
|-------|-----------------|--------|
| 1 C++ engine | `84fa87f` | Done |
| 2 Bridge | `3a801cc` | Done |
| 3 Backend | `1686b85` | Done |
| 4 Viewer SPA | `1a923b3` | Done |
| 5 Eval/docs | `12f06ae` | Done |

### Post-MVP on same PR
| Task | Commit | What |
|------|--------|------|
| PA-8 Dijkstra in meta | `d90d01e` | `modeled_paths.dijkstra_*`; SPA rose DJ |
| PA-9 uv + viewer HTTP | `7357c4d` | `uv sync`; `tests/test_viewer.py` 27 passed |
| PA-10 Bottlenecks UI | `3c1d7bd` | `meta.bottlenecks`; SPA BN panel + yellow highlight |
| PA-11 Demo walkthrough | `adbc3d8` | `docs/demo-walkthrough.md` + handoff refresh |
| PA-12 One-click launcher | `1169f34` | `dsa_attack_path/Run-Demo.bat` + `scripts/run_demo.py` |
| PA-13 Authorized URL UI | *(this push)* | Attack path form + `/api/attack-path/authorized-scan` + portal |

Simulated lateral stays **OFF** by default. Outputs remain **MODELED**.

---

## 3. Key paths

| Path | Role |
|------|------|
| `dsa_attack_path/` | C++ engine, bridge, backend |
| `dsa_attack_path/bridge/strix_dsa_bridge/paths.py` | BFS / Dijkstra / bottleneck helpers → meta |
| `strix/interface/viewer/` | `/api/attack-path` + AttackPathView SPA |
| `docs/demo-walkthrough.md` | User-facing thesis demo |
| `docs/eval-results.md` | Pass counts |
| `PROJECT_HANDOFF.md` | This file |

---

## 4. Decisions (still in force)

1. Independent `dsa_attack_path/` — no agent-loop hard-wire  
2. Explicit post-run CLI only  
3. Provenance on every node/edge  
4. One graph schema; meta is additive UI aid; `analysis.txt` = engine transcript fallback  
5. Push via **fork** only  
6. Windows toolchain: CMake + TDM-GCC MinGW Makefiles  

---

## 5. Gaps (non-blocking)

| Issue | Notes |
|-------|--------|
| Upstream merge | Maintainer decision on PR #1666 |
| Live browser demo | Walkthrough covers `uv run strix view`; not CI-automated |
| Dijkstra in C++ JSON | Still stdout/`analysis.txt`; Python meta already has ids |

---

## 6. Latest verified results

| Suite | Result |
|-------|--------|
| C++ ctest | 1/1 |
| Bridge unittest | 18 OK |
| Backend unittest | 6 OK |
| Viewer reader | 3 passed |
| Full `test_viewer.py` (uv) | 27 passed |
| Demo smoke (2026-11-07) | engine exit 0; meta BFS/DJ/BN present; reader `available=true` |

Re-verify: see `docs/eval-results.md` and §5 of `docs/demo-walkthrough.md`.

---

## 7. Next steps

- Thesis presentation / recording from `docs/demo-walkthrough.md`  
- Optional: PR destiny with usestrix maintainers  
- **Do not** invent fake pentest results or wire attack-path into agent loops  

### Env reminders
- Git: `Hiếu Nguyễn Trung` / `nth1992007@gmail.com`  
- Push: `git push fork cursor/dsa-attack-path-phase1-ae73`  
- CMake / g++ paths as in walkthrough §0  

---

## Reading order

1. `docs/demo-walkthrough.md`  
2. This handoff  
3. `dsa_attack_path/RUNBOOK.md`  
4. `docs/eval-results.md`  
5. `docs/strix-dsa-architecture.md`  
6. PR #1666  

*Handoff refreshed for PA-11 (demo walkthrough).*
