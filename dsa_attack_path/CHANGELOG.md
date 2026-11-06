# Changelog — dsa_attack_path

## 0.5.0 — Phase 5 tests, eval, docs

### Added / polished
- Canonical disclaimer strings (`DISCLAIMER` / `DISCLAIMER_BANNER`) aligned across bridge, backend, C++ CLI banner, viewer API, SPA.
- `meta.json` field `modeled_paths` (BFS node/edge ids) for UI path highlight without a second graph schema.
- `bridge/strix_dsa_bridge/paths.py` + `bridge/tests/test_paths.py`.
- Demo runbook: `RUNBOOK.md`.
- Eval record: `docs/eval-results.md` (25 checks green on this machine).

### Test results (2026-11-07)
| Suite | Result |
|-------|--------|
| C++ `ctest` | 1/1 passed |
| Bridge unittest | 15 OK |
| Backend unittest | 6 OK |
| Viewer `test_attack_path_viewer` | 3 passed |

### How to run / test
See `RUNBOOK.md` and `docs/eval-results.md`.

## 0.4.0 — Phase 4 dashboard visualization

### Added
- Viewer API `GET /api/attack-path` (`strix/interface/viewer/attack_path.py`) reusing `attack_graph.json` + `meta.json` + `analysis.txt`.
- SPA **Attack path** tab: provenance badges, defense-priority list, simulated-lateral checkbox **off by default**, graceful empty state.
- Rebuilt committed viewer static bundle.
- Unit tests: `tests/test_attack_path_viewer.py` (3 passed).

### How to run
```powershell
python -m strix_dsa_backend <run> --engine dsa_attack_path\build\strix_dsa_cli.exe
strix view <run>   # open Attack path in sidebar
python -m pytest tests/test_attack_path_viewer.py -q
```

### Not in this release
- Formal eval harness / thesis polish (Phase 5)

## 0.3.0 — Phase 3 backend integration

### Added
- `backend/strix_dsa_backend`: post-run analyzer writing `strix_runs/<run>/attack_path/` artifacts.
- Product default: simulated lateral **OFF**; opt-in `--allow-simulated-lateral` only.
- Optional Strix shim: `strix attack-path` → `strix/interface/attack_path_cli.py` (no agent-loop hook).
- Integration tests under `backend/tests/` (6 cases, including C++ E2E when built).

### How to run / test
```powershell
cd dsa_attack_path\backend
python -m unittest discover -s tests -v
python fixtures\make_fixture_run.py .\fixtures\sample_run_dir
python -m strix_dsa_backend .\fixtures\sample_run_dir --engine ..\build\strix_dsa_cli.exe
# From repo root with Strix installed:
#   strix attack-path .\dsa_attack_path\backend\fixtures\sample_run_dir
```

### Not in this release
- Viewer `/api/attack-path` + SPA (Phase 4)
- Automatic post-scan hook inside `ReportState` (intentionally avoided)

## 0.2.0 — Phase 2 bridge

### Added
- Independent Python package `bridge/strix_dsa_bridge` (stdlib only; no Strix imports).
- Mapping heuristics: host/endpoint nodes from findings, severity→probability exploit edges, labeled simulated entry (+ optional lateral), run-target hosts, modeled crown jewel.
- CLI: `python -m strix_dsa_bridge convert|analyze`.
- Fixture `bridge/fixtures/sample_vulnerabilities.json` + `sample_run.json` (schema-shaped, explicitly synthetic).
- Unit tests (`python -m unittest discover -s bridge/tests -v`) — 14 passing on this machine.
- Architecture doc updated with bridge contract / provenance rules.

### How to run / test
```powershell
cd dsa_attack_path\bridge
python -m unittest discover -s tests -v
python -m strix_dsa_bridge convert .\fixtures\sample_vulnerabilities.json --run-json .\fixtures\sample_run.json -o .\out --allow-simulated-lateral
python -m strix_dsa_bridge analyze .\fixtures\sample_vulnerabilities.json --run-json .\fixtures\sample_run.json -o .\out --allow-simulated-lateral --engine ..\build\strix_dsa_cli.exe
```

### Not in this release
- Viewer / backend API wiring (Phase 3)
- Automatic post-scan hook inside Strix runtime

## 0.1.0 — Phase 1 MVP

### Added
- Independent C++17 graph model (`Node`, `Edge`, `Graph`) under `strix_dsa`.
- DSA engine: BFS reachability, DFS simple-path enumeration (depth/path caps), Dijkstra lowest-cost / max product path (`w = -log(p)`), bottleneck ranking.
- CMake build (`strix_dsa` library, `strix_dsa_cli` demo, `strix_dsa_tests`).
- Unit tests covering shortest path, disconnect, cycles, Dijkstra product, zero-probability edges, identical endpoints, multi-path bottlenecks, search limits, scenario edge disable, empty graph.
- Simulated lab topology `data/simulated_lab_network.txt` (explicitly labeled non-real).

### Why
Thesis Phase 1 needs a self-contained, testable algorithm core that can later ingest Strix findings without rewriting Strix.

### How to build / run / test
See `README.md`. Quick path:

```powershell
$env:Path = "C:\Program Files\CMake\bin;" + $env:Path
cd dsa_attack_path
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
.\build\strix_dsa_cli.exe .\data\simulated_lab_network.txt 1 8
```

### Not in this release
- Strix `vulnerabilities.json` bridge (Phase 2)
- Viewer / backend API wiring (Phases 3–4)
