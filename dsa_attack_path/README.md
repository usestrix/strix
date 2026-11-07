# Strix DSA Attack Path Engine (Phase 1)

Independent C++17 graph library for **modeled** attack-path analysis intended to sit beside [Strix](https://github.com/usestrix/strix) without modifying its agent/runtime loops.

**Algorithms:** BFS (fewest hops), DFS (simple-path enumeration with caps), Dijkstra on `-log(p)` (max path-product), bottleneck ranking by path frequency.

> **Simulation only.** Sample topology and demo output are synthetic. They are not penetration-test results.

## Build (Windows / MinGW or any CMake + C++17 toolchain)

```powershell
cd dsa_attack_path
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

If CMake is installed but not on `PATH`:

```powershell
$env:Path = "C:\Program Files\CMake\bin;" + $env:Path
```

## Run demo CLI

```powershell
.\build\strix_dsa_cli.exe .\data\simulated_lab_network.txt 1 8
```

Arguments: `<topology> <start_id> <target_id> [max_depth=12] [max_paths=10000]`

## Layout

| Path | Role |
|------|------|
| `include/strix_dsa/` | Public headers |
| `src/` | Graph model + algorithms + CLI |
| `tests/test_engine.cpp` | Unit tests |
| `data/simulated_lab_network.txt` | Labeled synthetic topology |

## Phase 2 bridge

Python bridge under `bridge/` converts Strix-shaped `vulnerabilities.json` into a labeled graph + Phase-1 topology. See `bridge/README.md`.

```powershell
cd bridge
python -m unittest discover -s tests -v
python -m strix_dsa_bridge analyze .\fixtures\sample_vulnerabilities.json --run-json .\fixtures\sample_run.json -o .\out --allow-simulated-lateral --engine ..\build\strix_dsa_cli.exe
```

## Phase 3 backend

Post-run integration writes `strix_runs/<run>/attack_path/`. Simulated lateral off by default. See `backend/README.md`.

```powershell
cd backend
python -m unittest discover -s tests -v
python -m strix_dsa_backend <run-name-or-path> --engine ..\build\strix_dsa_cli.exe
# optional Strix subcommand from repo checkout:
# strix attack-path <run-name-or-path>
```

## Phase 4 dashboard

Local viewer **Attack path** tab + `GET /api/attack-path` (provenance badges; lateral off by default).

```powershell
python -m strix_dsa_backend <run> --engine .\build\strix_dsa_cli.exe
strix view <run>
# open Attack path in the sidebar
python -m pytest tests/test_attack_path_viewer.py -q
```

## Phase 5 polish

- Demo runbook: [`RUNBOOK.md`](RUNBOOK.md)
- Eval evidence: [`../docs/eval-results.md`](../docs/eval-results.md)
- Canonical disclaimer: `bridge/strix_dsa_bridge/constants.py`

Architecture / Strix integration plan: see Project store `docs/strix-dsa-architecture.md` and repo `docs/strix-dsa-architecture.md`.
