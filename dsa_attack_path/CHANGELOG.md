# Changelog — dsa_attack_path

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
