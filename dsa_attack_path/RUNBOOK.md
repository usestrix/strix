# Strix DSA Attack Path — Demo Runbook (Phases 1–5)

Thesis-layered module beside [Strix](https://github.com/usestrix/strix) (Apache-2.0).  
It does **not** rewrite Strix agents/scanners. Outputs are **MODELED** attack graphs — never confirmed multi-hop exploit chains.

## Provenance legend (aligned across CLI / API / UI)

| Mark | Meaning |
|------|---------|
| `provenance=from_finding` / **FROM FINDING** | Derived from Strix finding fields (`target`, `endpoint`, severity/CVSS) |
| `provenance=simulated` / **SIMULATED** | Explicit threat-model scaffolding (entry node, optional lateral) — **not** pentest proof |
| **BFS highlight** (viewer) | Fewest-hop path on the modeled graph for UI aid — still modeled |

Canonical disclaimer text lives in `bridge/strix_dsa_bridge/constants.py` (`DISCLAIMER`).

## 1. Build the C++ engine

```powershell
$env:Path = "C:\Program Files\CMake\bin;C:\TDM-GCC-64\bin;" + $env:Path
cd dsa_attack_path
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

## 2. Bridge (findings → labeled graph)

```powershell
cd dsa_attack_path\bridge
python -m unittest discover -s tests -v
python -m strix_dsa_bridge convert .\fixtures\sample_vulnerabilities.json `
  --run-json .\fixtures\sample_run.json -o .\out
```

Simulated lateral stays **off** unless you pass `--allow-simulated-lateral`.

## 3. Backend (persist under a Strix run dir)

```powershell
cd dsa_attack_path\backend
python fixtures\make_fixture_run.py .\fixtures\sample_run_dir
python -m strix_dsa_backend .\fixtures\sample_run_dir --engine ..\build\strix_dsa_cli.exe
python -m unittest discover -s tests -v
```

Writes:

```text
<run>/attack_path/
  attack_graph.json   # provenance-labeled graph
  topology.txt        # C++ input
  analysis.txt        # engine transcript (modeled banner)
  meta.json           # product defaults + modeled_paths (BFS + Dijkstra ids for UI)
```

Optional Strix shim (same checkout): `strix attack-path <run>`.

## 4. Viewer — Attack path tab

```powershell
# After artifacts exist for a run under ./strix_runs/<name>/
strix view <name>
# Sidebar / mobile: "Attack path"
```

- Missing `attack_path/` → graceful empty state (scan UI still works).
- Simulated lateral checkbox **off by default**.
- Sky **BFS** / rose **DJ** edges use `meta.modeled_paths` (modeled highlight only).

## 5. Full verification commands

See `docs/eval-results.md` (repo) for the latest recorded pass counts on this machine.
