# DSA Attack Path — evaluation evidence (Phase 5 + PA-8)

Recorded on the project Windows machine (`c:\Users\ADMIN\Documents\project-attt`), 2026-11-07.

Environment: CMake 4.x, TDM-GCC g++ 10.3, Python 3.14, Node/npm for viewer SPA.

**PA-8:** `meta.modeled_paths` now includes `dijkstra_node_ids` / `dijkstra_edges` / `dijkstra_path_probability` (Python mirror of C++ `-log(p)` Dijkstra). `analysis.txt` remains the richer CLI fallback.

**PA-10:** `meta.bottlenecks` ranks edges by crown-jewel reach + DFS path frequency (same order as C++). SPA shows a Bottlenecks panel + yellow **BN** highlights.

## Commands and results

### C++ engine

```powershell
$env:Path = "C:\Program Files\CMake\bin;C:\TDM-GCC-64\bin;" + $env:Path
cd dsa_attack_path
cmake --build build
ctest --test-dir build --output-on-failure
```

**Result:** `1/1 Test #1: strix_dsa_unit_tests ... Passed` — **100% tests passed**

### Bridge

```powershell
cd dsa_attack_path\bridge
python -m unittest discover -s tests -v
```

**Result:** `Ran 18 tests in ~0.2s` — **OK** (includes BFS + Dijkstra + bottleneck `test_paths.PathsTest`)

### Backend

```powershell
cd dsa_attack_path\backend
python -m unittest discover -s tests -v
```

**Result:** `Ran 6 tests in ~0.3s` — **OK** (includes C++ E2E when `build\strix_dsa_cli.exe` present; asserts `bfs`/`dijkstra` ids + `bottlenecks.edges`)

### Viewer artifact reader

```powershell
cd c:\Users\ADMIN\Documents\project-attt
$env:PYTHONPATH = "c:\Users\ADMIN\Documents\project-attt"
python -m pytest tests/test_attack_path_viewer.py -q
```

**Result:** **3 passed**

## Totals

| Suite | Pass count |
|-------|------------|
| C++ ctest | 1 |
| Bridge unittest | 18 |
| Backend unittest | 6 |
| Viewer pytest | 3 |
| **Combined** | **28** |

## Demo smoke (manual)

```powershell
cd dsa_attack_path\backend
python fixtures\make_fixture_run.py .\fixtures\sample_run_dir
python -m strix_dsa_backend .\fixtures\sample_run_dir --engine ..\build\strix_dsa_cli.exe
```

Expect `attack_path/{attack_graph.json,topology.txt,analysis.txt,meta.json}` with
`product_defaults.allow_simulated_lateral=false` and non-empty
`modeled_paths.bfs_node_ids` + `modeled_paths.dijkstra_node_ids` + non-empty `bottlenecks.edges`.

## PA-9 note (uv + full viewer HTTP)

```powershell
python -m pip install --user uv   # if uv missing from PATH
uv sync
uv run pytest tests/test_viewer.py -q
```

**Result (2026-11-07 after `uv sync`):** **27 passed** in ~24s.

## Notes

- DSA gates remain the C++/bridge/backend/reader matrix above; full `test_viewer.py` is now green with `uv`.
- Outputs remain **MODELED** — not confirmed multi-hop exploit chains. See `bridge/strix_dsa_bridge/constants.py`.
