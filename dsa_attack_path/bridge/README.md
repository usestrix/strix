# Strix → DSA Bridge (Phase 2)

Independent Python bridge that reads Strix-shaped finding artifacts
(`vulnerabilities.json`, optional `run.json`) and emits a **labeled modeled
attack graph** for the Phase-1 C++ engine.

Stdlib only — does not import or modify the Strix package.

## Labels (required reading)

| Provenance | Meaning |
|------------|---------|
| `from_finding` | Derived from filed finding fields (`target`, `endpoint`, severity/CVSS) |
| `simulated` | Explicit threat-model scaffolding (external attacker, optional lateral links) |

Every simulated node/edge carries `SIMULATED` (or `MODELED_*`) labels. Outputs
are **not** confirmed multi-hop exploit chains.

## Convert fixture → graph

```powershell
cd dsa_attack_path\bridge
python -m strix_dsa_bridge convert .\fixtures\sample_vulnerabilities.json `
  --run-json .\fixtures\sample_run.json `
  -o .\out `
  --allow-simulated-lateral
```

Writes:

- `out/attack_graph.json` — full bridge contract with provenance
- `out/topology.txt` — Phase-1 C++ topology (names keep `[SIM]` / `[FINDING]` prefixes)

## Analyze with C++ engine

```powershell
# Build engine once (from dsa_attack_path/)
cmake -S .. -B ..\build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build ..\build

python -m strix_dsa_bridge analyze .\fixtures\sample_vulnerabilities.json `
  --run-json .\fixtures\sample_run.json `
  -o .\out `
  --allow-simulated-lateral `
  --engine ..\build\strix_dsa_cli.exe
```

## Tests

```powershell
cd dsa_attack_path\bridge
python -m unittest discover -s tests -v
```
