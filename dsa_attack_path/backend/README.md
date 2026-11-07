# Strix DSA Backend Integration (Phase 3)

Post-run (explicit) wiring: read a Strix run directory → Phase-2 bridge → Phase-1 C++ engine → write artifacts under:

```text
strix_runs/<run>/attack_path/
  attack_graph.json   # provenance-labeled modeled graph
  topology.txt        # C++ engine input
  analysis.txt        # engine stdout/stderr (modeled disclaimer)
  meta.json           # invocation metadata + product defaults
```

**Does not** hook agent/scanner loops. Simulated lateral is **OFF by default**.

## CLI (independent)

```powershell
cd dsa_attack_path\backend
python -m strix_dsa_backend path\to\strix_runs\my-run --json
# or by run name from a cwd that contains strix_runs/:
python -m strix_dsa_backend my-run --cwd c:\Users\ADMIN\Documents\project-attt
```

Opt-in lateral (explicit only):

```powershell
python -m strix_dsa_backend my-run --allow-simulated-lateral
```

## Optional Strix subcommand

From this checkout (after `uv sync` / editable install):

```powershell
strix attack-path my-run
strix attack-path path\to\run-dir --skip-engine
```

If `dsa_attack_path/backend` is missing (plain upstream install), the subcommand exits with a short message.

## Tests

```powershell
cd dsa_attack_path\backend
python -m unittest discover -s tests -v
```
