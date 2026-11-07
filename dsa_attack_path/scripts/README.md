# Demo launchers (Windows)

| File | Role |
|------|------|
| `../Run-Demo.bat` | One-click from module root |
| `Run-Demo.bat` | Same entry (keeps console open) |
| `run_demo.py` | Build/reuse engine → fixture analyze → stage `strix_runs/dsa-demo` → `strix view` |
| `Build-Demo-Exe.bat` | Optional PyInstaller one-file exe → `dist/Run-DSA-Demo.exe` |

Simulated lateral stays **OFF**. Outputs are **MODELED** — not confirmed multi-hop exploits.

```powershell
python run_demo.py --skip-viewer
python run_demo.py --no-open
```
