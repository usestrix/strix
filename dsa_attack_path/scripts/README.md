# Demo launchers (Windows)

| File | Role |
|------|------|
| `../Run-Demo.bat` | One-click from module root |
| `Run-Demo.bat` | Same entry (keeps console open) |
| `run_demo.py` | Build/reuse engine → fixture analyze → stage `strix_runs/dsa-demo` → `strix view` |
| `Build-Demo-Exe.bat` | Optional PyInstaller one-file exe → `dist/Run-DSA-Demo.exe` |
| `Open-Authorized-Portal.bat` / `demo_portal.py` | Local URL form + auth checkbox (http://127.0.0.1:8765) |
| Viewer **Attack path** tab | Same URL form inside Strix SPA (`POST /api/attack-path/authorized-scan`) |

Simulated lateral stays **OFF**. Outputs are **MODELED** — not confirmed multi-hop exploits.  
Scans refuse to start without the authorization checkbox.

```powershell
python run_demo.py --skip-viewer
python run_demo.py --no-open
```
