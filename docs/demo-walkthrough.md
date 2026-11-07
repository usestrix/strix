# Demo walkthrough — Strix DSA Attack Path (thesis MVP)

Hướng dẫn ngắn chạy end-to-end trên Windows (máy lab đã verify).  
Module DSA **không** thay Strix agents; kết quả là **MODELED** graph — không phải chuỗi exploit đã xác nhận.

| Mục | Giá trị |
|-----|---------|
| Repo | `c:\Users\ADMIN\Documents\project-attt` |
| Branch / PR | `cursor/dsa-attack-path-phase1-ae73` · https://github.com/usestrix/strix/pull/1666 |
| Toolchain | CMake `C:\Program Files\CMake\bin` · g++ TDM-GCC `C:\TDM-GCC-64\bin` · Python 3.12+ · Node/npm (SPA đã commit) |

---

## One-click (Windows)

Double-click hoặc chạy:

```text
c:\Users\ADMIN\Documents\project-attt\dsa_attack_path\Run-Demo.bat
```

(hoặc `dsa_attack_path\scripts\Run-Demo.bat`)

Launcher sẽ: build/reuse `strix_dsa_cli.exe` → fixture + backend analyze (**simulated lateral OFF**) → copy vào `strix_runs\dsa-demo` → mở `strix view` nếu có `uv` / `.venv`.

### Nhập URL trên giao diện (không cần terminal)

1. Mở viewer (Run-Demo.bat hoặc uv run strix view dsa-demo).
2. Tab **Attack path**.
3. Form **Authorized target URL** ở đầu trang:
   - Dán URL (http/https)
   - Bắt buộc tick xác nhận quyền sở hữu / written permission
   - **Queue authorized Strix scan** hoặc **Stage MODELED Attack Path demo**
4. Nút bị **disabled** nếu chưa tick checkbox.

Portal độc lập: dsa_attack_path\scripts\Open-Authorized-Portal.bat → http://127.0.0.1:8765/



### Docker trên máy lab (PA-15)

Trạng thái 2026-11-08: **22H2 OK (19045.6456); Docker Desktop 4.98 đã cài; cần reboot lần 2 cho WSL2/Hyper-V**.

- Feature update 22H2 đã apply sau reboot 1
- winget cài Docker Desktop thành công; client `docker` có, Engine chưa lên (pipe 500) vì CBS còn **RebootPending** (WSL + VirtualMachinePlatform + Hyper-V)
- Agent **không** reboot lần 2 — user Restart → Start **Docker Desktop** → chờ Engine → báo lại để verify `docker version` / hello-world

**Trước khi Engine chạy:** dùng **Stage MODELED Attack Path demo** (SYNTHETIC). Không queue live scan.

### Nếu queue scan báo OK nhưng UI vẫn hiện fixture cũ

**Nguyên nhân thường gặp trên máy lab:** Strix thoát ngay vì **Docker chưa cài/không chạy** — log trong strix_runs/_authorization_queue/*.log. API cũ từng ghi scan_started=true dù process đã chết; viewer vẫn gắn run đang mở (vd. dsa-demo / Issues pp.example.com).

**Cách xem đúng:**
1. Queue lại — UI phải hiện lỗi Docker rõ (không còn giả OK).
2. Hoặc **Stage MODELED Attack Path demo** → viewer **tự chuyển** sang run demo-… (SYNTHETIC; Issues gắn nhãn demo, không phải live findings).
3. Live scan thật cần Docker Desktop + LLM key, rồi Past runs chọn run mới (không phải fixture cũ).

URL có #/… sẽ bị strip trước khi queue.

Flags hữu ích:

```powershell
cd dsa_attack_path\scripts
python run_demo.py --skip-viewer   # chỉ analyze + stage
python run_demo.py --no-open       # viewer không auto-browser
python run_demo.py --rebuild-engine
```

Optional `.exe` (cần Python trên máy để gọi backend; không commit binary vào git):

```powershell
cd dsa_attack_path\scripts
.\Build-Demo-Exe.bat
# → scripts\dist\Run-DSA-Demo.exe
```

---

## 0. Chuẩn bị PATH (mỗi session PowerShell)

```powershell
$env:Path = "C:\Program Files\CMake\bin;C:\TDM-GCC-64\bin;$env:APPDATA\Python\Python314\Scripts;" + $env:Path
cd c:\Users\ADMIN\Documents\project-attt
```

Nếu chưa có `uv`: `python -m pip install --user uv` rồi `uv sync`.

---

## 1. Build C++ engine + unit test

```powershell
cd dsa_attack_path
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Kỳ vọng: `strix_dsa_cli.exe` trong `build\`, ctest **1/1 Passed**.

Demo CLI thuần (topology giả lập):

```powershell
.\build\strix_dsa_cli.exe .\data\simulated_lab_network.txt 1 8
```

---

## 2. Fixture → backend analyze (tạo artifacts)

```powershell
cd c:\Users\ADMIN\Documents\project-attt\dsa_attack_path\backend
python fixtures\make_fixture_run.py .\fixtures\sample_run_dir
python -m strix_dsa_backend .\fixtures\sample_run_dir --engine ..\build\strix_dsa_cli.exe --json
```

Artifacts (đã verify smoke trên máy này):

```text
fixtures\sample_run_dir\attack_path\
  attack_graph.json   # provenance from_finding | simulated
  topology.txt
  analysis.txt        # transcript C++ (banner MODELED)
  meta.json           # modeled_paths (BFS/DJ) + bottlenecks (BN)
```

Defaults sản phẩm: **simulated lateral = OFF**.  
Trong `meta.json` xem nhanh: `modeled_paths.bfs_node_ids`, `dijkstra_node_ids`, `bottlenecks.edges`.

---

## 3. Đưa run vào `strix_runs` và mở viewer

```powershell
cd c:\Users\ADMIN\Documents\project-attt
New-Item -ItemType Directory -Force -Path .\strix_runs\dsa-demo | Out-Null
Copy-Item -Recurse -Force .\dsa_attack_path\backend\fixtures\sample_run_dir\* .\strix_runs\dsa-demo\

# Cách A (khuyến nghị sau uv sync)
uv run strix view dsa-demo

# Cách B — nếu strix đã trên PATH từ editable install
# strix view dsa-demo
```

Trong UI:

1. Sidebar / mobile → tab **Attack path**
2. Đọc disclaimer MODELED
3. Graph: badge **FROM FINDING** vs **SIMULATED**
4. Highlight: sky **BFS** (ít hop), rose **DJ** (max path-product −log p), yellow **BN** (bottleneck)
5. Panel **Bottlenecks** + **Defense priority** (chỉ cạnh `from_finding`)
6. Checkbox *Show simulated lateral* — **tắt mặc định**

Không có `attack_path/` → empty state (scan UI vẫn chạy).

---

## 4. Checklist nói chuyện bảo vệ luận

| Câu hỏi | Trả lời ngắn |
|---------|----------------|
| Có sửa agent loop Strix? | Không — CLI post-run độc lập |
| BFS / Dijkstra / bottleneck từ đâu? | Graph có nhãn provenance; meta mirror thuật toán C++ |
| Lateral giả lập? | Tắt mặc định; bật mới hiện cạnh MODELED_LATERAL |
| Đây có phải pentest thật? | **Không** — modeled / threat-model scaffolding |

---

## 5. Verify nhanh (optional)

```powershell
cd c:\Users\ADMIN\Documents\project-attt\dsa_attack_path\bridge
python -m unittest discover -s tests -q
cd ..\backend
python -m unittest discover -s tests -q
cd c:\Users\ADMIN\Documents\project-attt
$env:PYTHONPATH = (Get-Location).Path
python -m pytest tests/test_attack_path_viewer.py -q
# Full viewer HTTP (sau uv sync): uv run pytest tests/test_viewer.py -q
```

Chi tiết số pass: `docs/eval-results.md`.  
Kiến trúc: `docs/strix-dsa-architecture.md`. Runbook kỹ thuật: `dsa_attack_path/RUNBOOK.md`.

---

*Smoke verified 2026-11-07 trên máy Windows lab: ctest OK · backend analyze engine exit 0 · reader `available=true` với BFS/DJ/BN.*
