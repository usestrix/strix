# 🦅 Strix Hub (Multi-Tenant & Dual-Channel Orchestration Console)

[English](./README.md) | [简体中文](#简体中文)

---

## English

**Strix Hub** is an open-source, multi-tenant task orchestration and dual-channel model routing platform designed for [Strix](https://github.com/usestrix/strix) autonomous AI penetration testing.

### ✨ Key Features

1. **Zero-Intrusion Facade Architecture**:
   - Operates completely outside the core `strix/` codebase as a management facade.
   - 100% compatible with current and future upstream Strix versions without code merge conflicts.
2. **Independent Dual-Channel Model Routing**:
   - **Root Agent (Brain)**: High-reasoning cloud models (e.g. Gemini 3.1 Pro, Claude 3.7 Sonnet, GPT-4o) for strategic planning and vulnerability discovery.
   - **Sub-agents (Muscles)**: Private/local models (e.g. Qwen 3.8 / DeepSeek / Ollama / vLLM / SGLang) for high-concurrency port scanning, fuzzing, and payload execution with **zero token costs and zero rate limits**.
   - Built-in **Auto Tool-Call Recovery** to seamlessly convert text-based XML tool outputs into standard OpenAI function calls.
3. **Live Hot-Reloading**:
   - Switch model providers, base URLs, and API keys on-the-fly without interrupting running penetration tasks.
4. **OS-Level Process Control**:
   - True process group lifecycle management supporting **Start**, **Pause (`SIGSTOP` with 0 CPU & 0 Token consumption)**, **Resume (`SIGCONT`)**, and **Terminate**.
5. **Multi-Tenancy & Role-Based Access Control (RBAC)**:
   - Built-in SQLite database with user isolation (Users manage their own scans; Admins monitor the entire fleet).
6. **Zero External Dependencies**:
   - Powered purely by Python standard libraries (`http.server`, `sqlite3`, `subprocess`, `threading`) and a single-file modern Dark Mode React SPA.

### 🚀 Quick Start

```bash
# 1. Install & build Strix
git clone https://github.com/usestrix/strix.git
cd strix
make dev-install

# 2. Launch Strix Hub (default port 8888)
python -m strix_hub.main --port 8888
```

Open `http://localhost:8888` in your browser.
- **Default Admin Account**: `admin` / `admin123`

### ⚙️ Environment Variables (Optional)

```bash
export LOCAL_LLM_MODEL="openai/Qwen3.8-27B-abliterated"
export LOCAL_LLM_URL="http://127.0.0.1:8000/v1"
export LOCAL_LLM_KEY="your-api-key"
```

---

<a name="简体中文"></a>
## 简体中文

**Strix Hub** 是专为 [Strix](https://github.com/usestrix/strix) 打造的现代化、零侵入、多租户渗透测试任务编排与双渠道模型网关管理平台。

### 🌟 核心特性

1. **零侵入门面架构 (Zero-Intrusion Facade)**：
   - 100% 独立于官方 `strix/` 核心代码运行，完全解耦。
   - 官方上游仓库执行 `git pull` 升级时**零代码合并冲突**，天然适配当前与未来所有 Strix 版本。
2. **独立双渠道模型路由网关 (Dual-Channel Routing)**：
   - **主控大脑 (Root Agent)**：可自由配置云端顶尖推理模型（如 Gemini 3.1 Pro、Claude 3.7 Sonnet、GPT-4o），负责全局渗透决策与漏洞挖掘。
   - **探测打手 (Sub-agents)**：可无缝对接局域网私有化模型（如本地部署的 Qwen 3.8-27B 无审查特化版 / DeepSeek / SGLang / vLLM），负责高并发端口扫描与 Web 模糊测试，**零 Token 成本、零外网限流**！
   - 内置 **Tool-Call 自动解析自愈器**，自动将开源模型输出的 XML 格式工具调用转为标准 OpenAI 协议，确保子智能体触手稳定并发派生。
3. **运行时配置热更新 (Live Hot-Reload)**：
   - 任务在运行中或暂停中，均可在 Web 控制台一键热更模型渠道、Base URL 与 API Key，底层网关实时生效。
4. **操作系统进程级精准调度**：
   - 采用进程组信号控制，真正实现任务 **一键暂停 (`SIGSTOP` 瞬间零 CPU、零 Token 消耗挂起)**、**继续 (`SIGCONT` 唤醒)** 与 **强力终止**。
5. **多租户与 RBAC 权限隔离**：
   - 内置轻量 SQLite 持久化，普通用户仅能查看与操作自己创建的任务，管理员全局统一纳管。
6. **零额外依赖 & 极速部署**：
   - 后端基于 Python 标准库实现，前端内置现代化 Single-File React SPA 暗黑大屏，一键即可启动。

### 🚀 快速启动

```bash
# 1. 克隆并安装 Strix
git clone https://github.com/usestrix/strix.git
cd strix
make dev-install

# 2. 启动 Strix Hub 服务 (默认端口 8888)
python -m strix_hub.main --port 8888
```

浏览器访问 `http://localhost:8888` 即可开始使用。
- **默认管理员账户**：`admin` / `admin123`（登录后可在用户管理中修改或新增成员）

### 📄 License

Apache License 2.0
