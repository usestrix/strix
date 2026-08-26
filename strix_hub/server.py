"""Standalone HTTP REST Server and SPA host for Strix Hub.

Built with Python standard library for zero external dependencies.
Supports Independent Dual-Channel Providers, Local Qwen3.6 Presets & Live Hot-Reloading.
"""

from __future__ import annotations

import json
import logging
import mimetypes
import os
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from strix_hub import db, task_manager

logger = logging.getLogger("strix_hub.server")

STATIC_DIR = Path(__file__).resolve().parent / "static"

# Automatically load .env file from working directory or /opt/strix/.env if available
def _load_env_file() -> None:
    for env_path in [Path.cwd() / ".env", Path("/opt/strix/.env")]:
        if env_path.is_file():
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
            except Exception:
                pass

_load_env_file()

def get_local_llm_config() -> tuple[str, str, str]:
    """Resolve local LLM model name, API URL, and key with rich fallbacks."""
    model = os.environ.get("LOCAL_LLM_MODEL", os.environ.get("STRIX_LLM", "openai/Qwen3.8-27B-abliterated"))
    url = os.environ.get("LOCAL_LLM_URL", os.environ.get("LLM_API_BASE", os.environ.get("OPENAI_BASE_URL", "http://127.0.0.1:8000/v1")))
    key = os.environ.get("LOCAL_LLM_KEY", os.environ.get("LLM_API_KEY", os.environ.get("OPENAI_API_KEY", "")))
    return model, url, key

LOCAL_LLM_MODEL, LOCAL_LLM_URL, LOCAL_LLM_KEY = get_local_llm_config()

def get_model_presets() -> list[dict[str, Any]]:
    m, u, k = get_local_llm_config()
    return [
        {
            "id": "hybrid-gemini-qwen",
            "name": "🚀 顶配混合动力 (Gemini 3.1 Pro 大脑 + 本地 Qwen 3.8 打手)",
            "root_model": "openai/gemini-3.1-pro-preview",
            "root_api_base": "",
            "root_api_key": "",
            "subagent_model": m,
            "subagent_api_base": u,
            "subagent_api_key": k,
            "description": "【最佳推荐】主控用云端 Gemini 3.1 Pro 百万上下文做复杂漏洞挖掘；海量并发子智能体全部走本地私有化模型，零成本无外网限流！",
        },
        {
            "id": "local-pure-cluster",
            "name": "🛡️ 本地全离线集群 (主子全跑本地私有化模型)",
            "root_model": m,
            "root_api_base": u,
            "root_api_key": k,
            "subagent_model": m,
            "subagent_api_base": u,
            "subagent_api_key": k,
            "description": "完全在企业局域网内运行，数据绝不出网，适合离线环境与内网安全合规审计。",
        },
        {
            "id": "gemini-optimal",
            "name": "⚡ Gemini 纯云端组合 (3.1 Pro + 3.5 Flash)",
            "root_model": "openai/gemini-3.1-pro-preview",
            "root_api_base": "",
            "root_api_key": "",
            "subagent_model": "openai/gemini-3.5-flash",
            "subagent_api_base": "",
            "subagent_api_key": "",
            "description": "主控用 3.1 Pro 推理，子任务用 3.5 Flash 极速响应，全云端中转组合。",
        },
        {
            "id": "claude-hybrid",
            "name": "💎 Claude 3.7 安全审计 + 本地模型混合调度",
            "root_model": "openai/claude-3-7-sonnet",
            "root_api_base": "",
            "root_api_key": "",
            "subagent_model": m,
            "subagent_api_base": u,
            "subagent_api_key": k,
            "description": "主控使用顶级安全审计模型 Claude 3.7，子任务由本地私有化集群并发执行。",
        },
        {
            "id": "custom",
            "name": "⚙️ 自定义独立双渠道 (Custom Dual Channels)",
            "root_model": "",
            "root_api_base": "",
            "root_api_key": "",
            "subagent_model": "",
            "subagent_api_base": "",
            "subagent_api_key": "",
            "description": "自由为两个模型分别配置不同的 Base URL 与 API Key 渠道。",
        },
    ]

MODEL_PRESETS = get_model_presets()


def make_hub_handler() -> type[BaseHTTPRequestHandler]:
    class HubHandler(BaseHTTPRequestHandler):
        server_version = "StrixHub/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            logger.debug("StrixHub %s - %s", self.address_string(), format % args)

        def _send_json(self, status: HTTPStatus, payload: Any, headers: dict[str, str] | None = None) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            if headers:
                for k, v in headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _read_json_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                data = json.loads(raw.decode("utf-8"))
                return data if isinstance(data, dict) else {}
            except Exception:
                return {}

        def _get_current_user(self) -> dict[str, Any] | None:
            auth_header = self.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
                user = db.validate_session(token)
                if user:
                    return user

            cookie_str = self.headers.get("Cookie", "")
            for c in cookie_str.split(";"):
                parts = c.strip().split("=", 1)
                if len(parts) == 2 and parts[0] == "strix_hub_session":
                    user = db.validate_session(parts[1])
                    if user:
                        return user

            return None

        def do_OPTIONS(self) -> None:
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, Cookie")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()

        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            path = parts.path
            query = parse_qs(parts.query)

            if path.startswith("/api/"):
                self._handle_api_get(path, query)
            else:
                self._handle_static(path)

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            if path.startswith("/api/"):
                self._handle_api_post(path)
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not Found"})

        def do_PUT(self) -> None:
            path = urlsplit(self.path).path
            if path.startswith("/api/"):
                self._handle_api_put(path)
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not Found"})

        def do_DELETE(self) -> None:
            path = urlsplit(self.path).path
            if path.startswith("/api/"):
                self._handle_api_delete(path)
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not Found"})

        # --- API Route Handlers ---

        def _handle_api_get(self, path: str, query: dict[str, list[str]]) -> None:
            if path == "/api/models/presets":
                self._send_json(HTTPStatus.OK, {
                    "presets": MODEL_PRESETS,
                    "local_defaults": {
                        "model": LOCAL_LLM_MODEL,
                        "url": LOCAL_LLM_URL,
                        "key": LOCAL_LLM_KEY,
                    }
                })
                return

            if path == "/api/auth/me":
                user = self._get_current_user()
                if not user:
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized"})
                    return
                self._send_json(HTTPStatus.OK, {"user": user})
                return

            user = self._get_current_user()
            if not user:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized, please login"})
                return

            if path == "/api/tasks":
                is_admin = user.get("role") == "admin"
                tasks = db.list_tasks(user_id=user["id"], is_admin=is_admin)
                self._send_json(HTTPStatus.OK, {"tasks": tasks, "count": len(tasks), "is_admin": is_admin})
                return

            if path.startswith("/api/tasks/") and not path.endswith("/logs"):
                task_id = path.split("/")[3]
                task = db.get_task_by_id(task_id)
                if not task:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "Task not found"})
                    return
                if user.get("role") != "admin" and task.get("owner_id") != user["id"]:
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden"})
                    return
                self._send_json(HTTPStatus.OK, {"task": task})
                return

            if path.startswith("/api/tasks/") and path.endswith("/logs"):
                task_id = path.split("/")[3]
                task = db.get_task_by_id(task_id)
                if not task:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "Task not found"})
                    return
                if user.get("role") != "admin" and task.get("owner_id") != user["id"]:
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden"})
                    return
                logs = task_manager.get_task_logs(task_id)
                self._send_json(HTTPStatus.OK, {"logs": logs})
                return

            if path == "/api/admin/users":
                if user.get("role") != "admin":
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Admin permission required"})
                    return
                users = db.list_users()
                self._send_json(HTTPStatus.OK, {"users": users})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "API route not found"})

        def _handle_api_post(self, path: str) -> None:
            body = self._read_json_body()

            if path == "/api/auth/login":
                username = str(body.get("username", "")).strip()
                password = str(body.get("password", "")).strip()
                user = db.get_user_by_username(username)
                if not user or not db.verify_password(password, user["password_hash"], user["salt"]):
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "用户名或密码错误"})
                    return

                token = db.create_session(user["id"])
                user_data = {"id": user["id"], "username": user["username"], "role": user["role"]}
                cookie_header = {
                    "Set-Cookie": f"strix_hub_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800"
                }
                self._send_json(HTTPStatus.OK, {"token": token, "user": user_data}, headers=cookie_header)
                return

            if path == "/api/auth/logout":
                token = ""
                auth_header = self.headers.get("Authorization", "")
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:].strip()
                if not token:
                    cookie_str = self.headers.get("Cookie", "")
                    for c in cookie_str.split(";"):
                        parts = c.strip().split("=", 1)
                        if len(parts) == 2 and parts[0] == "strix_hub_session":
                            token = parts[1]
                if token:
                    db.delete_session(token)
                cookie_header = {"Set-Cookie": "strix_hub_session=; Path=/; HttpOnly; Max-Age=0"}
                self._send_json(HTTPStatus.OK, {"ok": True}, headers=cookie_header)
                return

            user = self._get_current_user()
            if not user:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized"})
                return

            # Create & Launch Task with Independent Dual Channel
            if path == "/api/tasks":
                target = str(body.get("target", "")).strip()
                if not target:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Target is required"})
                    return

                scan_mode = str(body.get("scan_mode", "deep")).strip()
                instruction = str(body.get("instruction", "")).strip()

                root_model = str(body.get("root_model", "openai/gemini-3.1-pro-preview")).strip()
                root_api_base = str(body.get("root_api_base", "")).strip()
                root_api_key = str(body.get("root_api_key", "")).strip()

                subagent_model = str(body.get("subagent_model", "openai/gemini-3.5-flash")).strip()
                subagent_api_base = str(body.get("subagent_api_base", "")).strip()
                subagent_api_key = str(body.get("subagent_api_key", "")).strip()

                task = db.create_task(
                    owner_id=user["id"],
                    owner_username=user["username"],
                    target=target,
                    scan_mode=scan_mode,
                    instruction=instruction,
                    root_model=root_model,
                    root_api_base=root_api_base,
                    root_api_key=root_api_key,
                    subagent_model=subagent_model,
                    subagent_api_base=subagent_api_base,
                    subagent_api_key=subagent_api_key,
                )

                started_task = task_manager.start_task(task["id"])
                self._send_json(HTTPStatus.CREATED, {"task": started_task})
                return

            if path.startswith("/api/tasks/") and path.endswith("/start"):
                task_id = path.split("/")[3]
                task = db.get_task_by_id(task_id)
                if not task or (user.get("role") != "admin" and task.get("owner_id") != user["id"]):
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden"})
                    return
                res = task_manager.start_task(task_id)
                self._send_json(HTTPStatus.OK, {"task": res, "status": "running"})
                return

            if path.startswith("/api/tasks/") and path.endswith("/pause"):
                task_id = path.split("/")[3]
                task = db.get_task_by_id(task_id)
                if not task or (user.get("role") != "admin" and task.get("owner_id") != user["id"]):
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden"})
                    return
                ok = task_manager.pause_task(task_id)
                self._send_json(HTTPStatus.OK, {"ok": ok, "status": "paused" if ok else task.get("status")})
                return

            if path.startswith("/api/tasks/") and path.endswith("/resume"):
                task_id = path.split("/")[3]
                task = db.get_task_by_id(task_id)
                if not task or (user.get("role") != "admin" and task.get("owner_id") != user["id"]):
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden"})
                    return
                ok = task_manager.resume_task(task_id)
                self._send_json(HTTPStatus.OK, {"ok": ok, "status": "running" if ok else task.get("status")})
                return

            if path.startswith("/api/tasks/") and path.endswith("/stop"):
                task_id = path.split("/")[3]
                task = db.get_task_by_id(task_id)
                if not task or (user.get("role") != "admin" and task.get("owner_id") != user["id"]):
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden"})
                    return
                ok = task_manager.stop_task(task_id)
                self._send_json(HTTPStatus.OK, {"ok": ok, "status": "stopped"})
                return

            if path == "/api/admin/users":
                if user.get("role") != "admin":
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Admin permission required"})
                    return
                username = str(body.get("username", "")).strip()
                password = str(body.get("password", "")).strip()
                role = str(body.get("role", "user")).strip()
                if not username or not password:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Username and password required"})
                    return
                new_user = db.create_user(username, password, role)
                if not new_user:
                    self._send_json(HTTPStatus.CONFLICT, {"error": "Username already exists"})
                    return
                self._send_json(HTTPStatus.CREATED, {"user": new_user})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

        def _handle_api_put(self, path: str) -> None:
            """Hot Update task configuration."""
            user = self._get_current_user()
            if not user:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized"})
                return

            if path.startswith("/api/tasks/") and path.endswith("/config"):
                task_id = path.split("/")[3]
                task = db.get_task_by_id(task_id)
                if not task or (user.get("role") != "admin" and task.get("owner_id") != user["id"]):
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden"})
                    return

                body = self._read_json_body()
                task_manager.hot_update_task_config(
                    task_id=task_id,
                    root_model=body.get("root_model"),
                    root_api_base=body.get("root_api_base"),
                    root_api_key=body.get("root_api_key"),
                    subagent_model=body.get("subagent_model"),
                    subagent_api_base=body.get("subagent_api_base"),
                    subagent_api_key=body.get("subagent_api_key"),
                )
                updated = db.get_task_by_id(task_id)
                self._send_json(HTTPStatus.OK, {"task": updated, "message": "配置热更新生效成功！"})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

        def _handle_api_delete(self, path: str) -> None:
            user = self._get_current_user()
            if not user:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized"})
                return

            if path.startswith("/api/tasks/"):
                task_id = path.split("/")[3]
                task = db.get_task_by_id(task_id)
                if not task or (user.get("role") != "admin" and task.get("owner_id") != user["id"]):
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden"})
                    return
                task_manager.stop_task(task_id)
                db.delete_task(task_id)
                self._send_json(HTTPStatus.OK, {"ok": True})
                return

            if path.startswith("/api/admin/users/"):
                if user.get("role") != "admin":
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Admin permission required"})
                    return
                del_id = path.split("/")[4]
                ok = db.delete_user(del_id)
                self._send_json(HTTPStatus.OK, {"ok": ok})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

        def _handle_static(self, path: str) -> None:
            self._serve_embedded_ui()

        def _serve_embedded_ui(self) -> None:
            html = EMBEDDED_SPA_HTML
            data = html.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return HubHandler


def serve(host: str = "0.0.0.0", port: int = 8888) -> None:
    db.init_db()
    handler = make_hub_handler()
    server = ThreadingHTTPServer((host, port), handler)
    logger.info("Strix Hub is running on http://%s:%d", host, port)
    print(f"\n=======================================================")
    print(f"🚀 Strix Hub Dual-Channel Platform running at:")
    print(f"👉 http://{host}:{port}")
    print(f"   Local LLM Provider: {LOCAL_LLM_URL}")
    print(f"=======================================================\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down Strix Hub...")
        server.server_close()


# Self-contained modern Web UI template (Tailwind + React bundle with Dual-Channel & Hot Reload)
EMBEDDED_SPA_HTML = """<!DOCTYPE html>
<html lang="zh-CN" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Strix Hub — 独立双渠道多模型自动化渗透控制台</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
  <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
  <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: { 500: '#10b981', 600: '#059669' }
          }
        }
      }
    }
  </script>
  <style>
    body { background-color: #080808; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif; }
    .glass-card { background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08); backdrop-filter: blur(12px); }
    .scrollbar-thin::-webkit-scrollbar { width: 6px; height: 6px; }
    .scrollbar-thin::-webkit-scrollbar-thumb { background: #262626; border-radius: 3px; }
  </style>
</head>
<body>
  <div id="root"></div>

  <script type="text/babel">
    const { useState, useEffect, useMemo, useRef } = React;

    function App() {
      const [user, setUser] = useState(null);
      const [loading, setLoading] = useState(true);
      const [view, setView] = useState("tasks"); // tasks | users
      const [tasks, setTasks] = useState([]);
      const [users, setUsers] = useState([]);
      const [presets, setPresets] = useState([]);
      const [localDefaults, setLocalDefaults] = useState({});
      const [showNewModal, setShowNewModal] = useState(false);
      const [hotConfigTask, setHotConfigTask] = useState(null);
      const [showLogsModal, setShowLogsModal] = useState(null);
      const [logsContent, setLogsContent] = useState("");

      const checkAuth = async () => {
        try {
          const res = await fetch("/api/auth/me");
          if (res.ok) {
            const data = await res.json();
            setUser(data.user);
          } else {
            setUser(null);
          }
        } catch (e) {
          setUser(null);
        } finally {
          setLoading(false);
        }
      };

      const fetchTasks = async () => {
        if (!user) return;
        try {
          const res = await fetch("/api/tasks");
          if (res.ok) {
            const data = await res.json();
            setTasks(data.tasks || []);
          }
        } catch (e) {}
      };

      const fetchPresets = async () => {
        try {
          const res = await fetch("/api/models/presets");
          if (res.ok) {
            const data = await res.json();
            setPresets(data.presets || []);
            setLocalDefaults(data.local_defaults || {});
          }
        } catch (e) {}
      };

      const fetchUsers = async () => {
        if (user?.role !== "admin") return;
        try {
          const res = await fetch("/api/admin/users");
          if (res.ok) {
            const data = await res.json();
            setUsers(data.users || []);
          }
        } catch (e) {}
      };

      useEffect(() => {
        checkAuth();
        fetchPresets();
      }, []);

      useEffect(() => {
        if (user) {
          fetchTasks();
          if (user.role === "admin") fetchUsers();
          const timer = setInterval(fetchTasks, 3000);
          return () => clearInterval(timer);
        }
      }, [user]);

      const handleLogout = async () => {
        await fetch("/api/auth/logout", { method: "POST" });
        setUser(null);
      };

      if (loading) {
        return (
          <div className="flex h-screen items-center justify-center">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-emerald-500 border-t-transparent"></div>
          </div>
        );
      }

      if (!user) {
        return <LoginView onLoginSuccess={checkAuth} />;
      }

      return (
        <div className="min-h-screen flex flex-col">
          {/* Top Navbar */}
          <header className="border-b border-neutral-800 bg-[#0d0d0d] px-6 py-4">
            <div className="mx-auto flex max-w-7xl items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold">
                  <i className="fa-solid fa-network-wired text-base"></i>
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h1 className="text-base font-bold text-white tracking-wide">Strix Hub</h1>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                      双渠道 · 热更新
                    </span>
                  </div>
                  <p className="text-[11px] text-neutral-500 font-mono">独立双渠道模型调度与任务控制中心</p>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <nav className="flex items-center gap-1 rounded-lg bg-neutral-900 border border-neutral-800 p-1 text-xs">
                  <button
                    onClick={() => setView("tasks")}
                    className={`px-3 py-1.5 rounded-md font-medium transition-colors ${view === "tasks" ? "bg-emerald-500 text-black font-bold" : "text-neutral-400 hover:text-white"}`}
                  >
                    <i className="fa-solid fa-list-check mr-1.5"></i>任务控制台
                  </button>
                  {user.role === "admin" && (
                    <button
                      onClick={() => { setView("users"); fetchUsers(); }}
                      className={`px-3 py-1.5 rounded-md font-medium transition-colors ${view === "users" ? "bg-emerald-500 text-black font-bold" : "text-neutral-400 hover:text-white"}`}
                    >
                      <i className="fa-solid fa-users-gear mr-1.5"></i>团队与成员
                    </button>
                  )}
                </nav>

                <div className="flex items-center gap-3 border-l border-neutral-800 pl-4">
                  <div className="text-right">
                    <span className="block text-xs font-semibold text-white">{user.username}</span>
                    <span className="inline-block text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-neutral-800 text-emerald-400 border border-neutral-700">
                      {user.role}
                    </span>
                  </div>
                  <button
                    onClick={handleLogout}
                    title="退出登录"
                    className="h-8 w-8 rounded-lg border border-neutral-800 bg-neutral-900 text-neutral-400 hover:text-red-400 hover:border-red-500/30 transition-colors flex items-center justify-center text-xs"
                  >
                    <i className="fa-solid fa-arrow-right-from-bracket"></i>
                  </button>
                </div>
              </div>
            </div>
          </header>

          {/* Main Content */}
          <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
            {view === "tasks" ? (
              <TasksView
                tasks={tasks}
                user={user}
                onOpenNew={() => setShowNewModal(true)}
                onOpenHotConfig={(task) => setHotConfigTask(task)}
                onRefresh={fetchTasks}
                onViewLogs={async (task) => {
                  setShowLogsModal(task);
                  const res = await fetch(`/api/tasks/${task.id}/logs`);
                  if (res.ok) {
                    const d = await res.json();
                    setLogsContent(d.logs || "暂无日志输出");
                  }
                }}
              />
            ) : (
              <UsersView users={users} onRefresh={fetchUsers} />
            )}
          </main>

          {/* New Task Modal */}
          {showNewModal && (
            <NewTaskModal
              presets={presets}
              localDefaults={localDefaults}
              onClose={() => setShowNewModal(false)}
              onSuccess={() => { setShowNewModal(false); fetchTasks(); }}
            />
          )}

          {/* Hot Update Model Config Modal */}
          {hotConfigTask && (
            <HotConfigModal
              task={hotConfigTask}
              localDefaults={localDefaults}
              onClose={() => setHotConfigTask(null)}
              onSuccess={() => { setHotConfigTask(null); fetchTasks(); }}
            />
          )}

          {/* Logs Modal */}
          {showLogsModal && (
            <LogsModal
              task={showLogsModal}
              logs={logsContent}
              onClose={() => setShowLogsModal(null)}
            />
          )}
        </div>
      );
    }

    // Login View
    function LoginView({ onLoginSuccess }) {
      const [username, setUsername] = useState("");
      const [password, setPassword] = useState("");
      const [error, setError] = useState("");
      const [submitting, setSubmitting] = useState(false);

      const handleSubmit = async (e) => {
        e.preventDefault();
        setError("");
        setSubmitting(true);
        try {
          const res = await fetch("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
          });
          const data = await res.json();
          if (res.ok) {
            onLoginSuccess();
          } else {
            setError(data.error || "登录失败");
          }
        } catch (e) {
          setError("网络异常，请检查后端服务");
        } finally {
          setSubmitting(false);
        }
      };

      return (
        <div className="flex min-h-screen items-center justify-center p-4">
          <div className="w-full max-w-md glass-card rounded-2xl p-8 space-y-6">
            <div className="text-center space-y-2">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <i className="fa-solid fa-shield-halved text-2xl"></i>
              </div>
              <h2 className="text-2xl font-bold text-white">Strix Hub 登录</h2>
              <p className="text-xs text-neutral-500">双渠道多智能体自动化渗透管理平台</p>
            </div>

            {error && (
              <div className="rounded-lg bg-red-500/10 border border-red-500/30 p-3 text-xs text-red-400 flex items-center gap-2">
                <i className="fa-solid fa-circle-exclamation"></i>
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-medium text-neutral-400">用户名</label>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin"
                  className="w-full rounded-lg border border-neutral-800 bg-neutral-900/80 px-3.5 py-2.5 text-sm text-white focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-medium text-neutral-400">密码</label>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full rounded-lg border border-neutral-800 bg-neutral-900/80 px-3.5 py-2.5 text-sm text-white focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <button
                type="submit"
                disabled={submitting}
                className="w-full rounded-lg bg-emerald-500 py-2.5 text-sm font-bold text-black transition-opacity hover:opacity-90 disabled:opacity-50"
              >
                {submitting ? "正在验证..." : "登录控制台"}
              </button>
            </form>

            <div className="text-center pt-2">
              <p className="text-[11px] text-neutral-500">
                默认管理员：<span className="font-mono text-neutral-400">admin / admin123</span>
              </p>
            </div>
          </div>
        </div>
      );
    }

    // Tasks View
    function TasksView({ tasks, user, onOpenNew, onOpenHotConfig, onRefresh, onViewLogs }) {
      const runningCount = tasks.filter(t => t.status === "running").length;
      const pausedCount = tasks.filter(t => t.status === "paused").length;
      const totalVulns = tasks.reduce((acc, t) => acc + (t.vulns_count || 0), 0);

      const handleAction = async (taskId, action) => {
        try {
          await fetch(`/api/tasks/${taskId}/${action}`, { method: "POST" });
          onRefresh();
        } catch (e) {}
      };

      const handleDelete = async (taskId) => {
        if (!confirm("确定要删除此任务记录吗？")) return;
        try {
          await fetch(`/api/tasks/${taskId}`, { method: "DELETE" });
          onRefresh();
        } catch (e) {}
      };

      return (
        <div className="space-y-6">
          {/* Metrics Top Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <div className="glass-card rounded-xl p-4 space-y-1">
              <span className="text-xs text-neutral-500">总扫描任务数</span>
              <div className="text-2xl font-bold text-white font-mono">{tasks.length}</div>
            </div>
            <div className="glass-card rounded-xl p-4 space-y-1 border-emerald-500/20">
              <span className="text-xs text-emerald-400 flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
                执行中任务
              </span>
              <div className="text-2xl font-bold text-white font-mono">{runningCount}</div>
            </div>
            <div className="glass-card rounded-xl p-4 space-y-1 border-amber-500/20">
              <span className="text-xs text-amber-400 flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-amber-400"></span>
                已暂停任务
              </span>
              <div className="text-2xl font-bold text-white font-mono">{pausedCount}</div>
            </div>
            <div className="glass-card rounded-xl p-4 space-y-1 border-purple-500/20">
              <span className="text-xs text-purple-400">累计挖掘漏洞</span>
              <div className="text-2xl font-bold text-purple-300 font-mono">{totalVulns}</div>
            </div>
          </div>

          {/* Header & New Button */}
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-bold text-white">渗透测试任务列表</h2>
              <p className="text-xs text-neutral-500">
                支持独立双渠道（云端+本地）与运行时配置热更新
              </p>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={onRefresh}
                className="px-3 py-2 rounded-lg border border-neutral-800 bg-neutral-900 text-xs text-neutral-300 hover:text-white transition-colors flex items-center gap-1.5"
              >
                <i className="fa-solid fa-arrows-rotate"></i> 刷新
              </button>
              <button
                onClick={onOpenNew}
                className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-xs font-bold text-black transition-colors flex items-center gap-1.5 shadow-[0_0_12px_rgba(16,185,129,0.2)]"
              >
                <i className="fa-solid fa-plus"></i> 新建双渠道任务
              </button>
            </div>
          </div>

          {/* Tasks Cards */}
          {tasks.length === 0 ? (
            <div className="glass-card rounded-2xl p-12 text-center space-y-3">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-neutral-900 text-neutral-600">
                <i className="fa-solid fa-radar text-xl"></i>
              </div>
              <p className="text-sm text-neutral-400">暂无进行中的渗透测试任务</p>
              <button
                onClick={onOpenNew}
                className="inline-flex items-center gap-1.5 text-xs text-emerald-400 hover:underline"
              >
                点击创建您的第一个双渠道扫描任务 →
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              {tasks.map((task) => (
                <div key={task.id} className="glass-card rounded-xl p-5 hover:border-neutral-700 transition-all space-y-4">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="space-y-2 min-w-0 flex-1">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <span className={`h-2.5 w-2.5 rounded-full flex-shrink-0 ${
                          task.status === "running" ? "bg-emerald-400 animate-ping" :
                          task.status === "paused" ? "bg-amber-400" :
                          task.status === "completed" ? "bg-blue-400" : "bg-neutral-600"
                        }`}></span>
                        <h3 className="text-base font-bold text-white font-mono">{task.target}</h3>
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-neutral-800 text-neutral-300 border border-neutral-700">
                          {task.scan_mode.toUpperCase()}
                        </span>
                        <span className={`text-[11px] font-semibold px-2.5 py-0.5 rounded-full uppercase border ${
                          task.status === "running" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" :
                          task.status === "paused" ? "bg-amber-500/10 text-amber-400 border-amber-500/30" :
                          task.status === "completed" ? "bg-blue-500/10 text-blue-400 border-blue-500/30" :
                          "bg-neutral-800 text-neutral-400 border-neutral-700"
                        }`}>
                          {task.status === "running" ? "扫描中" : task.status === "paused" ? "已暂停" : task.status === "completed" ? "已完成" : "已终止"}
                        </span>
                        {task.vulns_count > 0 && (
                          <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30">
                            发现 {task.vulns_count} 个漏洞
                          </span>
                        )}
                      </div>

                      {/* Dual Channel Model Details */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
                        <div className="rounded bg-black/40 p-2 border border-neutral-800/80 space-y-0.5">
                          <div className="text-purple-400 font-semibold flex items-center gap-1.5">
                            <i className="fa-solid fa-brain"></i> 主控大脑: {task.root_model.replace("openai/", "")}
                          </div>
                          <div className="text-[11px] text-neutral-500 truncate">
                            渠道: {task.root_api_base || "系统全局默认"}
                          </div>
                        </div>

                        <div className="rounded bg-black/40 p-2 border border-neutral-800/80 space-y-0.5">
                          <div className="text-emerald-400 font-semibold flex items-center gap-1.5">
                            <i className="fa-solid fa-bolt"></i> 探测打手: {task.subagent_model.replace("openai/", "")}
                          </div>
                          <div className="text-[11px] text-neutral-500 truncate">
                            渠道: {task.subagent_api_base || "系统全局默认"}
                          </div>
                        </div>
                      </div>

                      {/* Meta Footer */}
                      <div className="flex items-center gap-x-4 gap-y-1 flex-wrap text-xs text-neutral-500 font-mono">
                        <span><i className="fa-solid fa-user mr-1"></i>创建人: {task.owner_username}</span>
                        {task.duration_seconds > 0 && (
                          <span><i className="fa-regular fa-clock mr-1"></i>耗时: {Math.floor(task.duration_seconds / 60)} 分 {task.duration_seconds % 60} 秒</span>
                        )}
                      </div>

                      {task.instruction && (
                        <p className="text-xs text-neutral-400 bg-neutral-900/60 rounded p-2 border border-neutral-800 line-clamp-2">
                          <i className="fa-solid fa-terminal mr-1 text-emerald-500"></i> {task.instruction}
                        </p>
                      )}
                    </div>

                    {/* Action Controls */}
                    <div className="flex items-center gap-2 flex-shrink-0 flex-wrap sm:flex-nowrap">
                      {task.status === "running" && (
                        <button
                          onClick={() => handleAction(task.id, "pause")}
                          className="px-3 py-1.5 rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 text-xs font-semibold transition-colors flex items-center gap-1"
                        >
                          <i className="fa-solid fa-pause"></i> 暂停
                        </button>
                      )}

                      {task.status === "paused" && (
                        <button
                          onClick={() => handleAction(task.id, "resume")}
                          className="px-3 py-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 text-xs font-semibold transition-colors flex items-center gap-1"
                        >
                          <i className="fa-solid fa-play"></i> 继续
                        </button>
                      )}

                      {(task.status === "running" || task.status === "paused") && (
                        <button
                          onClick={() => handleAction(task.id, "stop")}
                          className="px-3 py-1.5 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/20 text-xs font-semibold transition-colors flex items-center gap-1"
                        >
                          <i className="fa-solid fa-stop"></i> 停止
                        </button>
                      )}

                      <button
                        onClick={() => onOpenHotConfig(task)}
                        title="热更新模型与渠道配置"
                        className="px-2.5 py-1.5 rounded-lg border border-neutral-700 bg-neutral-800 text-neutral-300 hover:text-emerald-400 text-xs font-medium transition-colors flex items-center gap-1"
                      >
                        <i className="fa-solid fa-sliders"></i> 热更
                      </button>

                      <button
                        onClick={() => onViewLogs(task)}
                        className="px-2.5 py-1.5 rounded-lg border border-neutral-700 bg-neutral-800 text-neutral-300 hover:text-white text-xs font-medium transition-colors flex items-center gap-1"
                      >
                        <i className="fa-solid fa-terminal"></i> 日志
                      </button>

                      <a
                        href={`http://${window.location.hostname}:8080/`}
                        target="_blank"
                        className="px-3 py-1.5 rounded-lg bg-neutral-100 hover:bg-white text-black text-xs font-bold transition-colors flex items-center gap-1"
                      >
                        <i className="fa-solid fa-eye"></i> 实时大屏
                      </a>

                      <button
                        onClick={() => handleDelete(task.id)}
                        className="h-7 w-7 rounded-lg border border-neutral-800 text-neutral-500 hover:text-red-400 hover:border-red-500/30 text-xs flex items-center justify-center transition-colors"
                      >
                        <i className="fa-regular fa-trash-can"></i>
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      );
    }

    // New Task Modal with Independent Dual Channel
    function NewTaskModal({ presets, localDefaults, onClose, onSuccess }) {
      const [target, setTarget] = useState("");
      const [scanMode, setScanMode] = useState("deep");
      const [instruction, setInstruction] = useState("");
      const [selectedPreset, setSelectedPreset] = useState("hybrid-gemini-qwen");

      // Root Channel
      const [rootModel, setRootModel] = useState(localDefaults.model || "openai/Qwen3.8-27B-abliterated");
      const [rootApiBase, setRootApiBase] = useState(localDefaults.url || "");
      const [rootApiKey, setRootApiKey] = useState(localDefaults.key || "");

      // Subagent Channel
      const [subagentModel, setSubagentModel] = useState(localDefaults.model || "openai/Qwen3.8-27B-abliterated");
      const [subagentApiBase, setSubagentApiBase] = useState(localDefaults.url || "");
      const [subagentApiKey, setSubagentApiKey] = useState(localDefaults.key || "");

      const [submitting, setSubmitting] = useState(false);
      const [error, setError] = useState("");

      const handlePresetChange = (presetId) => {
        setSelectedPreset(presetId);
        const p = presets.find(x => x.id === presetId);
        if (p && p.id !== "custom") {
          setRootModel(p.root_model);
          setRootApiBase(p.root_api_base || "");
          setRootApiKey(p.root_api_key || "");

          setSubagentModel(p.subagent_model);
          setSubagentApiBase(p.subagent_api_base || "");
          setSubagentApiKey(p.subagent_api_key || "");
        }
      };

      const fillLocalModelForRoot = () => {
        setRootModel(localDefaults.model || "openai/Qwen3.8-27B-abliterated");
        setRootApiBase(localDefaults.url || "http://127.0.0.1:8000/v1");
        setRootApiKey(localDefaults.key || "");
      };

      const fillLocalModelForSubagent = () => {
        setSubagentModel(localDefaults.model || "openai/Qwen3.8-27B-abliterated");
        setSubagentApiBase(localDefaults.url || "http://127.0.0.1:8000/v1");
        setSubagentApiKey(localDefaults.key || "");
      };

      const handleSubmit = async (e) => {
        e.preventDefault();
        setError("");
        setSubmitting(true);
        try {
          const res = await fetch("/api/tasks", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              target,
              scan_mode: scanMode,
              instruction,
              root_model: rootModel,
              root_api_base: rootApiBase,
              root_api_key: rootApiKey,
              subagent_model: subagentModel,
              subagent_api_base: subagentApiBase,
              subagent_api_key: subagentApiKey,
            }),
          });
          const data = await res.json();
          if (res.ok) {
            onSuccess();
          } else {
            setError(data.error || "创建任务失败");
          }
        } catch (e) {
          setError("网络请求失败");
        } finally {
          setSubmitting(false);
        }
      };

      return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="glass-card w-full max-w-3xl rounded-2xl p-6 sm:p-8 space-y-6 my-8 max-h-[90vh] overflow-y-auto scrollbar-thin">
            <div className="flex items-center justify-between border-b border-neutral-800 pb-4">
              <div className="flex items-center gap-2.5">
                <i className="fa-solid fa-rocket text-emerald-400"></i>
                <h3 className="text-lg font-bold text-white">新建双渠道渗透测试任务</h3>
              </div>
              <button onClick={onClose} className="text-neutral-500 hover:text-white">
                <i className="fa-solid fa-xmark text-lg"></i>
              </button>
            </div>

            {error && (
              <div className="rounded-lg bg-red-500/10 border border-red-500/30 p-3 text-xs text-red-400">
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-5">
              {/* Target & Scan Mode */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="sm:col-span-2 space-y-1">
                  <label className="text-xs font-semibold text-neutral-300">目标资产 (Target IP / Domain / URL) *</label>
                  <input
                    type="text"
                    required
                    placeholder="例如: 113.125.138.94 或 https://target.com"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    className="w-full rounded-lg border border-neutral-800 bg-neutral-900 px-3.5 py-2 text-sm text-white font-mono focus:border-emerald-500 focus:outline-none"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-neutral-300">扫描模式 (Scan Mode)</label>
                  <select
                    value={scanMode}
                    onChange={(e) => setScanMode(e.target.value)}
                    className="w-full rounded-lg border border-neutral-800 bg-neutral-900 px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
                  >
                    <option value="deep">深度渗透 (Deep)</option>
                    <option value="standard">标准审计 (Standard)</option>
                    <option value="quick">快速扫描 (Quick)</option>
                  </select>
                </div>
              </div>

              {/* Model Preset Selection */}
              <div className="space-y-2 border-t border-neutral-800 pt-4">
                <label className="text-xs font-semibold text-neutral-300 flex items-center justify-between">
                  <span>双渠道组合预设</span>
                  <span className="text-[10px] text-emerald-400 font-normal">支持 Qwen 3.8 无审查 / Gemini / Claude 自由调度</span>
                </label>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {presets.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => handlePresetChange(p.id)}
                      className={`text-left rounded-xl p-3 border transition-all ${
                        selectedPreset === p.id
                          ? "border-emerald-500 bg-emerald-500/10"
                          : "border-neutral-800 bg-neutral-900/60 hover:border-neutral-700"
                      }`}
                    >
                      <div className="text-xs font-bold text-white">{p.name}</div>
                      <div className="text-[11px] text-neutral-400 mt-1 line-clamp-2">{p.description}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Channel 1: Root Agent (Brain) */}
              <div className="rounded-xl p-4 bg-purple-950/10 border border-purple-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-purple-300 flex items-center gap-1.5">
                    <i className="fa-solid fa-brain text-purple-400"></i> 【渠道 1】主控大脑模型 (Root Agent — 统筹/漏洞挖掘)
                  </span>
                  <button
                    type="button"
                    onClick={fillLocalModelForRoot}
                    className="text-[11px] text-purple-400 hover:underline flex items-center gap-1 font-mono"
                  >
                    <i className="fa-solid fa-wand-magic-sparkles"></i> 一键填入本地/私有模型
                  </button>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="space-y-1">
                    <label className="text-[11px] text-neutral-300">模型名称 (Model) *</label>
                    <input
                      type="text"
                      required
                      value={rootModel}
                      onChange={(e) => { setRootModel(e.target.value); setSelectedPreset("custom"); }}
                      placeholder="openai/gemini-3.1-pro-preview"
                      className="w-full rounded-lg border border-neutral-800 bg-neutral-900 px-3 py-1.5 text-xs text-white font-mono focus:border-purple-500 focus:outline-none"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-[11px] text-neutral-300">专属 Base URL</label>
                    <input
                      type="text"
                      value={rootApiBase}
                      onChange={(e) => { setRootApiBase(e.target.value); setSelectedPreset("custom"); }}
                      placeholder="http://127.0.0.1:8000/v1"
                      className="w-full rounded-lg border border-neutral-800 bg-neutral-900 px-3 py-1.5 text-xs text-white font-mono focus:border-purple-500 focus:outline-none"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-[11px] text-neutral-300">专属 API Key</label>
                    <input
                      type="password"
                      value={rootApiKey}
                      onChange={(e) => { setRootApiKey(e.target.value); setSelectedPreset("custom"); }}
                      placeholder="sk-••••••••"
                      className="w-full rounded-lg border border-neutral-800 bg-neutral-900 px-3 py-1.5 text-xs text-white font-mono focus:border-purple-500 focus:outline-none"
                    />
                  </div>
                </div>
              </div>

              {/* Channel 2: Subagents (Muscles) */}
              <div className="rounded-xl p-4 bg-emerald-950/10 border border-emerald-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-emerald-300 flex items-center gap-1.5">
                    <i className="fa-solid fa-bolt text-emerald-400"></i> 【渠道 2】子智能体模型 (Sub-agents — 探测/高并发执行)
                  </span>
                  <button
                    type="button"
                    onClick={fillLocalModelForSubagent}
                    className="text-[11px] text-emerald-400 hover:underline flex items-center gap-1 font-mono"
                  >
                    <i className="fa-solid fa-wand-magic-sparkles"></i> 一键填入本地/私有模型
                  </button>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="space-y-1">
                    <label className="text-[11px] text-neutral-300">模型名称 (Model) *</label>
                    <input
                      type="text"
                      required
                      value={subagentModel}
                      onChange={(e) => { setSubagentModel(e.target.value); setSelectedPreset("custom"); }}
                      placeholder="openai/Qwen3.8-27B-abliterated"
                      className="w-full rounded-lg border border-neutral-800 bg-neutral-900 px-3 py-1.5 text-xs text-white font-mono focus:border-emerald-500 focus:outline-none"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-[11px] text-neutral-300">专属 Base URL</label>
                    <input
                      type="text"
                      value={subagentApiBase}
                      onChange={(e) => { setSubagentApiBase(e.target.value); setSelectedPreset("custom"); }}
                      placeholder="http://127.0.0.1:8000/v1"
                      className="w-full rounded-lg border border-neutral-800 bg-neutral-900 px-3 py-1.5 text-xs text-white font-mono focus:border-emerald-500 focus:outline-none"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-[11px] text-neutral-300">专属 API Key</label>
                    <input
                      type="password"
                      value={subagentApiKey}
                      onChange={(e) => { setSubagentApiKey(e.target.value); setSelectedPreset("custom"); }}
                      placeholder="sk-••••••••"
                      className="w-full rounded-lg border border-neutral-800 bg-neutral-900 px-3 py-1.5 text-xs text-white font-mono focus:border-emerald-500 focus:outline-none"
                    />
                  </div>
                </div>
              </div>

              {/* Instruction Prompt */}
              <div className="space-y-1 border-t border-neutral-800 pt-4">
                <label className="text-xs font-semibold text-neutral-300">专项渗透指导指令 (Instruction Prompt, 可选)</label>
                <textarea
                  rows="3"
                  placeholder="例如: 重点针对后台认证机制与 API 越权进行探测..."
                  value={instruction}
                  onChange={(e) => setInstruction(e.target.value)}
                  className="w-full rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-xs text-white placeholder-neutral-600 focus:border-emerald-500 focus:outline-none"
                ></textarea>
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 rounded-lg border border-neutral-800 text-xs text-neutral-400 hover:text-white"
                >
                  取消
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-5 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-xs font-bold text-black transition-colors disabled:opacity-50"
                >
                  {submitting ? "正在初始化并启动..." : "立即下发并启动任务"}
                </button>
              </div>
            </form>
          </div>
        </div>
      );
    }

    // Hot Update Model Config Modal
    function HotConfigModal({ task, localDefaults, onClose, onSuccess }) {
      const [rootModel, setRootModel] = useState(task.root_model || "openai/gemini-3.1-pro-preview");
      const [rootApiBase, setRootApiBase] = useState(task.root_api_base || "");
      const [rootApiKey, setRootApiKey] = useState("");

      const [subagentModel, setSubagentModel] = useState(task.subagent_model || "openai/Qwen3.8-27B-abliterated");
      const [subagentApiBase, setSubagentApiBase] = useState(task.subagent_api_base || "");
      const [subagentApiKey, setSubagentApiKey] = useState("");

      const [submitting, setSubmitting] = useState(false);
      const [msg, setMsg] = useState("");

      const fillLocalModelForHotRoot = () => {
        setRootModel(localDefaults.model || "openai/gemini-3.1-pro-preview");
        setRootApiBase(localDefaults.url || "http://127.0.0.1:8000/v1");
        setRootApiKey(localDefaults.key || "");
      };

      const fillLocalModelForHotSub = () => {
        setSubagentModel(localDefaults.model || "openai/Qwen3.8-27B-abliterated");
        setSubagentApiBase(localDefaults.url || "http://127.0.0.1:8000/v1");
        setSubagentApiKey(localDefaults.key || "");
      };

      const handleHotSave = async (e) => {
        e.preventDefault();
        setSubmitting(true);
        setMsg("");
        try {
          const res = await fetch(`/api/tasks/${task.id}/config`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              root_model: rootModel,
              root_api_base: rootApiBase,
              root_api_key: rootApiKey || undefined,
              subagent_model: subagentModel,
              subagent_api_base: subagentApiBase,
              subagent_api_key: subagentApiKey || undefined,
            }),
          });
          const d = await res.json();
          if (res.ok) {
            setMsg("配置热更新成功！实时网关已生效！");
            setTimeout(onSuccess, 1000);
          } else {
            setMsg(d.error || "更新失败");
          }
        } catch (e) {
          setMsg("网络错误");
        } finally {
          setSubmitting(false);
        }
      };

      return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="glass-card w-full max-w-2xl rounded-2xl p-6 space-y-5 max-h-[85vh] overflow-y-auto scrollbar-thin">
            <div className="flex items-center justify-between border-b border-neutral-800 pb-3">
              <div className="flex items-center gap-2">
                <i className="fa-solid fa-sliders text-emerald-400"></i>
                <h3 className="text-sm font-bold text-white font-mono">热更新模型与渠道配置 — {task.target}</h3>
              </div>
              <button onClick={onClose} className="text-neutral-500 hover:text-white">
                <i className="fa-solid fa-xmark"></i>
              </button>
            </div>

            <div className="text-xs text-amber-400 bg-amber-500/10 border border-amber-500/20 p-2.5 rounded-lg">
              <i className="fa-solid fa-bolt mr-1"></i> 热更新支持在任务执行或暂停中即时生效，底层的 ModelRouter 将动态切换路由通道。
            </div>

            {msg && <div className="text-xs p-2 rounded bg-neutral-800 text-emerald-400">{msg}</div>}

            <form onSubmit={handleHotSave} className="space-y-4">
              {/* Channel 1 */}
              <div className="space-y-2 rounded-xl p-3 bg-purple-950/10 border border-purple-500/20">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-purple-300">主控模型渠道 (Root Agent)</span>
                  <button
                    type="button"
                    onClick={fillLocalModelForHotRoot}
                    className="text-[11px] text-purple-400 hover:underline flex items-center gap-1 font-mono"
                  >
                    <i className="fa-solid fa-wand-magic-sparkles"></i> 填入本地/私有模型
                  </button>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <div>
                    <label className="text-[10px] text-neutral-400">模型名称</label>
                    <input
                      type="text"
                      value={rootModel}
                      onChange={(e) => setRootModel(e.target.value)}
                      className="w-full rounded border border-neutral-800 bg-neutral-900 px-2 py-1 text-xs text-white font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] text-neutral-400">Base URL</label>
                    <input
                      type="text"
                      value={rootApiBase}
                      onChange={(e) => setRootApiBase(e.target.value)}
                      placeholder="http://127.0.0.1:8000/v1"
                      className="w-full rounded border border-neutral-800 bg-neutral-900 px-2 py-1 text-xs text-white font-mono"
                    />
                  </div>
                </div>
              </div>

              {/* Channel 2 */}
              <div className="space-y-2 rounded-xl p-3 bg-emerald-950/10 border border-emerald-500/20">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-emerald-300">子智能体渠道 (Sub-agents)</span>
                  <button
                    type="button"
                    onClick={fillLocalModelForHotSub}
                    className="text-[11px] text-emerald-400 hover:underline flex items-center gap-1 font-mono"
                  >
                    <i className="fa-solid fa-wand-magic-sparkles"></i> 填入本地/私有模型
                  </button>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <div>
                    <label className="text-[10px] text-neutral-400">模型名称</label>
                    <input
                      type="text"
                      value={subagentModel}
                      onChange={(e) => setSubagentModel(e.target.value)}
                      className="w-full rounded border border-neutral-800 bg-neutral-900 px-2 py-1 text-xs text-white font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] text-neutral-400">Base URL</label>
                    <input
                      type="text"
                      value={subagentApiBase}
                      onChange={(e) => setSubagentApiBase(e.target.value)}
                      placeholder="http://127.0.0.1:8000/v1"
                      className="w-full rounded border border-neutral-800 bg-neutral-900 px-2 py-1 text-xs text-white font-mono"
                    />
                  </div>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-3 py-1.5 rounded-lg border border-neutral-800 text-xs text-neutral-400"
                >
                  取消
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-1.5 rounded-lg bg-emerald-500 text-xs font-bold text-black hover:bg-emerald-400 disabled:opacity-50"
                >
                  {submitting ? "正在热更新..." : "应用热更新"}
                </button>
              </div>
            </form>
          </div>
        </div>
      );
    }

    // Logs Modal
    function LogsModal({ task, logs, onClose }) {
      return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="glass-card w-full max-w-3xl rounded-2xl p-6 space-y-4 max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-neutral-800 pb-3">
              <div className="flex items-center gap-2">
                <i className="fa-solid fa-terminal text-emerald-400"></i>
                <h3 className="text-sm font-bold text-white font-mono">任务执行实时日志 — {task.target}</h3>
              </div>
              <button onClick={onClose} className="text-neutral-500 hover:text-white">
                <i className="fa-solid fa-xmark"></i>
              </button>
            </div>

            <div className="flex-1 bg-black rounded-xl p-4 overflow-y-auto font-mono text-xs text-neutral-300 leading-relaxed whitespace-pre-wrap scrollbar-thin border border-neutral-900">
              {logs}
            </div>

            <div className="flex justify-end">
              <button onClick={onClose} className="px-4 py-1.5 rounded-lg bg-neutral-800 text-xs text-white hover:bg-neutral-700">
                关闭
              </button>
            </div>
          </div>
        </div>
      );
    }

    // Users Management View (Admin Only)
    function UsersView({ users, onRefresh }) {
      const [username, setUsername] = useState("");
      const [password, setPassword] = useState("");
      const [role, setRole] = useState("user");
      const [submitting, setSubmitting] = useState(false);
      const [msg, setMsg] = useState("");

      const handleCreate = async (e) => {
        e.preventDefault();
        setSubmitting(true);
        setMsg("");
        try {
          const res = await fetch("/api/admin/users", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password, role }),
          });
          const d = await res.json();
          if (res.ok) {
            setUsername("");
            setPassword("");
            setMsg("成员创建成功");
            onRefresh();
          } else {
            setMsg(d.error || "创建失败");
          }
        } catch (e) {
          setMsg("网络错误");
        } finally {
          setSubmitting(false);
        }
      };

      const handleDelete = async (userId) => {
        if (!confirm("确定要注销此用户吗？")) return;
        try {
          await fetch(`/api/admin/users/${userId}`, { method: "DELETE" });
          onRefresh();
        } catch (e) {}
      };

      return (
        <div className="space-y-6">
          <div>
            <h2 className="text-lg font-bold text-white">团队成员与权限管理</h2>
            <p className="text-xs text-neutral-500">为团队成员创建独立账号，实现任务与测试数据的完全隔离。</p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Create User Form */}
            <div className="glass-card rounded-xl p-5 space-y-4 h-fit">
              <h3 className="text-sm font-bold text-white">新增团队成员</h3>
              {msg && <div className="text-xs p-2 rounded bg-neutral-800 text-emerald-400">{msg}</div>}

              <form onSubmit={handleCreate} className="space-y-3">
                <div className="space-y-1">
                  <label className="text-xs text-neutral-400">用户名</label>
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="成员用户名"
                    className="w-full rounded-lg border border-neutral-800 bg-neutral-900 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs text-neutral-400">初始密码</label>
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full rounded-lg border border-neutral-800 bg-neutral-900 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs text-neutral-400">角色权限</label>
                  <select
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    className="w-full rounded-lg border border-neutral-800 bg-neutral-900 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                  >
                    <option value="user">普通成员 (仅管理本人任务)</option>
                    <option value="admin">超级管理员 (管理全员任务及成员)</option>
                  </select>
                </div>

                <button
                  type="submit"
                  disabled={submitting}
                  className="w-full rounded-lg bg-emerald-500 py-2 text-xs font-bold text-black hover:bg-emerald-400 transition-colors disabled:opacity-50"
                >
                  创建成员账号
                </button>
              </form>
            </div>

            {/* Users List */}
            <div className="lg:col-span-2 glass-card rounded-xl p-5 space-y-4">
              <h3 className="text-sm font-bold text-white">成员列表 ({users.length})</h3>

              <div className="divide-y divide-neutral-800">
                {users.map((u) => (
                  <div key={u.id} className="py-3 flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-white">{u.username}</span>
                        <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded uppercase ${
                          u.role === "admin" ? "bg-purple-500/10 text-purple-400 border border-purple-500/30" : "bg-neutral-800 text-neutral-400"
                        }`}>
                          {u.role}
                        </span>
                      </div>
                      <div className="text-[11px] text-neutral-500 mt-0.5">
                        创建时间: {new Date(u.created_at * 1000).toLocaleString()}
                      </div>
                    </div>

                    {u.role !== "admin" && (
                      <button
                        onClick={() => handleDelete(u.id)}
                        className="px-2.5 py-1 rounded bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 text-xs"
                      >
                        删除
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      );
    }

    ReactDOM.render(<App />, document.getElementById("root"));
  </script>
</body>
</html>
"""
