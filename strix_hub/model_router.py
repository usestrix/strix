"""Smart Dual-Channel Model Router Gateway for Strix Hub.

Intercepts requests from Strix and dynamically routes across DIFFERENT providers/channels:
- Root Agent (Commander/Orchestrator) -> Dispatches to (root_model, root_api_base, root_api_key)
- Subagents (Recon/Fuzzing/Testers)  -> Dispatches to (subagent_model, subagent_api_base, subagent_api_key)

Supports hot-reloading channel URLs, keys, and model identifiers dynamically.
"""

from __future__ import annotations

import json
import logging
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

logger = logging.getLogger("strix_hub.model_router")


class ModelRouterServer:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 18880,
        root_model: str = "openai/gemini-3.1-pro-preview",
        root_api_base: str = "",
        root_api_key: str = "",
        subagent_model: str = "openai/gemini-3.5-flash",
        subagent_api_base: str = "",
        subagent_api_key: str = "",
    ):
        self.host = host
        self.port = port
        self.config_lock = threading.Lock()
        self.config: dict[str, Any] = {
            "root_model": root_model,
            "root_api_base": root_api_base.rstrip("/"),
            "root_api_key": root_api_key,
            "subagent_model": subagent_model,
            "subagent_api_base": subagent_api_base.rstrip("/"),
            "subagent_api_key": subagent_api_key,
        }
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def update_config(self, **kwargs: Any) -> None:
        """Hot-reload routing channels and credentials on the fly."""
        with self.config_lock:
            for k, v in kwargs.items():
                if k in self.config and v is not None:
                    if k.endswith("_api_base") and isinstance(v, str):
                        self.config[k] = v.rstrip("/")
                    else:
                        self.config[k] = v
            logger.info(
                "ModelRouter config hot-updated (root_model=%s, subagent_model=%s)",
                self.config.get("root_model"),
                self.config.get("subagent_model"),
            )

    def start(self) -> None:
        handler = _create_router_handler(self)
        self.server = ThreadingHTTPServer((self.host, self.port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        logger.info("Dual-Channel Model Router Gateway listening on http://%s:%d/v1", self.host, self.port)

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


def _clean_model_name(model_str: str) -> str:
    """Strip litellm/openai prefixes like 'openai/Qwen3.6-35B-A3B' -> 'Qwen3.6-35B-A3B'."""
    if "/" in model_str:
        return model_str.split("/", 1)[1]
    return model_str


def _is_root_agent_payload(body: dict[str, Any]) -> bool:
    """Detect if the LLM request originated from Root Agent vs a Sub-agent."""
    messages = body.get("messages", [])
    if not isinstance(messages, list):
        return True

    text_corpus = ""
    for msg in messages:
        if isinstance(msg, dict):
            content = msg.get("content", "")
            if isinstance(content, str):
                text_corpus += " " + content
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and "text" in part:
                        text_corpus += " " + str(part["text"])

    text_lower = text_corpus.lower()
    if "root agent" in text_lower or "overall mission" in text_lower or "spawn_child_agent" in text_lower:
        return True
    if "subagent" in text_lower or "child agent" in text_lower or "agent_finish" in text_lower:
        return False
    return True


def _create_router_handler(router_instance: ModelRouterServer) -> type[BaseHTTPRequestHandler]:
    class RouterHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            logger.debug("Router %s - %s", self.address_string(), format % args)

        def do_OPTIONS(self) -> None:
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.end_headers()

        def do_GET(self) -> None:
            with router_instance.config_lock:
                cfg = dict(router_instance.config)

            clean_root = _clean_model_name(cfg["root_model"])
            clean_sub = _clean_model_name(cfg["subagent_model"])

            if self.path.endswith("/models"):
                models_payload = {
                    "object": "list",
                    "data": [
                        {"id": clean_root, "object": "model", "owned_by": "strix_hub"},
                        {"id": clean_sub, "object": "model", "owned_by": "strix_hub"},
                        {"id": cfg["root_model"], "object": "model", "owned_by": "strix_hub"},
                        {"id": cfg["subagent_model"], "object": "model", "owned_by": "strix_hub"},
                    ],
                }
                body = json.dumps(models_payload).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "strix_hub_dual_channel_router_ready"}')

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(length) if length else b""

            try:
                payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            except Exception:
                payload = {}

            with router_instance.config_lock:
                cfg = dict(router_instance.config)

            # 1. Determine if this request is for Root Agent or Sub-agent
            is_root = _is_root_agent_payload(payload) if isinstance(payload, dict) else True

            if is_root:
                target_model = _clean_model_name(cfg["root_model"])
                target_base = cfg["root_api_base"]
                target_key = cfg["root_api_key"]
                role_label = "Root Agent (主控大脑)"
            else:
                target_model = _clean_model_name(cfg["subagent_model"])
                target_base = cfg["subagent_api_base"]
                target_key = cfg["subagent_api_key"]
                role_label = "Subagent (执行打手)"

            # 2. Rewrite model in payload (preserving raw messages and reasoning context 100% intact)
            if isinstance(payload, dict):
                payload["model"] = target_model
                forward_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            else:
                forward_body = raw_body

            logger.info("ModelRouter: Forwarding [%s] -> Model: %s @ Channel: %s", role_label, target_model, target_base or "Default")

            # 3. Determine Upstream URL
            req_path = self.path
            if req_path.startswith("/v1/"):
                sub_path = req_path[len("/v1") :]
            else:
                sub_path = req_path

            upstream_url = f"{target_base}{sub_path}" if target_base else f"https://api.openai.com/v1{sub_path}"

            # 4. Determine Authorization Header
            auth_header = f"Bearer {target_key}" if target_key else self.headers.get("Authorization", "")

            headers = {
                "Content-Type": "application/json",
                "User-Agent": "StrixHub-DualChannelRouter/1.0",
            }
            if auth_header:
                headers["Authorization"] = auth_header

            is_stream = payload.get("stream", False) if isinstance(payload, dict) else False

            try:
                req = Request(upstream_url, data=forward_body, headers=headers, method="POST")
                with urlopen(req, timeout=600) as response:
                    self.send_response(response.status)
                    for k, v in response.getheaders():
                        if k.lower() not in ["content-length", "transfer-encoding", "content-encoding"]:
                            self.send_header(k, v)

                    if is_stream:
                        self.send_header("Transfer-Encoding", "chunked")
                        self.end_headers()
                        while True:
                            chunk = response.read(4096)
                            if not chunk:
                                break
                            self.wfile.write(f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n")
                            self.wfile.flush()
                        self.wfile.write(b"0\r\n\r\n")
                        self.wfile.flush()
                    else:
                        raw_data = response.read()
                        try:
                            json_obj = json.loads(raw_data.decode("utf-8"))
                            if isinstance(json_obj, dict) and "choices" in json_obj and json_obj["choices"]:
                                msg = json_obj["choices"][0].get("message", {})
                                content = msg.get("content", "") or ""
                                if not msg.get("tool_calls") and "<tool_call>" in content:
                                    extracted = _parse_qwen_tool_calls(content)
                                    if extracted:
                                        msg["tool_calls"] = extracted
                                        json_obj["choices"][0]["finish_reason"] = "tool_calls"
                                        logger.info("ModelRouter: Auto-extracted %d tool calls from Qwen text output!", len(extracted))
                                        raw_data = json.dumps(json_obj, ensure_ascii=False).encode("utf-8")
                        except Exception:
                            pass

                        self.send_header("Content-Length", str(len(raw_data)))
                        self.end_headers()
                        self.wfile.write(raw_data)
            except HTTPError as e:
                err_content = e.read()
                self.send_response(e.code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err_content)))
                self.end_headers()
                self.wfile.write(err_content)
            except Exception as exc:
                logger.exception("Router forwarding error to %s", upstream_url)
                err_msg = json.dumps({"error": {"message": str(exc), "type": "dual_channel_router_error"}}).encode("utf-8")
                self.send_response(HTTPStatus.BAD_GATEWAY)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err_msg)))
                self.end_headers()
                self.wfile.write(err_msg)

    return RouterHandler


def _parse_qwen_tool_calls(content: str) -> list[dict[str, Any]]:
    """Extract tool calls from plain text Qwen XML/JSON tags."""
    if not content or "<tool_call>" not in content:
        return []

    import re
    import uuid

    tool_calls: list[dict[str, Any]] = []
    matches = re.findall(r"<tool_call>(.*?)</tool_call>", content, re.DOTALL)
    for block in matches:
        block = block.strip()
        func_match = re.search(r"<function=([a-zA-Z0-9_-]+)>", block)
        if func_match:
            func_name = func_match.group(1)
            params: dict[str, Any] = {}
            param_matches = re.findall(r"<parameter=([a-zA-Z0-9_-]+)>\s*(.*?)\s*</parameter>", block, re.DOTALL)
            for k, v in param_matches:
                v = v.strip()
                try:
                    params[k] = json.loads(v)
                except Exception:
                    params[k] = v
            tool_calls.append({
                "id": f"call_{uuid.uuid4().hex[:8]}",
                "type": "function",
                "function": {
                    "name": func_name,
                    "arguments": json.dumps(params, ensure_ascii=False),
                },
            })
            continue

        clean_json = re.sub(r"^```(json)?|```$", "", block, flags=re.MULTILINE).strip()
        try:
            parsed = json.loads(clean_json)
            if isinstance(parsed, dict) and "name" in parsed:
                args = parsed.get("arguments", {})
                args_str = json.dumps(args, ensure_ascii=False) if isinstance(args, dict) else str(args)
                tool_calls.append({
                    "id": f"call_{uuid.uuid4().hex[:8]}",
                    "type": "function",
                    "function": {
                        "name": parsed["name"],
                        "arguments": args_str,
                    },
                })
        except Exception:
            pass

    return tool_calls
