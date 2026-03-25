# Strix

开源 AI 安全代理，用于对 Web 应用、代码仓库和本地项目进行自动化安全评估、漏洞验证和结果归档。

## 项目定位

Strix 不是传统的静态扫描器。它会像真实安全研究员一样运行目标、调用浏览器和终端、编写与执行 PoC，并把发现结果整理成结构化事件、报告和漏洞产物。适合以下场景：

- 应用安全测试
- 灰盒或白盒渗透测试
- 漏洞赏金研究
- CI/CD 安全门禁
- 需要流式跟踪过程的自动化评估平台

## 核心能力

- 多代理协作，支持任务拆分、验证和汇总
- 同时覆盖代码仓库、本地目录、在线应用等多种目标
- 浏览器、HTTP、终端、Python runtime 等工具链开箱即用
- 通过 PoC 验证结果，尽量减少“只报不证”的误报
- CLI、TUI、Web API、内置 Web Demo 共用同一套扫描执行链
- 任务产物、事件流、最终报告统一落盘，便于二次集成

## 快速开始

### 前置要求

- Python 3.12+
- Docker 已安装并处于运行状态
- 可用的 LLM 提供商凭据

### 安装

生产环境或快速体验：

```bash
curl -sSL https://strix.ai/install | bash
```

本地开发环境：

```bash
git clone https://github.com/usestrix/strix.git
cd strix/strix_api
uv pip install -e .
```

如果你已经使用 Poetry，也可以执行：

```bash
poetry install
```

### 配置

Strix 运行时配置统一从 JSON 配置文件读取，默认路径为 `~/.strix/config.json`。

最小可用配置：

```json
{
  "llm": {
    "model": "openai/gpt-5.4",
    "api_key": "your-api-key"
  }
}
```

更完整的示例可以直接参考 [config.example.json](/Users/tao/Documents/docker/strix/strix/strix_api/config.example.json)。

常用配置项：

- `llm.model`：LiteLLM 模型标识，例如 `openai/gpt-5.4`
- `llm.api_key`：LLM 提供商 API Key
- `llm.api_base`：自定义网关或本地模型地址
- `llm.openai_compatible_provider`：显式声明 OpenAI 兼容 provider 名称
- `llm.reasoning_effort`：推理强度
- `features.perplexity_api_key`：联网研究能力所需的可选 Key
- `runtime.image`：沙箱镜像
- `api.host` / `api.port` / `api.auth_token`：Web API 服务配置

> Strix 不再依赖环境变量作为正常运行时配置来源。CLI、TUI 和 Web API 都优先读取配置文件。

### 第一次扫描

```bash
strix --target ./app-directory
```

常用示例：

```bash
# 扫描本地目录
strix --target ./app-directory

# 扫描在线应用
strix --target https://example.com

# 白盒 + 黑盒联合测试
strix --target https://github.com/org/repo --target https://staging.example.com

# 指定指令
strix --target https://example.com --instruction "重点看认证、IDOR 和业务逻辑"

# 从文件读取详细指令
strix --target https://example.com --instruction-file ./instruction.md

# 非交互模式，适合自动化
strix -n --target https://example.com --scan-mode quick

# 指定运行目录名称
strix --target ./app-directory --run-name audit-20260325
```

## Web API

启动 API 服务：

```bash
strix-api
```

也可以覆盖配置文件和监听地址：

```bash
strix-api --config ~/.strix/config.json --host 0.0.0.0 --port 8787
```

默认地址为 `http://127.0.0.1:8787`，任务接口统一挂在 `/api/v1` 下。

### 认证

如果配置了 `api.auth_token`，所有 `/api/v1/tasks*` 接口都需要携带 Bearer Token：

```text
Authorization: Bearer <your-token>
```

如果未配置 `api.auth_token`，则不校验认证。

### 文档入口

当 `api.enable_docs != false` 时，FastAPI 会暴露：

- `GET /docs`
- `GET /redoc`
- `GET /openapi.json`

### 创建任务请求

创建任务接口使用 JSON 请求体：

```json
{
  "targets": ["https://example.com"],
  "instruction": "重点看认证和 IDOR",
  "scan_mode": "deep",
  "task_id": "example-deep-scan"
}
```

字段说明：

- `targets`：必填，至少 1 项，支持本地目录、仓库 URL、在线应用 URL
- `instruction`：可选，直接传入扫描指令
- `instruction_file`：可选，服务端本地指令文件路径
- `scan_mode`：可选，`quick`、`standard`、`deep`，默认 `deep`
- `task_id`：可选，任务唯一标识
- `run_name`：可选，运行名称
- `config_path`：可选，该任务单独使用的配置文件路径

约束：

- `instruction` 与 `instruction_file` 不能同时传
- 不允许传入未定义字段
- 超过并发限制、任务重名、目标校验失败或配置文件非法时会返回 `400`

### 任务状态

任务状态枚举：

- `queued`
- `running`
- `cancelling`
- `completed`
- `failed`
- `cancelled`

### 接口速查

| 方法 | 路径 | 说明 | 响应要点 |
| --- | --- | --- | --- |
| `GET` | `/health` | 健康检查 | `{"status":"ok"}` |
| `POST` | `/api/v1/tasks` | 创建扫描任务 | 返回 `{"task": ...}` |
| `GET` | `/api/v1/tasks` | 列出任务 | 返回 `{"tasks": [...]}` |
| `GET` | `/api/v1/tasks/{task_id}` | 获取任务详情 | 实际返回完整结果对象 `{task, scan_state, artifacts}` |
| `GET` | `/api/v1/tasks/{task_id}/result` | 获取结构化结果 | 返回 `{task, scan_state, artifacts}` |
| `GET` | `/api/v1/tasks/{task_id}/results` | `/result` 别名 | 与 `/result` 相同 |
| `POST` | `/api/v1/tasks/{task_id}/cancel` | 取消任务 | 返回 `{"task": ...}` |
| `GET` | `/api/v1/tasks/{task_id}/events` | 获取历史事件 | 支持 `limit=1..5000` |
| `GET` | `/api/v1/tasks/{task_id}/stream` | SSE 流式订阅事件 | `text/event-stream` |
| `GET` | `/api/v1/tasks/{task_id}/artifacts` | 获取产物列表 | 返回文件路径数组 |
| `GET` | `/api/v1/tasks/{task_id}/report` | 获取最终报告 | 返回纯文本 Markdown |

### 响应结构

任务对象常见字段：

```json
{
  "task_id": "example-deep-scan",
  "run_name": "example-deep-scan",
  "status": "queued",
  "created_at": "2026-03-25T00:00:00+00:00",
  "updated_at": "2026-03-25T00:00:00+00:00",
  "started_at": null,
  "finished_at": null,
  "completed_at": null,
  "pid": 12345,
  "exit_code": null,
  "error": null,
  "request": {},
  "run_dir": "/abs/path/strix_runs/example-deep-scan",
  "worker_log_path": "/abs/path/strix_runs/example-deep-scan/worker.log",
  "scan_state_path": "/abs/path/strix_runs/example-deep-scan/scan_state.json",
  "events_path": "/abs/path/strix_runs/example-deep-scan/events.jsonl"
}
```

结果对象结构：

```json
{
  "task": {},
  "scan_state": {
    "run_metadata": {},
    "scan_config": {},
    "scan_results": {},
    "final_scan_result": "markdown text",
    "vulnerability_reports": [],
    "agents": {},
    "tool_executions": {},
    "chat_messages": []
  },
  "artifacts": [
    "/abs/path/strix_runs/example-deep-scan/events.jsonl",
    "/abs/path/strix_runs/example-deep-scan/scan_state.json"
  ]
}
```

说明：

- `artifacts` 当前返回的是本地文件路径，不是下载 URL
- `/api/v1/tasks/{task_id}` 与 `/api/v1/tasks/{task_id}/result` 当前返回结构一致
- `report` 接口返回纯文本响应，而不是 JSON

### 流式事件

事件流接口：

```bash
curl -N http://127.0.0.1:8787/api/v1/tasks/<task-id>/stream \
  -H 'Authorization: Bearer optional-api-token'
```

支持查询参数：

- `follow=true`：默认持续跟随新事件
- `from_offset=0`：从 `events.jsonl` 的字节偏移处继续读取

SSE 行为：

1. 建立连接后先发送 `stream.connected`
2. 随后把 `events.jsonl` 中的事件按 `event_type` 转成 SSE 事件名
3. 任务运行中会发送 `: keep-alive`
4. 任务结束后额外发送 `task.finished`

典型事件类型：

- `run.started`
- `run.configured`
- `agent.created`
- `agent.status.updated`
- `chat.streaming`
- `chat.message`
- `tool.execution.started`
- `tool.execution.updated`
- `finding.created`
- `finding.reviewed`
- `run.completed`
- `task.finished`

SSE 示例：

```text
event: stream.connected
data: {"task_id":"example-deep-scan","offset":0}

event: chat.message
data: {"offset":1234,"payload":{"event_type":"chat.message","payload":{"content":"hello"}}}

event: task.finished
data: {"task_id":"example-deep-scan","status":"completed"}
```

### 常见状态码

- `200 OK`：请求成功
- `201 Created`：任务创建成功
- `400 Bad Request`：业务校验失败
- `401 Unauthorized`：Token 缺失或错误
- `404 Not Found`：任务或报告不存在
- `422 Unprocessable Entity`：请求体或查询参数校验失败

### 常用调用示例

```bash
# 创建任务
curl -X POST http://127.0.0.1:8787/api/v1/tasks \
  -H 'Authorization: Bearer optional-api-token' \
  -H 'Content-Type: application/json' \
  -d '{
    "targets": ["https://example.com"],
    "instruction": "重点看认证和 IDOR",
    "scan_mode": "deep",
    "task_id": "example-deep-scan"
  }'

# 查看任务列表
curl http://127.0.0.1:8787/api/v1/tasks \
  -H 'Authorization: Bearer optional-api-token'

# 查看结构化结果
curl http://127.0.0.1:8787/api/v1/tasks/<task-id>/result \
  -H 'Authorization: Bearer optional-api-token'

# 拉取历史事件
curl http://127.0.0.1:8787/api/v1/tasks/<task-id>/events?limit=200 \
  -H 'Authorization: Bearer optional-api-token'

# 获取产物列表
curl http://127.0.0.1:8787/api/v1/tasks/<task-id>/artifacts \
  -H 'Authorization: Bearer optional-api-token'

# 获取最终 Markdown 报告
curl http://127.0.0.1:8787/api/v1/tasks/<task-id>/report \
  -H 'Authorization: Bearer optional-api-token'

# 取消任务
curl -X POST http://127.0.0.1:8787/api/v1/tasks/<task-id>/cancel \
  -H 'Authorization: Bearer optional-api-token'
```

更完整的接口说明请看：

- [docs/api/web-api.mdx](/Users/tao/Documents/docker/strix/strix/strix_api/docs/api/web-api.mdx)

## Web Demo

内置 Demo 页面用于展示任务管理、事件流和结果查看能力：

1. 启动 `strix-api`
2. 打开 `http://127.0.0.1:8787/demo`
3. 输入 API 地址和 Bearer Token
4. 在页面中创建任务、查看结果、回放事件、订阅流式输出

Demo 当前支持：

- 创建任务
- 查看任务列表与详情
- 获取 `/result` 和 `/results`
- 查看 `/events`、`/artifacts`、`/report`
- 取消任务
- 通过 SSE 流式查看执行过程

## 输出目录

默认情况下，每次运行都会写入：

```text
strix_runs/<run-name>/
```

常见文件：

- `task_state.json`：任务生命周期状态
- `events.jsonl`：事件流历史
- `scan_state.json`：结构化扫描状态与汇总结果
- `penetration_test_report.md`：最终 Markdown 报告
- `vulnerabilities/`：漏洞明细目录
- `vulnerabilities.csv`：漏洞索引
- `worker.log`：worker 标准输出与错误输出

## 文档索引

- [docs/api/web-api.mdx](/Users/tao/Documents/docker/strix/strix/strix_api/docs/api/web-api.mdx)：Web API 中文文档
- [docs/advanced/configuration.mdx](/Users/tao/Documents/docker/strix/strix/strix_api/docs/advanced/configuration.mdx)：配置说明
- [docs/usage/cli.mdx](/Users/tao/Documents/docker/strix/strix/strix_api/docs/usage/cli.mdx)：CLI 参数说明
- [docs/integrations/github-actions.mdx](/Users/tao/Documents/docker/strix/strix/strix_api/docs/integrations/github-actions.mdx)：GitHub Actions 集成

## 开发与测试

安装开发依赖后，可以执行：

```bash
make check-all
```

或按需运行：

```bash
uv run pytest -o addopts='' tests/api/test_server.py tests/api/test_task_store.py
python3 -m compileall strix tests
```

## 合规与免责声明

请仅测试你拥有或已获得明确授权的系统。使用者需自行确保测试行为符合当地法律、合同约束和组织安全规范。
