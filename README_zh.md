<p align="center">
  <a href="https://strix.ai/">
    <img src="https://github.com/usestrix/.github/raw/main/imgs/cover.png" alt="Strix 横幅" width="100%">
  </a>
</p>

<div align="center">

# Strix

### 开源 AI 渗透测试工具。自主 AI 黑客,帮你发现并修复应用漏洞。

<br/>


<a href="https://docs.strix.ai"><img src="https://img.shields.io/badge/Docs-docs.strix.ai-2b9246?style=for-the-badge&logo=gitbook&logoColor=white" alt="文档"></a>
<a href="https://strix.ai"><img src="https://img.shields.io/badge/Website-strix.ai-f0f0f0?style=for-the-badge&logoColor=000000" alt="官网"></a>
[![](https://dcbadge.limes.pink/api/server/strix-ai)](https://discord.gg/strix-ai)

<a href="https://deepwiki.com/usestrix/strix"><img src="https://deepwiki.com/badge.svg" alt="向 DeepWiki 提问"></a>
<a href="https://github.com/usestrix/strix"><img src="https://img.shields.io/github/stars/usestrix/strix?style=flat-square" alt="GitHub Stars"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-3b82f6?style=flat-square" alt="许可证"></a>
<a href="https://pypi.org/project/strix-agent/"><img src="https://img.shields.io/pypi/v/strix-agent?style=flat-square" alt="PyPI 版本"></a>


<a href="https://discord.gg/strix-ai"><img src="https://github.com/usestrix/.github/raw/main/imgs/Discord.png" height="40" alt="加入 Discord"></a>
<a href="https://x.com/strix_ai"><img src="https://github.com/usestrix/.github/raw/main/imgs/X.png" height="40" alt="关注 X"></a>


<a href="https://trendshift.io/repositories/15362" target="_blank"><img src="https://trendshift.io/api/badge/repositories/15362" alt="usestrix/strix | Trendshift" width="250" height="55"/></a>

</div>


> [!TIP]
> **全新!** Strix 与 GitHub Actions 及 CI/CD 流水线无缝集成。在每个 Pull Request 上自动扫描漏洞,在不安全代码进入生产环境前将其拦截 —— [无需任何配置即可开始](https://app.strix.ai)。

---


## Strix 概览

Strix 是自主 AI 渗透测试 agent,行为如同真正的黑客 —— 动态运行你的代码、发现漏洞,并通过实际的漏洞验证概念(PoC)加以确认。专为需要快速、精准安全测试的开发者和安全团队打造,免去手动渗透测试的开销,也避免静态分析工具的误报。

**核心能力:**

- **全套渗透测试工具箱** —— 开箱即用的侦察、利用与验证
- **多 agent 编排** —— 多个 AI 渗透测试员协同工作、可扩展
- **真实漏洞验证** —— 可运行的 PoC,而非传统漏扫工具的误报
- **开发者优先的 CLI** —— 可操作的发现结果,附带修复指引
- **自动修复与报告** —— 生成补丁及合规就绪的渗透测试报告


<br>


<div align="center">
  <a href="https://strix.ai">
    <img src=".github/screenshot.png" alt="Strix 演示" width="1000" style="border-radius: 16px;">
  </a>
</div>


## 使用场景

- **应用安全测试** —— 检测并验证应用中的关键漏洞
- **快速渗透测试** —— 数小时而非数周完成渗透测试,附带合规报告
- **漏洞赏金自动化** —— 自动化赏金挖掘并生成 PoC,加速上报
- **CI/CD 集成** —— 在 CI/CD 中运行测试,在漏洞进入生产环境前拦截

## 🚀 快速开始

**前置条件:**
- Docker(运行中)
- 任一[受支持提供商](https://docs.strix.ai/llm-providers/overview)的 LLM API 密钥(OpenAI、Anthropic、Google 等)

### 安装与首次扫描

```bash
# 安装 Strix
curl -sSL https://strix.ai/install | bash

# 配置你的 AI 提供商
export STRIX_LLM="openai/gpt-5.4"
export LLM_API_KEY="your-api-key"

# 运行你的首次安全评估
strix --target ./app-directory
```

> [!NOTE]
> 首次运行会自动拉取沙箱 Docker 镜像。结果保存至 `strix_runs/<run-name>`

---

## ☁️ Strix 平台

在 **[app.strix.ai](https://app.strix.ai)** 体验 Strix 全栈渗透测试平台 —— 免费注册,连接你的仓库和域名,几分钟内发起一次渗透测试。

- **带 PoC 的已验证漏洞** —— 每个漏洞都包含可运行的漏洞验证利用及复现步骤
- **一键自动修复** —— AI 生成的安全补丁,作为可直接合并的 Pull Request
- **持续渗透测试** —— 常驻漏洞扫描,与你的部署节奏同步
- **DevSecOps 集成** —— GitHub、GitLab、Bitbucket、Slack、Jira、Linear 及 CI/CD 流水线
- **持续学习** —— AI 基于过往发现积累经验,适配你的代码库,随时间降低误报

[**发起你的首次渗透测试 →**](https://app.strix.ai)

---

## ✨ 功能特性

### Agentic 渗透测试工具

Strix agent 配备了全面的进攻安全工具箱 —— 与专业渗透测试员和道德黑客所用相同:

- **HTTP 拦截代理** —— 通过 Caido 实现完整的请求/响应操纵与分析
- **浏览器漏洞利用** —— 自动化浏览器,用于测试 XSS、CSRF、点击劫持及认证绕过流程
- **Shell 与命令执行** —— 用于漏洞开发利用和后渗透的交互式终端
- **自定义漏洞利用运行时** —— 用于编写并验证 PoC 漏洞利用的 Python 沙箱
- **侦察与 OSINT** —— 自动化攻击面测绘、子域名枚举与指纹识别
- **静态与动态代码分析** —— SAST + DAST 能力,全面的应用安全测试
- **漏洞知识库** —— 结构化发现结果,附带 CVSS 评分和 OWASP 分类

### 全面的漏洞扫描器

Strix 识别、验证并利用跨越 OWASP Top 10 及更广范围的各类安全漏洞:

- **访问控制失效** —— IDOR、权限提升、认证绕过
- **注入攻击** —— SQL 注入、NoSQL 注入、操作系统命令注入、SSTI
- **服务端漏洞** —— SSRF、XXE、不安全的反序列化、RCE
- **客户端攻击** —— XSS(存储型/反射型/DOM)、原型链污染、CSRF
- **业务逻辑缺陷** —— 竞态条件、支付操纵、流程绕过
- **认证与会话** —— JWT 攻击、会话固定、撞库向量
- **基础设施与云** —— 错误配置、暴露的服务、云安全问题
- **API 安全** —— 认证失效、批量赋值、速率限制绕过

### Agent 图(多 agent 渗透测试)

用于全面自动化渗透测试的高级多 agent 编排:

- **分布式渗透测试** —— 专用于侦察、利用和后渗透的专业 AI agent
- **可扩展的安全测试** —— 跨多个目标并行执行,快速、全面覆盖
- **动态协同** —— agent 共享发现、链式串联漏洞,如同红队般协作

---

## 使用示例

### 基本用法

```bash
# 扫描本地代码库
strix --target ./app-directory

# 对 GitHub 仓库进行安全审查
strix --target https://github.com/org/repo

# 黑盒 Web 应用评估
strix --target https://your-app.com
```

### 高级测试场景

```bash
# 灰盒认证测试
strix --target https://your-app.com --instruction "Perform authenticated testing using credentials: user:pass"

# 多目标测试(源代码 + 已部署应用)
strix -t https://github.com/org/app -t https://your-app.com

# 白盒源码感知扫描(本地仓库)
strix --target ./app-directory --scan-mode standard

# 通过自定义指令聚焦测试
strix --target api.your-app.com --instruction "Focus on business logic flaws and IDOR vulnerabilities"

# 通过文件提供详细指令(如交战规则、范围、排除项)
strix --target api.your-app.com --instruction-file ./instruction.md

# 针对特定 base 分支强制限定 PR diff 范围
strix -n --target ./ --scan-mode quick --scope-mode diff --diff-base origin/main
```

### 无头模式

使用 `-n/--non-interactive` 标志以编程方式运行 Strix,无需交互式 UI —— 非常适合服务器和自动化作业。CLI 会实时打印漏洞发现并在退出前输出最终报告。发现漏洞时以非零退出码退出。

```bash
strix -n --target https://your-app.com
```

### CI/CD(GitHub Actions)

可将 Strix 加入你的流水线,通过轻量级 GitHub Actions 工作流在 Pull Request 上运行安全测试:

```yaml
name: strix-penetration-test

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Install Strix
        run: curl -sSL https://strix.ai/install | bash

      - name: Run Strix
        env:
          STRIX_LLM: ${{ secrets.STRIX_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}

        run: strix -n -t ./ --scan-mode quick
```

> [!TIP]
> 在 CI 的 Pull Request 运行中,Strix 会自动将快速审查范围限定在变更文件。
> 若 diff 范围无法解析,请确保 checkout 使用完整历史(`fetch-depth: 0`),或显式传入
> `--diff-base`。

### 配置

```bash
export STRIX_LLM="openai/gpt-5.4"
export LLM_API_KEY="your-api-key"

# 可选
export LLM_API_BASE="your-api-base-url"  # 若使用本地模型,如 Ollama、LMStudio
export PERPLEXITY_API_KEY="your-api-key"  # 用于搜索能力
export STRIX_REASONING_EFFORT="high"  # 控制思考强度(默认:high,快速扫描:medium)
```

> [!NOTE]
> Strix 会自动将配置保存到 `~/.strix/cli-config.json`,因此无需每次运行都重新输入。

**为获得最佳效果,推荐模型:**

- [OpenAI GPT-5.4](https://openai.com/api/) - `openai/gpt-5.4`
- [Anthropic Claude Sonnet 4.6](https://claude.com/platform/api) - `anthropic/claude-sonnet-4-6`
- [Google Gemini 3 Pro Preview](https://cloud.google.com/vertex-ai) - `vertex_ai/gemini-3-pro-preview`

所有受支持的提供商(包括 Vertex AI、Bedrock、Azure 及本地模型)详见 [LLM 提供商文档](https://docs.strix.ai/llm-providers/overview)。

## 企业级渗透测试

通过[企业级](https://strix.ai/demo)控制获得相同的 Strix 体验:SSO(SAML/OIDC)、自定义合规就绪渗透测试报告(SOC 2、ISO 27001、PCI DSS)、专属支持与 SLA、自定义部署选项(VPC/自托管)、BYOK 模型支持,以及针对你的环境优化的定制 AI 渗透测试 agent。[了解更多](https://strix.ai/demo)。

## 文档

完整文档见 **[docs.strix.ai](https://docs.strix.ai)** —— 包括使用、CI/CD 集成、技能(skills)及高级配置的详细指南。

## 贡献

我们欢迎代码、文档及新技能的贡献 —— 查阅我们的[贡献指南](https://docs.strix.ai/contributing)开始参与,或提交 [Pull Request](https://github.com/usestrix/strix/pulls)/[issue](https://github.com/usestrix/strix/issues)。

## 加入社区

有疑问?发现 bug?想要贡献?**[加入我们的 Discord!](https://discord.gg/strix-ai)**

## 支持项目

**喜欢 Strix?** 在 GitHub 上给我们一个 ⭐!

## 致谢

Strix 建立在 [LiteLLM](https://github.com/BerriAI/litellm)、[Caido](https://github.com/caido/caido)、[Nuclei](https://github.com/projectdiscovery/nuclei)、[Playwright](https://github.com/microsoft/playwright) 和 [Textual](https://github.com/Textualize/textual) 等杰出开源项目之上。衷心感谢它们的维护者!


> [!WARNING]
> 仅对你拥有或已获授权测试的应用进行测试。你需对以合乎道德与法律的方式使用 Strix 负责。

</div>
