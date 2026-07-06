---
name: strix-security
description: Run authorized Strix application-security assessments through a coding agent and the Strix MCP server, including source review, reconnaissance, browser/API testing, exploit validation, vulnerability reporting, and resumable final reports. Use when asked to pentest, security-test, scan, assess, or find and validate vulnerabilities in a local codebase, repository, web application, domain, or IP address with Strix.
---

# Strix Security

Use the connected coding agent for all reasoning. Use only Strix MCP tools for the scan lifecycle, isolated offensive commands, proxy operations, findings, and report persistence. Never request a separate model API key or invoke a model API from Strix.

## Run the assessment

1. Confirm the targets are explicitly authorized. Treat the targets returned by `start_scan` as the hard scope; user instructions may narrow but never expand it.
2. Call `start_scan` once. For a prior run, pass its name with `resume=true`. Record the returned sandbox paths and output directory.
3. Call `load_knowledge` for `scan_modes/<mode>`. Load technology, framework, protocol, tooling, and vulnerability modules only when evidence makes them relevant.
4. Build a short test plan covering attack-surface discovery, authentication/authorization, input handling, data exposure, business logic, dependencies, and infrastructure as applicable.
5. Execute security commands with `sandbox_exec`. Source targets are under the returned `/workspace/<name>` paths. Drive the browser with the `agent-browser` CLI through `sandbox_exec`; inspect and replay its captured traffic with the proxy tools.
6. Validate every suspected issue with a concrete, reproducible proof of concept. Prefer safe demonstrations and avoid destructive actions, persistence, denial of service, or access beyond the authorized scope.
7. Call `list_findings` before filing. Call `create_vulnerability_report` once per distinct verified root cause. For white-box findings, include repository-relative `code_locations`, exact line ranges, and actionable fixes.
8. Continue until the selected scan mode is satisfied. Call `finish_scan` with customer-facing executive summary, methodology, consolidated technical analysis, and prioritized recommendations. Report the returned output directory.

## Quality bar

- Do not report scanner output, weak signals, version banners, missing headers, or theoretical code paths without exploitability and impact evidence.
- Distinguish separate endpoints, parameters, privileges, and root causes. Do not duplicate a finding with different wording.
- Keep customer-facing reports free of internal paths, agent/tool names, prompts, sandbox details, and model commentary.
- Preserve evidence in commands and reports, but never expose credentials or unrelated sensitive data.
- If blocked or interrupted, call `stop_scan` so artifacts and resume state remain usable.

Read [references/mcp-tools.md](references/mcp-tools.md) when tool selection, arguments, or the browser/proxy workflow is unclear.
