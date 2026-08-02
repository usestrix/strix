# Strix MCP tools

## Lifecycle

- `start_scan`: initialize targets, report state, source mappings, and the Docker sandbox. Pass `targets`, `mounts`, `scan_mode`, `instruction`, and optional `run_name`. To resume, pass `run_name` and `resume=true`.
- `scan_status`: inspect active state, output path, configuration, and finding count.
- `stop_scan`: persist an incomplete run and tear down its sandbox.
- `finish_scan`: write `penetration_test_report.md`, `run.json`, vulnerability Markdown/CSV/JSON, and SARIF, then tear down the sandbox.

## Execution and knowledge

- `sandbox_exec`: pass an argv array, never a shell command string. Examples: `["bash", "-lc", "cd /workspace/app && semgrep scan --config auto"]`, `["agent-browser", "open", "https://target.example"]`.
- `list_knowledge`: list built-in Strix modules.
- `load_knowledge`: load a module by exact name, such as `frameworks/nextjs`, `protocols/graphql`, `vulnerabilities/idor`, or `tooling/agent_browser`.

## HTTP proxy

All HTTP(S) traffic from sandbox commands is routed through Caido.

1. Generate traffic with curl, Python, or `agent-browser` through `sandbox_exec`.
2. Use `list_proxy_requests` with an optional Caido HTTPQL filter.
3. Use `view_proxy_request` to inspect request or response content.
4. Use `repeat_proxy_request` with field-level modifications to test authorization, input handling, cookies, headers, or bodies.
5. Use `list_sitemap` and `view_sitemap_entry` to enumerate captured application structure.
6. Use `manage_scope` to create or update proxy allowlists and denylists.

## Findings

- `list_findings`: review existing reports before filing another.
- `create_vulnerability_report`: requires title, description, impact, target, technical analysis, PoC description, actual PoC code/payload, remediation, and all eight CVSS 3.1 base metrics. Optional fields include endpoint, method, CVE, CWE, and code locations.

CVSS keys and values:

- `attack_vector`: `N`, `A`, `L`, or `P`
- `attack_complexity`: `L` or `H`
- `privileges_required`: `N`, `L`, or `H`
- `user_interaction`: `N` or `R`
- `scope`: `U` or `C`
- `confidentiality`, `integrity`, `availability`: `N`, `L`, or `H`
