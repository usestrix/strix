---
name: strix2_domains
description: Root-agent guidance for delegating cloud/network/infra/api testing to Strix 2 domain specialists under the scope + two-tier discipline
---

# Strix 2 domain delegation (root agent)

Strix 2 extends this engagement beyond web to **network, cloud, infra/IaC, and API** targets, under a strict
**authorized-scope** policy and a **two-tier finding model**. As the root agent you orchestrate — you do not
run domain tools yourself; you **spawn a specialist subagent** per in-scope domain with the matching skill.

## Delegate by what the authorized scope actually contains
Read the scope first (`scope_status`). For each domain the scope authorizes, spawn one focused specialist:

| Scope contains | Spawn | Skill |
|---|---|---|
| `cloud.aws_account_ids` | `create_agent(name="cloud-agent", …)` | `cloud/aws_pentest` |
| `network.hosts` / `network.cidrs` | `create_agent(name="network-agent", …)` | `network/network_pentest` |
| IaC / container / image targets | `create_agent(name="infra-agent", …)` | `infra/infra_pentest` |
| `api.base_urls` | `create_agent(name="api-agent", …)` | `api/api_pentest` |

Give each specialist 1–3 related skills and a concrete task naming its in-scope targets. The cloud specialist
reaches AWS through the **auto-attached `strix-aws` MCP wrapper** (read-only, host-side, scope-gated); the
network/infra specialists use the in-sandbox CLIs via `exec_command`; the API specialist rides the Caido
proxy. Do not spawn a domain specialist for a domain the scope does not authorize.

## The two-tier discipline (enforce it on every specialist)
- A scanner/recon signal — an open port, a public-looking bucket, an over-permissive IAM policy, a static
  scanner hit, an enumerable endpoint — is a **candidate** (`create_candidate`), never a finding.
- A record becomes a **validated finding** only when the specialist demonstrates the impact with **captured
  I/O** and files `create_vulnerability_report`, then `promote_candidate`. Reconcile candidates vs. findings
  via `list_candidates` / `list_coverage` before `finish_scan`; unproven leads stay candidates, not findings.

## Scope is enforced, not advisory
Out-of-scope actions are refused at the tool boundaries (the `exec_command` shell gate, the `call_mcp`
boundary, and the cloud wrapper — all fail-closed for these domains). If a specialist reports a refusal, it
must pick an in-scope target or stop — do not try to work around scope. Intrusive/state-changing proof
requires the run to have been authorized with `--allow-intrusive`.
