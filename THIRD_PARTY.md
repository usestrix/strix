# Third-Party Tools

Strix 2 (like upstream Strix) drives external security tools rather than vendoring their code.
Per the build brief, every wrapped tool is recorded here with its license and how it is invoked, and
redistribution compatibility is confirmed before a tool is wrapped.

## Wrapping model (why most of these impose no license obligation on this repo)

- **Subprocess / separate program.** In-sandbox tools are invoked as separate processes via the agent's
  shell (`exec_command`) inside the prebuilt sandbox image (`ghcr.io/usestrix/strix-sandbox`). Their
  binaries are installed from distribution packages / upstream releases **in the image**, not copied into
  this repository. This repo distributes **no** third-party tool source or binaries.
- **MCP / host-side (Phase 1+).** New domain tools (esp. cloud) are wrapped as MCP servers or host-side
  modules that shell out to the tool's own CLI. Same separation: we call the tool, we do not link or
  vendor it.
- Because invocation is at arm's length (separate process, separate distribution), copyleft licenses
  (GPL/AGPL/LGPL) on a wrapped CLI do **not** extend to Strix 2's own code. We still record them, and we
  will not vendor or statically link any incompatible code. This repository's own license is Apache-2.0
  (see `LICENSE`).

> **Confidence column.** ✅ = verified against the project's LICENSE. ⚠️ = commonly-cited license,
> **confirm at wrap time**. Anything wrapped in Phase 1+ gets its row promoted to ✅ with a link when the
> wrapper lands.

## Already relied upon — bundled in the sandbox image (`containers/Dockerfile`)

Invoked in-sandbox via shell; not redistributed by this repo.

| Tool | Purpose | License | Conf. |
|---|---|---|---|
| nmap | host/port/service discovery | Nmap Public Source License (NPSL; GPLv2-derived, custom terms) | ⚠️ |
| naabu | fast port scan | MIT (ProjectDiscovery) | ✅ |
| httpx | HTTP probing | MIT (ProjectDiscovery) | ✅ |
| katana | crawler | MIT (ProjectDiscovery) | ✅ |
| subfinder | subdomain enum | MIT (ProjectDiscovery) | ✅ |
| nuclei | templated checks | MIT (ProjectDiscovery) | ✅ |
| interactsh-client | OOB interaction | MIT (ProjectDiscovery) | ✅ |
| vulnx (cvemap) | CVE lookup | MIT (ProjectDiscovery) | ⚠️ |
| gospider | crawler | MIT | ⚠️ |
| govulncheck | Go vuln scan | BSD-3-Clause (golang.org/x/vuln) | ✅ |
| sqlmap | SQLi exploitation | GPL-2.0 | ✅ |
| ffuf | fuzzing | MIT | ✅ |
| wapiti | web scanner | GPL-2.0 | ⚠️ |
| trivy | container/IaC/vuln scan | Apache-2.0 | ✅ |
| semgrep | SAST | LGPL-2.1 (CLI) | ⚠️ |
| bandit | Python SAST | Apache-2.0 | ✅ |
| ast-grep | structural search | MIT | ✅ |
| trufflehog | secret scanning | AGPL-3.0 | ⚠️ |
| gitleaks | secret scanning | MIT | ✅ |
| retire.js | JS dep vuln scan | Apache-2.0 | ⚠️ |
| arjun | param discovery | GPL-3.0 | ⚠️ |
| dirsearch | content discovery | GPL-2.0 | ⚠️ |
| wafw00f | WAF fingerprint | BSD-3-Clause | ⚠️ |
| jwt_tool | JWT testing | GPL-3.0 | ⚠️ |
| agent-browser | headless browser driver | (verify) | ⚠️ |
| Caido CLI | HTTP proxy | proprietary/free tier (verify redistribution) | ⚠️ |

> `masscan` and `checkov` are **not** in the current image; if wrapped later, add rows
> (masscan: AGPL-3.0; checkov: Apache-2.0 — confirm at wrap time).

## Landed — Phase 1 wrappers

| Tool | Domain | How wrapped | License | Conf. |
|---|---|---|---|---|
| boto3 (AWS SDK) | cloud API calls (read-only validation PoC) | host-side MCP wrapper `strix/mcp_servers/aws.py`, **imported as a library** (not a subprocess) | Apache-2.0 | ✅ |

> **boto3 is a library dependency, not an arm's-length subprocess**, so the "separate program"
> reasoning above does not apply — but boto3 is Apache-2.0 (permissive), which is compatible with this
> repo's Apache-2.0 license and imposes no copyleft obligation. It is already resolved transitively via
> `litellm` (a core dependency), so the AWS wrapper adds **no new install requirement**. The wrapper is
> read-only (STS identity, S3 recon + a bounded ≤1 KiB object read), runs host-side so AWS credentials
> never enter the sandbox, and is scope-gated on `cloud.aws_account_ids` (fail-closed without a scope).

## To be wrapped — later Phase 1/3 (network / cloud / infra / API)

Rows are provisional targets; each is confirmed and promoted to ✅ when its wrapper lands.

| Tool | Domain | Planned wrap | License (to confirm) |
|---|---|---|---|
| prowler | cloud (AWS/Azure/GCP) misconfig | host-side MCP (creds stay on host) | Apache-2.0 ⚠️ |
| ScoutSuite | cloud multi-provider audit | host-side MCP | GPL-2.0 ⚠️ |
| CloudFox | cloud attack-path enum | host-side MCP | Apache-2.0 / MIT ⚠️ |
| checkov | IaC static analysis | in-sandbox native/skill (tool runs in the sandbox) | Apache-2.0 ⚠️ |
| nuclei | infra templated checks (already present) | native/skill sequencing | MIT ✅ |

> **Network/infra tools are NOT host-side MCP wrappers.** They already live in the sandbox image and are
> reachable via `exec_command`; a host-side MCP subprocess cannot see the sandbox. They gain the Strix 2
> scope + candidate discipline as in-sandbox native tools / skills (Phase 2/3), not as MCP wrappers.
> Host-side MCP is for tooling that must hold credentials off the sandbox (cloud) — see the design log.

## Referenced knowledge sources (not vendored)

Strix 2's internal skill playbooks (`strix/skills2/`) are **original**, tailored to Strix's own tools and the
two-tier / scope discipline. They *link* to external methodology collections for deeper technique detail; we
reference these, we do not copy or vendor their files.

| Source | What | License |
|---|---|---|
| [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | 800+ agent cybersecurity skill guides (network / api / infra / cloud pentest, mapped to MITRE ATT&CK / NIST) | Apache-2.0 |

> Apache-2.0 is compatible with this repo's Apache-2.0 license. The `skills2/` playbooks are original and only
> **link** to the source as further reading. If substantive text from a referenced source is ever adapted
> into a skill file, add its attribution here and keep the license notice at that point.

## Method for confirming a license before wrapping
1. Read the tool's `LICENSE` at the pinned version.
2. Confirm we invoke it as a separate process (no linking/vendoring of its code).
3. Record the version pinned in the image / wrapper here.
4. If a tool's license would require redistributing source when we distribute *it* — we don't distribute
   it (it's fetched at image-build / install time), so the obligation doesn't attach; note that explicitly.
