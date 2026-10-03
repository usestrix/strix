# Strix 2 — Bug-bounty mode

Run the Strix engine as a **scoped bug-bounty engagement** against a single HackerOne or Bugcrowd program:
load the program's scope + rules of engagement, dedupe against disclosed reports, test only novel issues, and
get submission-ready write-ups.

Bug bounty is **authorized testing — but only within the program's scope and rules**. Bounty mode compiles the
program's published policy into Strix 2's existing, fail-closed scope engine and enforces the rules; it does
not loosen anything. You remain the accountable participant and submitter.

## 1. Describe the program

Bounty mode needs the program's scope + rules as a `BountyProgram`. Two ways to get one:

**A. From a file (offline, no token) — recommended to start.** Paste the program's published scope and rules
into a JSON or YAML file. Minimal shape (see `tests/fixtures/bounty/program_fromfile.yaml` for a full example):

```yaml
platform: hackerone            # or bugcrowd
handle: acme
name: Acme Security
url: https://hackerone.com/acme

in_scope:
  - { identifier: "*.acme.com",            asset_type: wildcard }
  - { identifier: "https://api.acme.com/v2", asset_type: api }
  - { identifier: "198.51.100.0/24",       asset_type: cidr }
out_of_scope:                   # carve-outs beat the wildcard above (deny-first)
  - { identifier: "blog.acme.com",         asset_type: domain }

roe:
  automated_testing_allowed: true     # false => mode refuses by default (see §3)
  state_changing_poc_allowed: false   # true => intrusive proofs auto-enabled (auto policy)
  rate_limit_rps: 5
  prohibited_actions: ["Denial of service", "Social engineering", "Physical"]
  ineligible_vuln_types: ["Self-XSS", "Missing SPF/DMARC"]
```

`asset_type` is optional — omit it and the compiler infers from the identifier (a `*` host → wildcard, a URL
with a path → API base, a CIDR/IP → network, `aws:<id>` → cloud). Mobile/source/binary assets are kept in the
record but cannot be auto-gated by the network scope engine, so they are reported as *unmapped* for you to
test deliberately.

**B. Live from the platform API** (`hackerone:<handle>` / `bugcrowd:<code>`). Set the token(s) in the
environment first:

```bash
export HACKERONE_API_USERNAME=<id>   # HackerOne uses Basic auth: identifier + token
export HACKERONE_API_TOKEN=<token>
export BUGCROWD_API_TOKEN=<token>
```

HackerOne exposes no machine-readable "automated testing allowed" flag or numeric rate limit (they live in the
free-text policy). Encode those as real rules with a companion ROE file via `--bounty-roe roe.yaml` (same
fields as the `roe:` block above); it is overlaid on whatever the API returned.

> **Platform support:** the HackerOne live pull is verified against the real API. The Bugcrowd live pull
> expects a Bugcrowd **API token** (not a web session cookie); Bugcrowd has no clean researcher REST API, so
> for Bugcrowd prefer **path A** (paste the program's brief into a file).

## 2. Run it

```bash
STRIX_LLM=openai/ds/deepseek-v4-pro LLM_API_BASE=http://localhost:20128/v1 LLM_API_KEY=<key> \
  uv run strix -n -t https://app.acme.com/ \
  --bounty-program ./acme.yaml \
  --bounty-known-reports ./acme_disclosed.json \
  --scan-mode quick --max-turns 40
```

- `--bounty-program` compiles the program scope into the authorized scope (it **overrides** `--scope-config`)
  and enforces the rules. Still pass `-t <in-scope asset>` to say where to start; scope confines the run.
- Run prerequisites are the same as any scan: Docker running + an LLM (see `02`/the usage runbook). Run it in
  the background — scans take minutes to tens of minutes.
- `--bounty-known-reports` is a JSON file of disclosed reports (Hacktivity / Crowdstream export, or a list of
  `{title, vuln_type, asset, url, state}`) to dedupe against.

## 3. Policies (the two knobs)

- `--bounty-automated-policy` — what to do when the program **prohibits** automated testing/scanners:
  - `refuse` (default): stop before any scan. Firing active tools at a program that bans them is outside its
    authorization — submissions get rejected, accounts get banned.
  - `recon_only`: map the surface, dedupe, and produce a manual test plan — no active tools.
  - `warn_and_proceed`: run the automated engine anyway. A deliberate, logged override — use only when you are
    sure the program permits it.
  (When the program allows or does not mention automated testing, the run proceeds normally.)
- `--bounty-intrusive-policy` — `auto` (default) permits state-changing proofs only when the program's ROE
  allows them; `never` forbids them regardless. `--allow-intrusive` can still force it on.

## 4. What the agents do

The run briefs the root agent to read `bounty_scope_status` first (scope, exclusions, unmapped assets, rules),
follow the `bounty/bounty_hunting` skill, delegate one domain specialist per in-scope domain, and — before
treating anything as submittable — call `check_duplicate` to rank it against the disclosed reports
(likely / possible / novel). Findings follow the two-tier discipline (a scanner signal is a *candidate*; a
demonstrated impact with captured I/O is a *validated finding*).

### Rules enforced at the tool boundary
When a program requires an identifying header or caps the request rate, bounty mode does more than tell the
agent — it enforces it:
- **Required header** (e.g. HackerOne's `X-Bug-Bounty: HackerOne-<username>`) is auto-derived from the policy
  (your real username is substituted for the policy's placeholder) or set via `--bounty-roe`. The
  `exec_command` gate **refuses** an HTTP CLI that targets a host without it, and the Caido `repeat_request`
  replay path **injects** it automatically.
- **Rate cap** (e.g. `10 per second`) is auto-derived too; a high-volume fuzzer (nuclei/ffuf/…) run without a
  rate flag is **refused** with the exact flag to add.
- Pure browser navigation is not force-injected (it is recon) — set the header there per the briefing.

## 5. Outputs — `strix_runs/<run>/bounty/`

- `program.json` — the compiled program (scope + rules).
- `dedupe.md` — the disclosed reports checked against.
- `submissions/<finding>.md` — one submission-ready write-up per validated finding: title, in-scope asset,
  severity + CVSS + CWE, reproduction steps, impact, evidence, and a **duplicate check** (verdict + closest
  known reports). `INDEX.md` lists them all.
- `README.md` — the engagement summary (program, mode, rules obeyed).

Review each submission (especially its duplicate check) before sending it to the program. You can regenerate
the artifacts for a finished run with `python -m strix.bounty.report strix_runs/<run>`.

## Authorization (unchanged, non-negotiable)

Only run against a program you are enrolled in and authorized to test, and only within its published scope and
rules. Out-of-scope targets are refused at the tool boundaries; prohibited techniques (DoS, social engineering,
physical, third-party services) are never performed; the rate limit and exclusions are enforced. See the usage
runbook for the general authorization gate.
