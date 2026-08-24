---
name: dependency-cve-scanning
description: Supply-chain / SCA playbook — scan repository lockfiles for known dependency CVEs and report them with create_dependency_report (no dynamic PoC required)
---

# Dependency / Supply-Chain CVE Scanning (SCA)

Use this skill on white-box / repository scans to make sure a repository pinning a
**known-vulnerable dependency** is actually reported as a finding, instead of being
discovered and then silently dropped because it cannot be dynamically exploited.

Known-CVE dependency findings are a first-class deliverable. Report each one with
the dedicated `create_dependency_report` tool.

## Why this skill exists

A vulnerable dependency pinned in a lockfile (e.g. `lodash@4.17.4` with a known
prototype-pollution CVE) usually cannot be dynamically PoC'd from the outside —
the vulnerable code path may not even be reachable from a running endpoint. The
normal "no report without a dynamic PoC" rule would suppress it. For these
findings the proof is the **lockfile entry + scanner output + published
advisory**, not an exploit script. This is the one explicit exception to the
dynamic-validation rule, and it exists only for `create_dependency_report`.

## Scan procedure

Run from the repo root and store output in the shared artifact directory used by
the source-aware pass:

```bash
ART=/workspace/.source-aware
mkdir -p "$ART"

# Record the vuln DB age so a stale DB is a visible signal, not a silent clean scan.
trivy version --format json 2>/dev/null | tee "$ART/trivy-version.json"
# inspect .VulnerabilityDB.UpdatedAt / NextUpdate

# Lockfile/manifest -> known-CVE matching. Try a best-effort DB refresh first so a
# sandbox with egress gets the freshest CVEs; if the update fails, fall back to the
# cached DB instead of failing the scan. --offline-scan keeps per-package advisory
# lookups offline.
# --list-all-pkgs includes the package graph (Relationship + DependsOn) needed
# to attribute transitive CVEs to the direct dependency that introduces them.
trivy fs --scanners vuln --timeout 30m --offline-scan --list-all-pkgs \
  --format json --output "$ART/trivy-sca.json" . \
  || trivy fs --scanners vuln --timeout 30m --offline-scan --skip-db-update --list-all-pkgs \
       --format json --output "$ART/trivy-sca.json" . \
  || true
```

If `.VulnerabilityDB.UpdatedAt` is more than a few weeks old (the sandbox had no
egress to refresh it), treat it as a scan limitation and note it in the
`assumptions` of dependency findings — a stale DB that still returns *some* results
will not trip the "zero results is suspicious" heuristic, so its age is the only
staleness signal.

Trivy reads the lockfiles/manifests it finds, including:
`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`,
`requirements.txt`, `Pipfile.lock`, `go.mod`/`go.sum`, `Gemfile.lock`,
`pom.xml`/`gradle.lockfile`, `Cargo.lock`, `composer.lock`, etc.

If trivy returns zero vulnerabilities on a repo with dependencies, treat it as
suspicious: confirm the vuln DB is present (`trivy-version.json`) and that
lockfiles exist.

## Interpreting results

For each entry under `.Results[].Vulnerabilities[]` in `trivy-sca.json`, collect:

- `VulnerabilityID` — the CVE (or GHSA; prefer the CVE if both are present)
- `PkgName` and `InstalledVersion` — the affected package + pinned version
- `FixedVersion` — the version that resolves it
- `Target` — the lockfile path it came from
- `.Results[].Type` (e.g. `npm`, `pip`, `gomod`, `pom`, `gemspec`, `cargo`) — the
  package ecosystem; normalize to the registry name lowercased (`npm`, `pypi`,
  `go`, `maven`, `rubygems`, `cargo`, `composer`, `nuget`, ...)
- `CVSS` — the published advisory base score
- `PrimaryURL` / references — to verify the advisory

Deduplicate by `(CVE, PkgName, Target)` — the same CVE/package observed in two
different manifests (e.g. two workspaces of a monorepo) is two findings, one
per manifest. File one `create_dependency_report` per CVE — do not batch
multiple CVEs into one report.

### Attribute transitive CVEs to the direct dependency

With `--list-all-pkgs`, each `.Results[].Packages[]` entry carries `ID`
(`name@version`), `Relationship` (`direct` / `indirect`) and `DependsOn` (the
`ID`s it resolves to). For every vulnerable package that is **indirect**, walk
the `DependsOn` graph backwards to find the `direct` package(s) whose closure
contains it, then pass to `create_dependency_report`:

- `introduced_by` — the direct dependency as `name@version` (e.g.
  `express@4.18.1`). If several direct dependencies pull it in, pick the
  primary one and name the rest in `technical_analysis`.
- `dependency_path` — the shortest resolution chain from that direct
  dependency to the vulnerable package, joined with ` > ` (e.g.
  `express@4.18.1 > body-parser@1.20.0 > qs@6.10.2`).
- Omit both when the vulnerable package is itself a direct dependency.

If the ecosystem's lockfile gives trivy no graph (`DependsOn` absent), derive
the chain from the package manager instead (`npm ls <pkg>`, `pnpm why <pkg>`,
`yarn why <pkg>`, `pipdeptree --reverse -p <pkg>`, `go mod graph`,
`mvn dependency:tree`, ...) — and if that also fails, leave the fields out
rather than guessing.

For transitive findings, `remediation_steps` must be actionable at the
**direct-dependency level**: upgrading the vulnerable package directly is
usually impossible from the app's own manifest. Say which direct dependency to
bump (a version whose closure resolves the fixed version), or how to force the
resolution (npm `overrides` / yarn `resolutions` / pnpm `pnpm.overrides` /
Maven `dependencyManagement` / Gradle resolution strategy / `go mod edit`),
not just "upgrade <vulnerable pkg> to <fixed>".

### Usage / reachability analysis (required for every dependency CVE)

For every CVE you are about to report, run a static usage analysis and record
the result in the structured `reachability` + `reachability_evidence` fields.
The level is an **evidence ladder, never an exploitability verdict** — claim
only what you proved, and cite the proof. It never changes severity (that is
`advisory_cvss` alone); it exists so the reader can prioritize.

**Go — use govulncheck (real call-graph analysis):**

```bash
# Symbol-level: reports only vulnerabilities whose vulnerable functions are
# actually reachable from application code. Needs the Go toolchain + module
# deps; if either is missing, fall back to the checks below rather than
# claiming a level.
if command -v govulncheck >/dev/null && go version >/dev/null 2>&1; then
  govulncheck -format json ./... > "$ART/govulncheck.json" || true
fi
```

- A finding with a call stack ⇒ `reachability=reachable_call_path`, put the
  call-path excerpt (entrypoint → vulnerable function) in
  `reachability_evidence`.
- Listed as affecting a required module but with no reachable symbol ⇒ fall
  back to the import/symbol checks below (`imported` / `not_imported`).

**All other ecosystems — import check, then symbol match:**

1. **Import check.** Search application code (exclude lockfiles, vendored
   deps, `node_modules`, build output) for imports of the vulnerable package:
   `ast-grep`/`rg` for `import`/`require`/`from X import` of the package (and
   its ecosystem import name, which may differ from the registry name, e.g.
   `PyYAML` → `yaml`). No hits ⇒ `not_imported`, with the search scope stated
   in `reachability_evidence`. For a **transitive** dependency, the check is
   whether application code imports it directly; if not, it is reachable only
   through the direct dependency — check whether the direct dep's usage can
   hit it (if unclear, use `imported` when the direct dep is used at all).
2. **Symbol match — per CVE, not per package.** Read each CVE's own advisory
   (GHSA/NVD/OSV `affected[].ecosystem_specific.imports` or the advisory
   text) for the affected functions/classes/APIs. Search application code for
   those symbols (`ast-grep` pattern or `rg -n`). Hits ⇒
   `vulnerable_symbol_used`, with repo-relative `file:line` of each hit (up
   to a handful) in `reachability_evidence`. Imported but no affected-symbol
   usage found (or the advisory names no symbols) ⇒ `imported`.
   Different CVEs on the same package usually affect **different** symbols
   (one hits a parser, another a header check) — never copy one CVE's
   verdict/evidence onto its siblings; run the symbol search against each
   CVE's own affected-symbol list. The import check (step 1) is the only
   part shared across a package's CVEs.
3. **Source-to-sink trace — do this whenever step 2 found a symbol hit.** A
   symbol hit alone says the code calls the vulnerable API; it does not say
   who can reach it. Start at the sink (the exact line that calls the
   vulnerable function) and walk backwards hop by hop to the source: the
   entry point that carries untrusted input (HTTP route, CLI argument, queue
   or webhook payload, uploaded file, config value). Read each intermediate
   function; when a hop is a thin wrapper, go one step deeper — never stop at
   the first caller. Record what each hop enforces: authentication, a role
   check, validation, a feature flag, a size or type limit, a default that is
   off in production.
   Write the chain into `reachability_evidence` as
   `entry point -> intermediate call -> package call` with a
   repository-relative `file:line` for every hop, and say who controls the
   input. If no source reaches the sink, say that too — the level stays
   `vulnerable_symbol_used` (the call is real), and the trace is what tells
   the reader it is only reachable from, say, an operator CLI.
4. If the analysis was not performed or is inconclusive (obfuscated code,
   dynamic loading, unparsable sources) ⇒ `unknown` and say why in
   `assumptions`.

Cheap-first budgeting: the import check is one search per package — always do
it. Do the per-CVE symbol match for every CVE whose advisory names affected
symbols (they can be batched into one multi-pattern search per package);
prioritize `critical`/`high`/KEV when the budget is tight; a CVE whose symbol
search was skipped may still be reported as `imported` (the import check is
real evidence), but its `reachability_evidence` must state that the
affected-symbol check was not performed, so a skipped search is never
mistaken for a completed one with no hits. Never let this analysis stall
reporting — `unknown` with a reason beats an unverified claim.

Anti-overclaim rules:

- `not_imported` still does NOT mean safe (dynamic `import()`/reflection/
  framework wiring evade static search) — never phrase it as "not exploitable".
- `reachable_call_path` is reserved for call-graph tools (govulncheck); a
  symbol grep hit is `vulnerable_symbol_used`, no matter how convinced you are.
- The tool rejects any level other than `unknown` without
  `reachability_evidence`.

### Reachability is a confidence modifier, not a gate

Do NOT suppress or downgrade a known CVE just because you could not prove the
vulnerable code path is reachable. Report it, set `advisory_cvss` from the
advisory, record the usage analysis in `reachability`/`reachability_evidence`,
and use `assumptions` for anything softer. If you *can* actually trigger the
vulnerable path or chain it into a dynamic exploit, additionally report that
as a normal dynamic finding with `create_vulnerability_report` (the standalone
CVE stays in its own `create_dependency_report`).

## Reporting

Report each confirmed known CVE with the dedicated `create_dependency_report`
tool (NOT `create_vulnerability_report` — that tool is for dynamically validated
findings and rejects empty PoC fields):

- Set `cve` to the verified `CVE-YYYY-NNNNN` id (required). If you only have a
  GHSA, look up the mapped CVE; if there is genuinely no CVE, do not report it
  with this tool.
- There are no PoC fields — `create_dependency_report` does not take
  `poc_description` / `poc_script_code` / `code_locations`. The proof lives in
  `description` and `technical_analysis` (scanner output + advisory).
- **Always fill the structured dependency fields** (they power the dedicated
  dependency-report card; do not leave them only in free-text):
  - `package_name` — `PkgName` (required).
  - `installed_version` — `InstalledVersion` (required).
  - `package_ecosystem` — normalized ecosystem from `.Results[].Type` (lowercased,
    e.g. `npm`, `pypi`, `go`, `maven`, `rubygems`, `cargo`) (required).
  - `fixed_version` — `FixedVersion` (leave empty only if no fix is published).
  - `manifest_path` — the repo-relative `Target` lockfile/manifest path
    (required). Strip any scan-workspace or repo checkout directory prefix so
    the path is relative to the repository root (e.g. `package-lock.json`,
    `services/api/pom.xml`); the tool rejects absolute paths and `..` segments.
    This binds the finding to the exact file so remediation can target the
    right repository.
- Reference the repo-relative `Target` lockfile path in `description` /
  `technical_analysis` (no leading slash) so the finding is traceable.
- Put the concrete proof in `description` / `technical_analysis`: package name,
  installed/affected version, fixed version, lockfile path, and the relevant
  trivy output excerpt.
- **Always set `advisory_cvss` to the published advisory base score (0.0–10.0).**
  It is the published reference, and it rates the finding whenever you give no
  contextual breakdown: read it off the advisory (`CVSS` in trivy output, or the
  NVD/GHSA page) and pass the real value. The tool rejects a call that omits it,
  because guessing a score both inflates low CVEs and deflates critical ones.
- Set `cwe` to the most specific `CWE-NNN` when the advisory names one.
- Do NOT cap severity at LOW just because there is no dynamic reproduction — use
  the advisory score.
- Set `reachability` + `reachability_evidence` from the usage analysis above —
  the tool rejects a report with no evidence, so for `unknown` write what you
  searched and why the result is inconclusive;
  use `assumptions` for anything softer (confidence, caveats, analysis limits).
- **Always set `contextual_cvss_breakdown` + `contextual_cvss_reasoning`.** Every
  dependency finding carries a contextual rating of the CVE in this codebase
  (see below). Start from the published metrics and change only what your
  evidence proves.
- Set every other field the report accepts when the information exists:
  `package`, `ecosystem`, `installed_version`, `fixed_version`, `manifest_path`,
  `introduced_by` for a transitive package, `dependency_path`, `cwe`,
  `assumptions`, and the remediation instruction. A blank field costs the reader
  a triage step.

### Contextual CVSS

The published score rates the CVE in the abstract. `contextual_cvss_breakdown`
rates it **here**, in this codebase, and every dependency report must carry
one. It is the same 8-metric CVSS v3.1 object as a
normal finding's `cvss_breakdown` (`attack_vector`, `attack_complexity`,
`privileges_required`, `user_interaction`, `scope`, `confidentiality`,
`integrity`, `availability`). You never pass a score: the contextual score and
vector are computed from the breakdown, and when you provide one it determines
the finding's severity. `advisory_cvss` stays the published reference.

Start from the advisory's own published metrics and change only what your
evidence proves is different in this codebase:

- `attack_vector` `N`/`A`/`L`/`P` — as deployed. A library reached only by a
  local CLI is `L`, not `N`.
- `attack_complexity` `L`/`H` — raise to `H` when the vulnerable path needs a
  precondition the code enforces (input validation, a non-default flag, an
  internal-only route).
- `privileges_required` `N`/`L`/`H`, `user_interaction` `N`/`R` — what this
  deployment requires before the path is reachable.
- `scope` `U`/`C` — whether exploitation here escapes the component boundary.
- `confidentiality`/`integrity`/`availability` `N`/`L`/`H` — the impact in this
  codebase. `not_imported` code the build still ships is usually `N` across all
  three.

Ground every metric in the **source-to-sink trace** from the usage analysis
(step 3 above), not in a general impression of the package. Derive the metrics
from that chain: `attack_vector`, `privileges_required`, and `user_interaction`
come from what the source requires; `attack_complexity` comes from the
preconditions the hops enforce; `confidentiality`, `integrity`, and
`availability` come from the data and privileges available at the sink.

When you have no source-to-sink trace, still rate the finding: copy the
published metrics, change only the metrics the usage level itself proves, and
say so in the reasoning. For example, for a `not_imported` package that the
build still ships, keep the published metrics and lower `confidentiality`,
`integrity`, and `availability` to `N`, because no code path reaches the
vulnerable symbol. Never invent a hop you did not read.

`contextual_cvss_reasoning` is required with the breakdown. Write two to four
sentences that another engineer can check without opening the repository. Name
the chain hop by hop as `entry point -> intermediate call -> package call`, with
a repository-relative `file:line` for each hop, say who controls the input, and
say what the contextual rating changes. Example: lowering `attack_vector` to
`L` and `confidentiality` to `L` with "The only caller of `yaml.load` is
`parse_manifest` in `scripts/import.py:88`, which `cli/commands.py:212` invokes
for an operator-supplied path behind the `--allow-unsafe-import` flag that
`deploy/prod.yaml` never sets. No HTTP route reaches that function, so an
attacker must already hold shell access on the job host, and the parsed data is
build metadata rather than customer records."

When the published rating already fits this codebase, repeat the published
metrics in the breakdown and say in the reasoning that the deployment matches
the advisory. A contextual rating is a claim you must be able to defend, and it
never replaces `advisory_cvss` as the published reference.

Verify the CVE with `web_search` when available before reporting. Never guess or
hallucinate a CVE id.

## Anti-patterns

- Do not report a dependency CVE with `create_vulnerability_report`; use
  `create_dependency_report`.
- Do not report a finding without a verified CVE id.
- Do not batch multiple CVEs into one report.
- Do not omit `advisory_cvss` — the tool rejects it, and it rates every finding
  that carries no contextual breakdown.
- Do not silently drop a known CVE because it lacks a dynamic PoC — that is the
  exact failure this skill prevents.
- Do not downgrade advisory severity for lack of dynamic reproduction.
- Do not claim a `reachability` level the evidence does not prove — `unknown`
  with a reason is always acceptable; an overclaimed level never is.
- Do not send a report without `contextual_cvss_breakdown` and
  `contextual_cvss_reasoning` — the reader rates and ranks the finding with them.
- Do not use the contextual breakdown to quietly de-rate a CVE you could not
  analyze. State the limit of the analysis in the reasoning instead.
