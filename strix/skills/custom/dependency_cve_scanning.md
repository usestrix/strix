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

Every CVE you report carries a verdict in `reachability`, the proof in
`reachability_evidence`, and every usage site in `code_locations` (see
Reporting). The verdict answers one question for THIS advisory in THIS
codebase: does the vulnerable code run here? There are three answers and no
"unknown". The tool rejects a report without a verdict or without evidence,
so finish the analysis before you file.

- **`reachable`** — the advisory's vulnerable code executes in this codebase:
  application code, or a package it calls on the application's behalf, calls
  the affected function, mode or feature. Evidence: the call site as
  `file:line` and the source-to-sink trace (step 3).
- **`not_reachable`** — the package is loaded by the shipped code, but this
  CVE's vulnerable path does not execute here. Evidence: what you checked and
  why the path is dead. Typical reasons: no caller of the affected API after
  a complete search; the only call site is behind a condition that is false
  here (a polyfill for an older runtime, a flag that is off, a dev-only
  command); the parent package of a transitive dependency never references
  the affected API; the flaw sits in a mode or option this code never uses;
  the argument that triggers the flaw is a constant here.
- **`not_applicable`** — the advisory does not apply to this codebase at all:
  nothing the shipped code loads imports the package; it is build, test or
  dev tooling the artifact never executes; the installed copy is a patched or
  unaffected build; the flaw is specific to a platform this code does not run
  on; or the only code that could use it cannot be inspected (a compiled
  blob, a private bundle with no source) and nothing you can inspect reaches
  it. Evidence: the search scope and the negative result.

The verdict is per CVE, not per package. Sibling CVEs on one package usually
affect different symbols or modes (one hits a parser, another a header
check): run the check against each advisory's own affected functions and
never copy one CVE's verdict or evidence onto another. The import check
(step 1) is the only step shared across a package's CVEs.

`reachable` is not an exploit, and `not_reachable` / `not_applicable` are
not proof of safety (dynamic `import()`, reflection and framework wiring
evade static search). Say what you checked; never write "not exploitable".

**Procedure**

1. **Import check.** Search application code (exclude lockfiles, vendored
   deps, `node_modules`, build output) for imports of the vulnerable package
   under its ecosystem import name (`PyYAML` → `yaml`): `ast-grep`/`rg` for
   `import`/`require`/`from X import`. For a **transitive** dependency nothing
   in application code imports it, so walk every introducing chain from the
   lockfile (e.g. `express > body-parser > qs`) and inspect the code of the
   package one hop above the vulnerable one on each chain (`body-parser`, not
   just `express`; its installed sources, or the class references of its
   jar). Nothing imports it and no chain loads it ⇒ `not_applicable`, citing
   the scope you searched. Loaded ⇒ continue.
2. **Affected-symbol check, per CVE.** Read the advisory (GHSA/NVD/OSV
   `affected[].ecosystem_specific.imports`, the advisory text, the fix commit
   when the text is vague) for the functions, classes, options or modes that
   trigger the flaw. Search application code, and the parent package of a
   transitive dependency, for them (`ast-grep` pattern or `rg -n`; sibling
   CVEs can share one multi-pattern search per package). No caller after a
   complete search ⇒ `not_reachable`, citing the symbols and the scope. A
   caller ⇒ step 3. When the flaw is in code every use of the package runs
   (the parser the package exists for), the import itself is the call site ⇒
   step 3.
3. **Source-to-sink trace.** Start at the sink (the exact line that calls the
   affected function) and walk backwards hop by hop to the source: the entry
   point that carries the input (HTTP route, CLI argument, queue or webhook
   payload, uploaded file, config value). Read each intermediate function;
   when a hop is a thin wrapper, go one step deeper — never stop at the first
   caller. Read what reaches the function: a constant argument that cannot
   contain the triggering pattern, a flag that is off, a runtime-version
   gate, a path only a dev tool runs means the vulnerable path does not run
   ⇒ `not_reachable`, citing the condition. Otherwise ⇒ `reachable`. Write
   the chain into `reachability_evidence` as
   `entry point -> intermediate call -> package call` with a repo-relative
   `file:line` for every hop, what each hop enforces (authentication, a role
   check, validation, a size or type limit), and who controls the input. A
   trusted or operator-only source does not soften the verdict: the code
   runs, so it is `reachable`, and the trace is what tells the reader who can
   reach it; the contextual CVSS carries that.
4. **Go — govulncheck first.** When the Go toolchain and module deps are
   present, `govulncheck -format json ./... > "$ART/govulncheck.json"` gives a
   real call graph: a finding with a call stack ⇒ `reachable`, with the call
   path (entrypoint → vulnerable function) as the trace; an affected module
   with no reachable symbol ⇒ `not_reachable` when application code imports
   it (cite the govulncheck result and the import), `not_applicable` when
   nothing imports it. When govulncheck cannot analyze the module (build
   errors, missing deps), run steps 1–3 instead of guessing.

Work in severity order (critical, high and KEV first) so that if time runs
out the low tail is what is missing, and name that tail in the scan summary.
A CVE whose analysis you did not finish is neither filed with a guessed
verdict nor filed as `not_applicable`: finish it, or report the gap. Never let
the usage analysis silently drop a CVE: every advisory the scanner matched is
either filed with a verdict or named in the summary as not analyzed.

### Reachability is a verdict on the code path, not on severity

Do NOT suppress or downgrade a known CVE because its vulnerable code path is
not reached. Report it with its verdict, set `advisory_cvss` from the
advisory, put what the analysis proved in `reachability_evidence`, and use
`assumptions` for anything softer. If you *can* actually trigger the
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
  `poc_description` / `poc_script_code`. The proof lives in `description` and
  `technical_analysis` (scanner output + advisory).
- **You MUST report usage sites in `code_locations`.** Add one entry for each
  import of the package and each call of an affected symbol that your usage
  analysis found. Every `file:line` you cite in `reachability_evidence` must
  also be a `code_locations` entry. Also add the line in `manifest_path` that
  pins the vulnerable version. Each entry needs the repo-relative `file`, the
  exact `start_line` / `end_line`, the verbatim `snippet` at those lines, and a
  short `label` (e.g. "imports js-yaml", "calls yaml.load on CLI input"). Read
  the real file to confirm the lines; never guess. When the verdict is
  `not_applicable`, the manifest line is the only entry. If an entry carries
  `fix_before` / `fix_after`, also fill `fix_verification`.
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
  the tool rejects a report without a verdict or without evidence; use
  `assumptions` for anything softer (confidence, caveats, analysis limits).
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
  codebase. A `not_applicable` package the build still ships is usually `N`
  across all three.

Ground every metric in the **source-to-sink trace** from the usage analysis
(step 3 above), not in a general impression of the package. Derive the metrics
from that chain: `attack_vector`, `privileges_required`, and `user_interaction`
come from what the source requires; `attack_complexity` comes from the
preconditions the hops enforce; `confidentiality`, `integrity`, and
`availability` come from the data and privileges available at the sink.

When you have no source-to-sink trace, still rate the finding: copy the
published metrics, change only the metrics the usage level itself proves, and
say so in the reasoning. For example, for a `not_applicable` package that the
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
- Do not claim a `reachability` verdict the evidence does not prove, and do
  not file a CVE whose analysis you did not finish — report the gap instead.
- Do not send a report without `contextual_cvss_breakdown` and
  `contextual_cvss_reasoning` — the reader rates and ranks the finding with them.
- Do not use the contextual breakdown to quietly de-rate a CVE you could not
  analyze. State the limit of the analysis in the reasoning instead.
