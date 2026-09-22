---
name: supply-chain-attack-recon
description: Supply-chain attack surface recon for typosquatting, dependency confusion, maintainer takeover, and build-script risk beyond known-CVE scanning
---

# Supply-Chain Attack Recon

`dependency_cve_scanning` finds known-CVE risk in the dependency tree. `npx_confusion` covers package-runner identity confusion. This skill covers the remaining supply-chain surface: attacks that don't require any existing CVE — they exploit trust assumptions in how package ecosystems resolve names, verify maintainers, and execute install-time code.

## Attack Surface

- Internal/private package names referenced in `package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, `pom.xml` that may not be claimed on the corresponding public registry
- Install-time build scripts (`postinstall`, `preinstall`, setup.py `install` overrides) across the full dependency tree, not just direct dependencies
- Package maintainer contact/domain validity for actively-relied-upon dependencies
- Lockfile integrity/hash-pinning completeness

## Key Techniques

### Typosquat-Candidate Generation

For each of the target's own internal/private package names (found in a source-aware review of `package.json`/`requirements.txt`/etc., or inferred from internal tool names surfaced during OSINT), generate typosquat candidates and check public registry claim status:
- Character substitution (`react` → `raect`), omission (`lodash` → `lodsh`), adjacent-key typos, hyphen/underscore swaps (`some-pkg` vs `some_pkg`), pluralization (`util` vs `utils`)
- Check npm, PyPI, RubyGems, crates.io, Go module proxy for each candidate — an unclaimed high-similarity name against a package the target's build actually pulls in (even transitively) is a real, reportable finding: register it defensively (with program permission) or report the gap for the target to claim themselves
- Do not actually publish a malicious package under a typosquat candidate — the finding is "this name is unclaimed and would collide with your dependency tree," not a live proof-of-compromise

### Dependency Confusion

The classic internal-package-name-not-claimed-publicly attack:
1. Identify internal package names from `package.json`/`requirements.txt`/internal build configs (often visible in JS source maps, CI config leaked in a public repo, or a `.npmrc`/`.pip.conf` pointing at a private registry alongside a public-fallback configuration)
2. Check whether that exact name exists on the public registry (npm, PyPI)
3. If unclaimed, and the target's build tooling is misconfigured to prefer the public registry (or falls back to it) over the intended private one for that name, a package published there would be pulled automatically on the next build — again, report the misconfiguration and the unclaimed name; do not publish a live package unless the program's rules explicitly permit and scope that PoC
- This is highest-value when combined with source-aware review: a leaked internal CI config showing `registry=https://npm.internal.target.com` for scoped packages but no explicit pin for unscoped internal names is the exact misconfiguration pattern to look for

### Maintainer/Domain Takeover Risk

For dependencies the target's build critically relies on (check `package-lock.json`/`poetry.lock` for maintainer contact info, or query the registry API directly):
- Check whether the listed maintainer email's domain is still registered/resolves (an expired personal domain used as a maintainer's npm account recovery email is a known real-world takeover vector — recovering that domain lets an attacker reset the maintainer's registry account)
- Check package publish cadence — a critical, widely-relied-upon package with no updates in years and a maintainer whose other public accounts (GitHub, personal site) appear abandoned is higher risk for this kind of takeover
- This is a reconnaissance/risk-flagging exercise, not something to exploit directly (registering an expired domain to demonstrate takeover crosses into infrastructure acquisition that needs explicit separate authorization) — report the risk with evidence (WHOIS/expiry status) rather than executing the takeover

### Build-Script (`postinstall`) Supply-Chain Risk

- Recursively enumerate `postinstall`/`preinstall` scripts across the *entire* resolved dependency tree (not just direct dependencies — most real-world npm supply-chain compromises hit a deeply transitive dependency):
```
npm ls --all --json | jq -r '.. | .name? // empty' | sort -u > all_deps.txt
# For each resolved package, check its package.json for install-time scripts
find node_modules -name package.json -exec jq -r 'select(.scripts.postinstall or .scripts.preinstall) | input_filename' {} \;
```
- Flag any transitive dependency running non-trivial logic (network calls, binary downloads, obfuscated/minified script content) at install time — this is the exact mechanism used in real npm/PyPI supply-chain compromises and is worth flagging even absent a known CVE, since it's a standing risk surface regardless of current compromise status
- For Python, check `setup.py` for custom `install` command overrides (rarer than npm postinstall, but same risk class)

### Lockfile Integrity Gaps

- Confirm the lockfile pins exact versions **and** includes integrity hashes (`integrity` field in `package-lock.json`/`yarn.lock`, hash pins in `requirements.txt` via `--hash`, `Cargo.lock` checksums)
- A lockfile with version pins but no hash verification still allows a compromised registry (or a hijacked account re-publishing over an existing version tag, on ecosystems that permit it) to serve different content for the same declared version without detection
- Check CI/build pipeline for `--ignore-scripts`/`--frozen-lockfile` equivalents — their *absence* means build-script risk (above) is unconditionally live on every CI run, not just a theoretical exposure

## Chaining Attacks

- Dependency confusion + leaked internal CI config: turns an OSINT finding (leaked registry config) directly into a concrete, exploitable dependency-confusion target list
- Postinstall-script risk + typosquat: a successful typosquat registration's payload delivery mechanism is exactly the postinstall script pattern documented above
- Maintainer-domain risk + supply-chain report: strengthens a dependency-risk finding from "theoretical" to "actively exploitable within N days if the domain lapses"

## Testing Methodology

1. Extract the full internal/private package name list from source (direct + inferred from configs/leaks)
2. Check public-registry claim status for each; generate and check typosquat candidates for the most critical ones
3. Enumerate the full resolved dependency tree for install-time scripts
4. Spot-check maintainer contact validity for the target's most business-critical dependencies
5. Confirm lockfile hash-pinning and CI script-execution controls

## Validation

1. Demonstrate the unclaimed-name gap with a registry lookup (do not publish unless explicitly authorized)
2. Show the actual misconfiguration (registry fallback config, missing lockfile hash) with concrete evidence, not just a general statement of ecosystem risk
3. For postinstall risk: identify the specific transitive package and script content that's concerning, not a blanket "many packages have postinstall scripts" statement

## False Positives

- Internal name coincidentally matches an unrelated, long-established, reputable public package (no real collision risk)
- Postinstall scripts doing benign, well-known compilation (e.g., native-module rebuilds via `node-gyp`) rather than anything network/obfuscated
- Lockfile hash-pinning present via a mechanism not initially checked (ecosystem-specific alternate integrity system)

## Impact

- Remote code execution in CI/build environments or production via a confused/typosquatted dependency
- Persistent supply-chain compromise surviving normal dependency updates (malicious code ships with every build)
- Credential/secret exfiltration from CI environment variables via a compromised install-time script

## Pro Tips

1. Always check the *transitive* tree for install-time scripts, not just direct dependencies — that's where real-world compromises land
2. A leaked CI/registry config is worth far more than it looks — it turns generic dependency-confusion risk into a specific, provable target
3. Report unclaimed typosquat/confusion-vulnerable names without publishing anything — the finding value is in the gap, not a live exploit
4. Maintainer-takeover risk-flagging is inherently probabilistic; frame it as risk exposure with evidence, not a confirmed vulnerability

## Summary

Supply-chain risk lives in trust assumptions — registry name resolution, maintainer identity, install-time code execution — that exist independent of any specific CVE. Map the gaps, prove them with registry/config evidence, and stop short of live exploitation unless the program explicitly scopes it.
