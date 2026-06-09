---
name: container_image
description: Docker/OCI registry and image security testing - layer secret mining, CVE triage, misconfigured entrypoints, and registry abuse
---

# Docker Registry / Image

A container image is an addressable, layered filesystem (plus config/manifest JSON) served by an OCI/Docker registry. The asset identifier may be a registry endpoint (`registry.example.com`, `*.dkr.ecr.<region>.amazonaws.com`, GHCR, GCR/Artifact Registry, ACR, Harbor, Quay, a self-hosted `registry:2`) or a specific image reference (`repo/name:tag` or `@sha256:...`). The attacker objective is to pull or list images without authorization, then scan every layer for embedded secrets, exploitable CVEs in the base/runtime, and misconfigured entrypoints/run-as-root/capabilities that turn "I have the image" into credential theft, source disclosure, or remote code execution wherever that image runs. Layers are immutable and additive: a secret `rm`'d in a later layer still lives in the earlier layer's tarball.

## Attack Surface

**Registry API (v2)**
- Registry HTTP API v2 at `/v2/` (200 or 401 with `WWW-Authenticate: Bearer` confirms a registry)
- Catalog: `/v2/_catalog`, tags: `/v2/<repo>/tags/list`, manifests: `/v2/<repo>/manifests/<ref>`, blobs: `/v2/<repo>/blobs/<digest>`
- Token/auth service (Bearer realm) — anonymous pulls often allowed even when push is gated
- Common ports: 5000 (`registry:2`), 443/80 (hosted), 5001, 8080; Harbor/Quay/Nexus web UIs on 80/443/8081/8082

**Image contents (per layer)**
- Filesystem tarballs (`diff` layers), the image config JSON (env, entrypoint, cmd, user, labels), and the manifest
- Build-time `ENV`/`ARG` leaked into config, `.dockerignore` misses, `COPY . .` of the whole repo (`.git/`, `.env`, keys)
- Shell history, package caches, broken multi-stage builds that ship the builder stage

**Surrounding ecosystem**
- Dockerfiles, `docker-compose.yml`, CI workflows (`.github/workflows`, `.gitlab-ci.yml`) referencing registry creds
- `~/.docker/config.json`, `~/.dockercfg`, k8s `imagePullSecrets`, cloud registry tokens (ECR/GCR/ACR)
- Signing/attestation: cosign/Notary signatures, SBOM and provenance attestations (or their absence)

## Recon & Enumeration

Install the container toolchain (not preinstalled in the sandbox):
```
# trivy (CVE + secret + misconfig scanner)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
# syft (SBOM) + grype (vuln match)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
# skopeo (pull/inspect without a daemon), crane/regctl (registry surgery), dive (layer browser), cosign
apt-get update && apt-get install -y skopeo
GO111MODULE=on go install github.com/google/go-containerregistry/cmd/crane@latest
go install github.com/regclient/regclient/cmd/regctl@latest
curl -sSL https://github.com/wagoodman/dive/releases/latest/download/dive_linux_amd64.tar.gz | tar xz -C /usr/local/bin dive
go install github.com/sigstore/cosign/v2/cmd/cosign@latest
```

Find and fingerprint registries:
```
naabu -host registry.example.com -p 5000,5001,443,80,8080,8081,8082 -silent
httpx -l hosts.txt -path /v2/ -status-code -title -silent          # 200/401+Bearer = registry
nuclei -u https://registry.example.com -tags docker,registry,exposure -s critical,high,medium -silent
subfinder -d example.com -silent | httpx -path /v2/ -mc 200,401 -silent   # find registry.* / ghcr-style hosts
```

Enumerate repositories and tags over the v2 API (anonymous first):
```
curl -s https://registry.example.com/v2/_catalog | jq .                  # may be paginated: ?n=1000&last=<name>
curl -s https://registry.example.com/v2/<repo>/tags/list | jq .
# Hidden/undocumented repos when _catalog is disabled:
ffuf -w repos.txt -u 'https://registry.example.com/v2/FUZZ/tags/list' -mc 200 -ac
# Bearer-token flow (token scoped per-repo; anonymous scope often granted):
TOKEN=$(curl -s "https://auth.example.com/token?service=registry.example.com&scope=repository:<repo>:pull" | jq -r .token)
curl -s -H "Authorization: Bearer $TOKEN" https://registry.example.com/v2/<repo>/manifests/latest \
  -H 'Accept: application/vnd.oci.image.index.v1+json'
```

Pull/inspect without running a daemon, then scan layers:
```
skopeo inspect --config docker://registry.example.com/<repo>:<tag> | jq '{User,Entrypoint:.config.Entrypoint,Cmd:.config.Cmd,Env:.config.Env,Labels:.config.Labels}'
skopeo copy docker://registry.example.com/<repo>:<tag> oci:/tmp/img:<tag>   # offline copy of all layers
trivy image --scanners vuln,secret,misconfig --format json -o /tmp/trivy.json registry.example.com/<repo>:<tag>
syft registry.example.com/<repo>:<tag> -o cyclonedx-json=/tmp/sbom.json && grype sbom:/tmp/sbom.json -o table
```

Mine layers directly for secrets (history-aware — secrets survive in lower layers):
```
crane export registry.example.com/<repo>:<tag> - | tar -tvf -                # list flattened FS
crane config registry.example.com/<repo>:<tag> | jq .history                 # build commands, leaked ARGs
mkdir -p /tmp/layers && cd /tmp/layers
crane pull registry.example.com/<repo>:<tag> img.tar && tar xf img.tar
for l in blobs/sha256/*; do file "$l"; done                                  # extract each gzip layer tar
trufflehog docker --image registry.example.com/<repo>:<tag> --only-verified  # per-layer verified secrets
gitleaks dir /tmp/layers/rootfs                                              # after extracting layers
dive registry.example.com/<repo>:<tag>                                        # interactive layer/wasted-space view
```

## Methodology

1. **Confirm the registry and auth model.** `GET /v2/` — `200` (open) vs `401 + WWW-Authenticate: Bearer realm=...` (token-gated). Note the realm/service; test whether anonymous `pull` scope is granted.
2. **Enumerate the namespace.** Pull `/v2/_catalog` (or brute repo names via `ffuf` if disabled), then `tags/list` per repo. Build the full `repo:tag` inventory and resolve each tag to a digest.
3. **Triage entrypoints/config first.** `skopeo inspect --config` every image: record `User` (root if empty/`0`), `Entrypoint`/`Cmd`, `Env`, `ExposedPorts`, `Labels`. Cheap and high-signal before pulling gigabytes.
4. **Pull layers offline.** Use `skopeo copy` / `crane pull` to an OCI dir so you can analyze without a daemon and without re-pulling.
5. **Scan for CVEs.** `trivy image` (or `syft`→`grype`) for OS + language package CVEs; prioritize critical/high with a known exploit and reachable from the entrypoint.
6. **Mine for secrets across all layers.** `trufflehog docker --only-verified`, `trivy --scanners secret`, `gitleaks` on extracted rootfs. Inspect `history` for `ARG`/`ENV`/`RUN curl ...?token=` leaks. Hunt `.git/`, `.env`, `id_rsa`, `.aws/credentials`, `.npmrc`, `.pypirc`, `.kube/config`, `*.pem`, JWTs.
7. **Assess misconfig.** Root user, no `USER` directive, broad `ENV` secrets, mutable `:latest` pinning, missing signatures/SBOM, writable setuid binaries, embedded SSH daemons.
8. **Test write/push.** If push is reachable, validate (carefully) whether you can overwrite a tag or push to a namespace — supply-chain poisoning.
9. **Validate & PoC.** Extract one verified credential and confirm it authenticates; or show one exploitable CVE reachable from the entrypoint; or demonstrate a tag overwrite in a sandbox repo.

## Key Weaknesses / Techniques

### Anonymous / over-permissive registry access
Open `/v2/_catalog` or anonymous `pull` scope exposes every internal image. Self-hosted `registry:2` frequently runs with no auth on :5000.
```
curl -s http://registry.example.com:5000/v2/_catalog | jq '.repositories[]'
nuclei -u http://registry.example.com:5000 -tags registry,exposure -silent     # exposed-registry templates
```

### Secrets baked into layers (the core of this asset)
Build secrets `ENV`/`ARG`, `COPY . .` of repo roots, and "deleted-but-not-really" files in lower layers.
```
trufflehog docker --image <repo>:<tag> --only-verified --json | jq -r 'select(.Verified)|.DetectorName'
crane config <repo>:<tag> | jq -r '.history[].created_by' | grep -iE 'ARG|ENV|token|key|password|aws|curl .*http'
# pull a single secret-bearing layer and grep:
grep -rIaoE '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)' /tmp/layers/rootfs
```

### Exploitable CVEs in base image / runtime
Stale base images (old `openssl`, `glibc`, `log4j`, `bash`/Shellshock, vulnerable interpreters) reachable from the entrypoint.
```
trivy image --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed <repo>:<tag>
grype <repo>:<tag> --only-fixed -o json | jq '.matches[] | select(.vulnerability.severity=="Critical") | {id:.vulnerability.id, pkg:.artifact.name}'
```
Cross-reference the CVE'd package against `Entrypoint`/`Cmd` — a vulnerable library only matters if the running code calls it.

### Misconfigured entrypoint / runs as root
No `USER` directive (defaults to UID 0), entrypoint shell scripts that `eval` env vars, secrets passed as args visible in `/proc/*/cmdline`.
```
skopeo inspect --config <repo>:<tag> | jq '{User:.config.User, Entrypoint:.config.Entrypoint, Cmd:.config.Cmd}'
# Empty/"0"/"root" User + privileged runtime = container-escape blast radius (see kubernetes skill)
crane export <repo>:<tag> - | tar -tv | grep -E 'rws|setuid'    # ship-with-setuid binaries
```

### Source / IP disclosure
Multi-stage builds that ship the builder stage, `.git/` directories, unminified source, internal hostnames, private package indexes in `.npmrc`/`.pip.conf`.
```
crane export <repo>:<tag> - | tar -tv | grep -E '\.git/|\.env$|\.npmrc|\.pypirc|\.kube/config|credentials$'
semgrep --config auto /tmp/layers/rootfs/app    # source shipped in image
```

### Unsigned / unverifiable images & push abuse
No cosign/Notary signature and no provenance attestation means a poisoned image is indistinguishable from a legit one. If push is reachable, a tag can be overwritten.
```
cosign verify <repo>:<tag>                       # error => unsigned/unverifiable
cosign download sbom <repo>:<tag>                # absent SBOM/attestation
# Validate push reachability against a benign throwaway repo only:
crane push /tmp/benign.tar registry.example.com/<your-test-namespace>/canary:poc
```

### Manifest/index quirks
Multi-arch indexes can hide an extra platform manifest; `:latest` is mutable; digests are not. Always resolve `tag -> @sha256` and test whether overwriting a tag changes what consumers pull.

## Validation

1. **Secret:** extract one credential and prove it authenticates — `aws sts get-caller-identity` for an AWS key, `GET /user` with a `ghp_*`/`gho_*` token, `jwt_tool <token> -V` then a single authenticated request. Use `--only-verified` to avoid reporting dead strings.
2. **CVE:** show the vulnerable package + version from `trivy`/`grype`, and that it is invoked by the entrypoint (reachable), not merely present. A fixed-version-available, reachable critical is a real finding.
3. **Misconfig:** show `User` is empty/`0` from the actual config JSON, or that an entrypoint passes a secret on the command line / `eval`s untrusted env.
4. **Access:** for anonymous-registry findings, show the full `_catalog` listing or a successful pull of an image you should not be able to read. For push, show a digest you wrote to a sandbox repo.
5. **Reproducibility:** record the exact `repo@sha256:` digest so the finding is pinned and re-verifiable.

## False Positives

- Unverified secret regex hits (test/example keys, placeholders like `AKIAIOSFODNN7EXAMPLE`, dummy JWTs). Confirm with `--only-verified` or live auth before reporting.
- CVEs in packages that are present but never invoked by the entrypoint, or `--ignore-unfixed` items with no patch — note as informational, not exploitable.
- `401`/`403` on `/v2/_catalog` or manifests means auth is working; an open `/v2/` root that still gates pulls is not a breach.
- Public base-image layers (Debian/Alpine official) flagged for shared CVEs that the vendor tracks — deduplicate against the app's own layers.
- `:latest` mutable tag in a registry that enforces immutable tags / digest-pinned deploys.
- "Secrets" that are public config (e.g., publishable API keys, Sentry DSNs) intended to be client-visible.

## Chaining & Impact

- Anonymous `_catalog` -> pull internal image -> mine layers -> verified cloud key -> `aws sts`/`gcloud` -> control-plane access (pivot to cloud and kubernetes skills).
- Registry creds in a layer (`~/.docker/config.json`, `imagePullSecrets`) -> push access -> overwrite `:latest` of a deployed image -> RCE on every node that pulls it (supply-chain).
- Source/`.git` disclosure -> hardcoded DB/admin creds -> direct data access; or internal hostnames -> expanded SSRF/internal-network targeting.
- Reachable critical CVE + root entrypoint + privileged k8s runtime -> in-container RCE -> container escape -> node/cluster compromise.
- Unsigned images + push -> seed a backdoored image that passes review because nothing verifies provenance.

## Pro Tips

1. Always `skopeo inspect --config` before pulling — entrypoint/User/Env triage is free and tells you where to dig.
2. Secrets hide in *lower* layers even after deletion; scan per-layer (`trufflehog docker`) rather than only the flattened rootfs.
3. `crane config | jq .history` reverse-engineers the Dockerfile — `RUN curl ...?token=`, `ARG SECRET`, and broken multi-stage builds show up here.
4. Resolve tags to digests immediately; `:latest` lies, `@sha256:` does not. Report findings against digests.
5. `--only-verified` (trufflehog) and live auth checks are the difference between a credible report and noise.
6. When `_catalog` is disabled, brute repo names with `ffuf` against `/v2/FUZZ/tags/list`; org/product/service wordlists from subdomains and JS often hit.
7. Cross-check every CVE against the entrypoint's reachable code path before calling it exploitable.
8. ECR/GCR/ACR are just OCI registries — once you have the cloud token (`aws ecr get-login-password`, `gcloud auth print-access-token`, `az acr login`), the same `crane`/`skopeo`/`trivy` flow applies.
9. Test push against a throwaway namespace only; never overwrite a production tag during assessment — prove the capability, not the damage.

## Summary

A container image is a transparent, immutable archive: assume every secret ever copied in is still recoverable from some layer, every stale package is a CVE, and an empty `USER` plus a careless entrypoint is RCE waiting for the right runtime. Enumerate the registry anonymously, triage configs before pulling, mine all layers for verified secrets, match CVEs to reachable entrypoints, and pin every finding to a digest.
