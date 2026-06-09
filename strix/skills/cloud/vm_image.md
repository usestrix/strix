---
name: vm_image
description: Offline analysis of container and VM images for leaked secrets, CVEs, and misconfigurations by mounting and scanning the filesystem and layer history.
---

# Container / VM Image Assessment

A container image (Docker/OCI tarball, registry reference, or saved layers) or a VM disk image (QCOW2, VMDK, VDI, AMI/raw, OVA) is a frozen, shippable filesystem plus metadata. Unlike a live host, every artifact is inert and fully inspectable offline: build history, environment variables, package versions, embedded credentials, and dead-but-recoverable layers are all on disk. The attacker's objective is to recover anything that grants access elsewhere — long-lived cloud keys, private keys, hardcoded passwords, tokens baked into early layers and "deleted" later, plus exploitable CVEs and runtime misconfigurations (root user, setuid binaries, world-writable paths) that enable escape or escalation once the image runs. Treat the image as a credential and CVE dump first, a runtime target second.

## Attack Surface

**Image formats and entry points**
- Container images: `image.tar` (`docker save`), OCI layout dirs, registry refs (`registry.tld/ns/app:tag`), individual `layer.tar` blobs
- VM disk images: `.qcow2`, `.vmdk`, `.vdi`, `.vhd/.vhdx`, raw `.img`, `.ova`/`.ovf` bundles, cloud AMI snapshots
- Build metadata: image config JSON (`Config.Env`, `Config.Cmd`, `Config.Entrypoint`, `History`), `manifest.json`, `repositories`
- Registry exposure: anonymous-pullable private registries, `/v2/_catalog`, unauthenticated registry API on :5000

**What is exposed once you have the artifact**
- Every file in every layer, including files removed in later layers (whiteout files do not delete data)
- Per-layer build commands (often contain inlined secrets: `RUN export AWS_SECRET=...`)
- Environment variables and entrypoint scripts that fetch or hold credentials at runtime
- Installed OS and language packages with exact versions → direct CVE mapping
- SSH host/user keys, cloud config (`/root/.aws`, `/home/*/.config/gcloud`), kube configs, `.npmrc`, `.git-credentials`
- VM images additionally expose shell history, cron, systemd units, `/etc/shadow`, and persistent data partitions

## Recon & Enumeration

Install the core image-analysis stack (Kali/Ubuntu sandbox). Trivy, syft, grype, gitleaks, and trufflehog are the workhorses:

```
# Trivy (CVEs + secrets + misconfig in one tool)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
# Syft (SBOM) + Grype (vuln match against SBOM)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
# Secret scanners
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
# gitleaks (Git history of layers / .git dirs left in images)
GLV=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name); \
curl -sL "https://github.com/gitleaks/gitleaks/releases/download/${GLV}/gitleaks_${GLV#v}_linux_x64.tar.gz" | tar xz -C /usr/local/bin gitleaks
# dive (interactive layer/efficiency inspection), skopeo (registry copy), dockle (CIS-ish image lint)
apt-get update && apt-get install -y skopeo libguestfs-tools binwalk
# VM/disk forensics
apt-get install -y qemu-utils libguestfs-tools sleuthkit
```

Acquire the artifact without running it:

```
# Pull a registry image to a tarball WITHOUT a daemon (no execution)
skopeo copy docker://registry.tld/ns/app:tag oci:./app-oci:tag
skopeo inspect --config docker://registry.tld/ns/app:tag       # config/env/history, no pull of layers
# Enumerate an exposed/private registry
curl -s http://registry.tld:5000/v2/_catalog | jq .
curl -s http://registry.tld:5000/v2/ns/app/tags/list | jq .
nuclei -u http://registry.tld:5000 -tags docker,registry,exposure -silent
```

First-pass scans (run all three; they overlap but each catches what the others miss):

```
trivy image --input app.tar --scanners vuln,secret,misconfig --severity CRITICAL,HIGH,MEDIUM -f json -o trivy.json
syft app.tar -o cyclonedx-json=sbom.json -o table          # full package inventory
grype sbom:sbom.json -o table --fail-on high                # CVE match from the SBOM
trufflehog docker --image file://app.tar --results=verified  # verified = live-checked credentials
```

## Methodology

1. **Acquire inertly.** Get the tarball/disk via `skopeo copy`, `docker save`, or file transfer. Never `docker run` an untrusted image to inspect it — extract and read it on disk.
2. **Read the metadata before the bytes.** Dump the config and per-layer history; inlined build secrets and entrypoint logic are visible without unpacking:
   ```
   tar -xf app.tar -C ./unpacked && jq . ./unpacked/manifest.json
   skopeo inspect --config oci:./app-oci:tag | jq '.config.Env, .history[].created_by'
   ```
3. **Explode every layer, including deleted content.** Each `layer.tar` is a diff; whiteouts (`.wh.*`) hide but do not remove earlier data. Extract layers individually to recover "deleted" secrets:
   ```
   for L in $(jq -r '.[0].Layers[]' ./unpacked/manifest.json); do
     mkdir -p "./layers/$(dirname $L)"; tar -xf "./unpacked/$L" -C "./layers/$(dirname $L)" 2>/dev/null; done
   dive app.tar    # walk layers, spot the layer where a secret was added then "removed"
   ```
4. **CVE + SBOM pass.** `syft` → `grype` and `trivy` for OS and language deps. Prioritize CRITICAL/HIGH with a known exploit and a reachable runtime.
5. **Secret sweep across the flattened tree and per-layer.** Run trufflehog (verified) + gitleaks + trivy secret over the unpacked filesystem, then again per layer to catch credentials that exist only in an intermediate layer.
6. **Runtime config audit.** Inspect user, capabilities, setuid/setgid binaries, world-writable files, and entrypoint scripts.
7. **For VM disks:** mount read-only and repeat steps 4–6 against the real root filesystem, plus shell history, cron, and `/etc/shadow`.
8. **Validate, chain, report.** Verify each credential against its provider with read-only calls; map CVEs to a runnable PoC.

## Key Weaknesses / Techniques

**Secrets in layers and history (highest yield).** Credentials added in an early `RUN`/`COPY` and removed in a later layer remain fully recoverable. Always scan per-layer, not just the flattened image:

```
trufflehog docker --image file://app.tar --results=verified --json
gitleaks dir ./layers --no-banner -f json -r gitleaks.json    # also catches embedded .git dirs
grep -rIaE 'AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|xox[baprs]-|-----BEGIN [A-Z ]*PRIVATE KEY-----' ./layers
trivy image --input app.tar --scanners secret -f json | jq '.Results[].Secrets'
```

**Secrets in environment and entrypoint.** `Config.Env` and entrypoint scripts frequently carry DB URLs, API keys, and `*_TOKEN` values:

```
skopeo inspect --config oci:./app-oci:tag | jq -r '.config.Env[]' | grep -iE 'key|secret|token|pass|cred|url='
jq -r '.history[].created_by' ./unpacked/*.json | grep -iE 'export|ARG|--password|token'
```

**Exploitable CVEs in base image / packages.** Outdated base images (`debian:10`, EOL `node:14`) and pinned-but-old libs map directly to CVEs. Confirm the vulnerable component is actually invoked at runtime before claiming impact:

```
grype app.tar -o json | jq '.matches[] | select(.vulnerability.severity=="Critical") | {pkg:.artifact.name, ver:.artifact.version, id:.vulnerability.id}'
```

**Runtime misconfiguration → escape/escalation.**
- Runs as root (`Config.User` empty or `0`): combined with a privileged/`--cap-add` runtime this is a direct escape vector.
- Unexpected setuid/setgid binaries in the image expand the post-exploitation surface.
- World-writable files in `$PATH` or writable entrypoints allow tampering before execution.

```
skopeo inspect --config oci:./app-oci:tag | jq '.config.User'      # empty/"0"/"root" == runs as root
find ./layers -perm -4000 -o -perm -2000 2>/dev/null               # setuid/setgid
find ./layers -xdev \( -perm -0002 \) -type f 2>/dev/null | grep -E 'bin/|/etc/'
dockle --input app.tar                                              # CIS-style image findings
```

**VM disk: mount read-only and harvest.** libguestfs mounts without booting the guest; never attach an untrusted disk to a running kernel via loopback without `ro`:

```
qemu-img info disk.qcow2                                            # format, virtual size, backing chain
guestfish --ro -a disk.qcow2 -i                                    # interactive: cat, find, download
# or non-interactive recursive secret scan:
guestmount --ro -a disk.qcow2 -i /mnt/img && \
  trufflehog filesystem /mnt/img --results=verified && \
  trivy fs /mnt/img --scanners vuln,secret,misconfig
# high-value paths once mounted:
cat /mnt/img/etc/shadow; ls -la /mnt/img/root/.ssh /mnt/img/root/.aws /mnt/img/home/*/.config/gcloud
grep -rIa . /mnt/img/root/.bash_history /mnt/img/home/*/.*_history 2>/dev/null
binwalk -e /mnt/img/path/to/firmware.bin                            # embedded blobs in appliance images
```

## Validation

1. **Secrets:** prove the credential is live and what it unlocks, with read-only provider calls. Do not mutate.
   ```
   AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity   # confirms valid + identity/scope
   curl -s -H "Authorization: token ghp_..." https://api.github.com/user            # confirms PAT + account/scopes
   ```
   `trufflehog --results=verified` already performs this liveness check; record which layer/file the secret came from.
2. **CVEs:** match the installed version to the advisory's affected range AND confirm the vulnerable code path is reachable (binary present, service started by entrypoint/systemd). Run a non-destructive PoC against an instance of the image where authorized.
3. **Misconfig:** demonstrate the concrete consequence — e.g., start the image in the authorized lab and show `whoami` returns `root`, or that a world-writable entrypoint can be overwritten pre-exec.
4. Capture the exact artifact digest (`sha256:...`) and layer index so the finding is reproducible against that specific image.

## False Positives

- **Example/placeholder secrets:** `AKIAIOSFODNN7EXAMPLE`, `changeme`, `password123`, docs/test fixtures. Verify liveness — unverified hits from gitleaks/trufflehog regex are candidates, not findings.
- **CVEs in uninstalled or unreachable packages:** a vulnerable lib present in the SBOM but never loaded, or in a build-stage layer dropped from the final multi-stage image. Check the final layer set, not intermediate builders.
- **Distroless/scratch noise:** version detectors misfire; confirm the package actually exists in the final image.
- **Already-rotated credentials:** a secret recovered from an old layer that the provider now rejects — note it, but it is not exploitable.
- **VM "deleted" files that are genuinely zeroed:** trimmed/zeroed sectors yield no recoverable data; do not report carved garbage.
- **setuid binaries that are expected** (e.g., `sudo`, `ping`) — only unexpected or vulnerable-version setuid binaries matter.

## Chaining & Impact

- Leaked AWS/GCP/Azure key in a layer → `sts get-caller-identity` → enumerate IAM/storage → read other secrets → cloud account pivot.
- Private SSH key + known host in `/root/.ssh` → direct access to production hosts the image was built to deploy.
- Registry/CI token in `Config.Env` → push a backdoored image to the same registry → supply-chain compromise of every consumer.
- Old base-image CVE (e.g., libc/openssl RCE) + image runs as root + privileged runtime → container escape to node → (with cluster creds also found in the image) cluster compromise. See the kubernetes skill for the post-escape path.
- `.git` directory or `.npmrc`/`.pypirc` left in the image → source code disclosure or package-registry credential → further secret and dependency-confusion attacks.

## Pro Tips

1. The highest-value secrets are almost always in *intermediate* layers, not the flattened image. `dive` plus per-layer extraction beats scanning only the final filesystem.
2. Run trufflehog with `--results=verified` first — it live-checks credentials, so you triage real findings instead of regex noise.
3. `skopeo inspect --config` reads env, history, and entrypoint over the network without pulling gigabytes of layers — use it to triage many images fast.
4. Multi-stage builds drop builder layers from the final image, but if the registry kept builder tags, pull those separately; that is where build secrets survive.
5. For VM disks, always `--ro` / `guestfish --ro`; libguestfs runs the guest filesystem in isolation so you never boot untrusted code.
6. Mismatched `Config.User` (empty) plus an entrypoint that `chmod`s or writes to `$PATH` is a tell for a tamperable runtime — confirm before the app starts.
7. Cross-reference grype CVE output with the entrypoint: a CRITICAL in a package the entrypoint never invokes is lower priority than a HIGH in the running service.
8. Shell history (`.bash_history`, `.zsh_history`) in VM images frequently contains plaintext passwords and one-liners with embedded tokens — grep it early.
9. Keep the artifact digest in every note; "the image" is ambiguous once tags get repushed.
