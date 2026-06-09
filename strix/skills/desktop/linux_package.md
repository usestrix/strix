---
name: linux_package
description: Assessing Linux binaries and packages for malicious/insecure install scripts, unsafe binaries, and bundled dependency CVEs
---

# Linux Binary / Package

A distributable Linux artifact: a `.deb`/`.rpm`/`.apk` package, a tarball/AppImage/Snap/Flatpak bundle, or a standalone ELF binary. The attacker objective is to find code that runs with elevated privilege during install/upgrade/remove, ELF binaries shipped with exploitable memory-safety or logic flaws, hardcoded secrets, world-writable or setuid drops, and vulnerable third-party libraries vendored or declared as dependencies. Packages are trusted by root at install time and frequently by services at runtime, so a single unsafe maintainer script or a bundled CVE becomes local privilege escalation, supply-chain compromise, or RCE.

## Attack Surface

**Package metadata & scripts**
- Maintainer scripts run as root: deb `preinst`/`postinst`/`prerm`/`postrm`, rpm `%pre`/`%post`/`%preun`/`%postun`/`%posttrans`/`%trigger*`, apk `.pre-install`/`.post-install`
- Declared dependencies and pinned versions (CVE-bearing transitive deps)
- File manifest: install paths, ownership, and permission bits (setuid/setgid, world-writable, dirs under `$PATH`)
- Signing/trust: GPG signature presence, repo `Release`/`repomd.xml` integrity

**Shipped binaries**
- ELF executables and shared objects: hardening flags, RPATH/RUNPATH, symbol exports
- setuid/setgid binaries and capabilities (`getcap`) installed by the package
- systemd units, init scripts, cron entries, polkit policies, sudoers drop-ins, udev rules the package installs

**Bundled / vendored code**
- Statically linked or vendored libraries (often outdated)
- Interpreted payloads inside the package (python/perl/node/shell helpers)
- Embedded archives, firmware blobs, and config with credentials

## Recon & Enumeration

Install asset-specific tooling not present in the Kali base:

```bash
# SBOM + vuln scanning
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
apt-get install -y trivy 2>/dev/null || \
  curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
# Firmware/blob carving, RPM handling, hardening checks
apt-get install -y binwalk rpm2cpio cpio checksec yara radare2
pip install -q capa-explorer 2>/dev/null || true   # optional: capability matching for ELF
```

Unpack without executing anything:

```bash
file ./artifact.*                                   # confirm type before touching it
# .deb: extract data + control without running scripts
dpkg-deb -R package.deb /tmp/pkg                     # -R keeps control/ scripts intact for review
ar t package.deb && ar x package.deb                 # raw members: control.tar.*, data.tar.*
# .rpm: convert to cpio, never rpm -i in a host you care about
rpm2cpio package.rpm | cpio -idmv -D /tmp/rpm
rpm -qp --scripts package.rpm                        # dump %pre/%post without installing
rpm -qp --requires package.rpm                       # declared deps
# AppImage / self-extracting
./app.AppImage --appimage-extract                    # -> squashfs-root/
unsquashfs -d /tmp/snap snap.snap                    # snaps are squashfs
# tarball
tar tzvf bundle.tar.gz                               # list perms/owners before extracting
```

SBOM and dependency-CVE pass over the unpacked tree or the artifact directly:

```bash
syft package.deb -o cyclonedx-json=sbom.json -o table
grype sbom:sbom.json --fail-on high                  # CVE match against the SBOM
trivy fs --scanners vuln,secret,misconfig /tmp/pkg   # also catches embedded secrets/IaC
trivy rootfs squashfs-root/                           # for AppImage/Snap roots
```

Static review of scripts, binaries, and secrets:

```bash
semgrep --config p/bash --config p/command-injection /tmp/pkg          # maintainer-script flaws
trufflehog filesystem /tmp/pkg --only-verified                          # live credentials
gitleaks dir /tmp/pkg -v                                                # broader secret patterns
grep -rEn 'curl .*\| *(sudo )?(ba)?sh|wget .*-O- *\| *sh|eval \$' /tmp/pkg/control* /tmp/pkg/DEBIAN 2>/dev/null
```

ELF triage on each shipped binary:

```bash
checksec --file=/tmp/pkg/usr/bin/svc                 # RELRO/NX/PIE/Canary/RPATH/Fortify
readelf -d /tmp/pkg/usr/bin/svc | grep -E 'RPATH|RUNPATH'   # writable-dir hijack candidates
objdump -d /tmp/pkg/usr/bin/svc | grep -E 'system|popen|execve|strcpy|sprintf|gets'
strings -n8 /tmp/pkg/usr/bin/svc | grep -Ei 'password|secret|token|api[_-]?key|http://'
nm -D /tmp/pkg/usr/lib/*.so 2>/dev/null              # exported symbols / version pinning
find /tmp/pkg -perm -4000 -o -perm -2000 -o -perm -0002 2>/dev/null    # setuid/setgid/world-writable
getcap -r /tmp/pkg 2>/dev/null                       # file capabilities
r2 -A -q -c 'afl;/c system' /tmp/pkg/usr/bin/svc     # quick call-graph + xrefs to system()
```

If the package self-updates or fetches at install/runtime, capture egress:

```bash
interactsh-client -v        # seed an OAST host into any URL the scripts/binary contact
```

## Methodology

1. **Identify and freeze.** `file` the artifact, record sha256, and unpack with extract-only tooling (`dpkg-deb -R`, `rpm2cpio | cpio`, `--appimage-extract`, `unsquashfs`). Never run `dpkg -i`/`rpm -i`/the AppImage on a trusted host — do all execution in the disposable sandbox.
2. **Read maintainer scripts as root code.** Dump every install/upgrade/remove hook. Trace each external command, every variable expanded into a shell command, every path written, and any network fetch piped to a shell.
3. **Audit the file manifest.** Map install paths, owners, and mode bits. Flag setuid/setgid binaries, world-writable files/dirs, files dropped into `$PATH` or `/etc/{cron.d,sudoers.d,profile.d}`, and units/timers that run as root.
4. **Generate an SBOM and match CVEs.** `syft` → `grype`/`trivy` over the package and unpacked root. Separate truly-reachable bundled libs from inert duplicates.
5. **Triage shipped ELF binaries.** Hardening flags, RPATH/RUNPATH, dangerous imports, embedded secrets, and reachable `system`/`exec` sinks via radare2.
6. **Hunt secrets and trust gaps.** trufflehog/gitleaks/trivy over the tree; check signature presence and repo metadata integrity.
7. **Model install + runtime contexts.** Decide whether each finding triggers at install (root), upgrade, or service runtime, and under whose UID.
8. **Validate with a minimal PoC** in the sandbox; confirm UID, the exact trigger, and reproducibility. Stop at proof of access.

## Key Weaknesses / Techniques

**Command injection / unsafe shell in maintainer scripts (root-context).** Scripts that interpolate package-controlled or environment values into shell, or `eval` attacker-influenced data:
```bash
# vulnerable postinst pattern (runs as root at install)
NAME=$(cat /etc/myapp/instance)        # attacker-writable file
useradd "$svc_$NAME"                    # unquoted, expandable -> injection on upgrade
```
Assess by reviewing every expansion and testing in the sandbox with a crafted input file/env var. Also flag `curl ... | sh` install-time fetches (network attacker controls the payload).

**Insecure file/dir permissions dropped by the package.** World-writable files under root-run paths, writable directories on a daemon's `$PATH`, or writable systemd unit/`ExecStart` targets allow a local user to replace content executed as root:
```bash
find /tmp/pkg -perm -0002 -type f                    # world-writable files
awk -F= '/ExecStart/{print $2}' /tmp/pkg/**/*.service # then check perms of that binary/dir
```

**setuid/setgid binaries and unsafe capabilities.** Any setuid-root binary the package installs is a LPE candidate; check it for argv/env trust, `system()`/`popen()`, relative-path `execvp`, and `LD_PRELOAD`/`PATH` reliance. `cap_setuid`, `cap_dac_override`, `cap_sys_admin` on a binary are equivalent escalations.

**Writable RPATH/RUNPATH → library hijack.** If `readelf -d` shows an RPATH/RUNPATH pointing to a writable or `$ORIGIN`-relative dir, a local attacker plants a malicious `.so` loaded by a privileged process.

**Bundled dependency CVEs.** Vendored/static libs with known CVEs (e.g. an old `libssl`, `libxml2`, `zlib`, `log4j`-style helper, or a pinned-vulnerable npm/pip module). `grype`/`trivy` flag the version; confirm the affected code path is actually reached, not just present.

**Hardcoded secrets & default credentials.** API keys, private keys, DB passwords, or signing keys baked into binaries/config:
```bash
trufflehog filesystem /tmp/pkg --only-verified
strings -n8 /tmp/pkg/usr/bin/* | grep -Ei 'BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|aws_secret|xox[bp]-'
```

**Memory-safety bugs in shipped C/C++ binaries.** No-canary/no-PIE binaries using `strcpy`/`sprintf`/`gets`/format strings reachable from package-parsed input. Disassemble around the sink, then fuzz/PoC in the sandbox.

**Unsigned packages / weak repo trust.** Missing or unverifiable GPG signature, or a repo served over plain HTTP, enables on-path package substitution. Verify with `dpkg-sig --verify` / `rpm -K` against an expected key.

## Validation

1. Reproduce the trigger in the disposable sandbox only. For maintainer scripts, install with `dpkg -i` / `rpm -i` (or invoke the script directly) under controlled input and capture the effect with a benign marker — e.g. write a timestamped file to `/root/poc-$(id -u)` to prove root-context execution; do not run destructive payloads.
2. Confirm the UID/context: run `id` from inside the injected path, or record the owner/mode of the artifact the bug let you create.
3. For permission/RPATH/setuid issues, demonstrate the actual hijack: drop a benign `.so`/binary in the writable location and show the privileged process loads/executes it (e.g. it creates your marker file as root).
4. For bundled CVEs, tie the version `grype`/`trivy` reports to a concrete reachable call path (function present + invoked), not mere presence on disk.
5. Capture exact reproduction steps, the controlling input, and a sha256 of the artifact tested.

## False Positives

- CVEs in libraries that are vendored but never linked/loaded, or in code paths the binary never reaches (presence ≠ reachability).
- `grype`/`trivy` matches on a distro-backported package whose fix the vendor patched without bumping the upstream version string — check the distro changelog.
- "World-writable" hits on files inside the extracted staging tree whose real installed mode is corrected by the maintainer script — verify post-install mode, not the archive mode.
- Secrets that are public test fixtures, example placeholders, or already-revoked keys (`trufflehog --only-verified` reduces these).
- setuid bits on the extracted tree that the packaging tool normalizes; confirm the bit survives a real install.
- A `curl | sh` that pins a sha256 / fetches over HTTPS from a vendor-controlled host with signature verification is materially weaker as a finding.

## Chaining & Impact

- Unsafe maintainer script → arbitrary code as root at install/upgrade → **local privilege escalation / full host compromise**.
- Writable RPATH or world-writable `ExecStart` target → library/binary hijack of a root service → **LPE**.
- setuid binary with `system()`/`PATH` trust → **root shell** for any local user.
- Bundled CVE in a network-facing daemon shipped by the package → **remote code execution** at the service's privilege.
- Compromised/unsigned repo or `curl | sh` over HTTP → **supply-chain RCE** across every host that installs/updates.
- Hardcoded cloud/API keys → pivot off-host: cloud control-plane access, registry pushes, or lateral movement into CI/CD.

## Pro Tips

1. Never install untrusted packages on the analysis host. Convert deb/rpm to plain files (`dpkg-deb -R`, `rpm2cpio | cpio`) and read scripts before any execution; reserve real installs for a throwaway container.
2. Maintainer scripts run as **root** and on *upgrade* and *removal*, not just first install — review `prerm`/`postrm`/`%preun` too; removal-time bugs are commonly missed.
3. Diff two package versions (`dpkg-deb -R` both, `diff -r`) to spot newly introduced scripts, permission changes, or silently added network fetches — fast way to catch a backdoored update.
4. `grype`/`trivy` give you the candidate CVE; confirm reachability with `nm -D`/`objdump`/radare2 before reporting, or it is noise.
5. AppImages and Snaps bundle an entire userland — run `trivy rootfs` on the extracted root; the real CVE surface is the vendored libs, not the launcher.
6. `$ORIGIN` in RUNPATH plus a writable install dir is a quiet LPE; checksec/readelf surface it in one line.
7. Seed an `interactsh-client` host into any install-time URL to catch silent telemetry or update fetches that widen the trust boundary.
8. Prove impact with a harmless marker (timestamped file owned by root) and stop — never run destructive proof payloads, even in the sandbox.
