---
name: physical_access_control
description: Assessing badge, lock, and access-control system exposure across controllers, readers, credentials, and their management/network planes.
---

# Physical Facility / Access Control

Physical Access Control Systems (PACS) tie a building's doors, turnstiles, gates, and elevators to electronic credentials (RFID/NFC badges, PIN pads, mobile credentials, biometrics). The asset is identified by a credential, reader, door controller, or its management software/host. The attacker's objective in an authorized engagement is to assess whether the badge ecosystem, the locks/controllers, and the management and network planes can be made to grant access, disclose credentials, or be tampered with — ideally without ever touching the door, by reaching the IP-side of the system. Treat the door as the last mile: most of the real attack surface is a Windows host, a Linux embedded controller, and a handful of TCP services on the corporate or OT VLAN.

## Attack Surface

**Network / IP plane (primary remote surface)**
- Door/access controllers: Mercury/LenelS2, HID VertX/Edge, Software House iStar, AMAG, Axis A1001/A1601, ZKTeco, Honeywell Pro-Watch/WIN-PAK, Genetec Synergis, Avigtron/Avigilon ACM.
- Management servers and web consoles (Lenel OnGuard, Genetec Security Center, Brivo/Verkada cloud, S2 NetBox) over HTTP(S), and thick-client/RPC ports.
- Protocols: OSDP (RS-485, sometimes IP-bridged), Wiegand (reader↔controller), proprietary TCP, BACnet/Modbus where PACS rides building automation, ONVIF where cameras share the stack.
- Default management/diagnostic ports: 80/443, 8080/8443, 4070 (Mercury), 9999, 3001, 5432/1433 (backend DB), 22/23, 161 (SNMP).

**Credential / RF plane**
- 125 kHz low-frequency cards (HID Prox, EM4100, Indala) — no crypto, trivially cloned.
- 13.56 MHz: MIFARE Classic (broken Crypto1), MIFARE DESFire EV1/EV2/EV3, iCLASS legacy/SE/Seos, NTAG.
- Mobile credentials (BLE/NFC: HID Mobile Access, Apple/Google Wallet badges), facility codes, PIN pads.

**Physical/console surface (note when in scope)**
- USB/serial console on controllers, exposed RJ45 behind readers (the reader side of a door is "outside trust"), maintenance/jog buttons, REX (request-to-exit) sensors.

## Recon & Enumeration

Scope the IP plane first — it is the highest-leverage and lowest-risk surface.

```
# Discover PACS hosts/controllers on the in-scope VLAN
naabu -host 10.0.0.0/24 -p 22,23,80,161,443,1433,3001,4070,5432,8080,8443,9999 -rate 1000 -o pacs_ports.txt
nmap -sV -sC -p- --version-intensity 5 -oA pacs_nmap 10.0.20.0/24
# SNMP often left at 'public' on controllers and PoE switches feeding readers
nmap -sU -p161 --script snmp-info,snmp-sysdescr 10.0.20.0/24
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.0.20.0/24   # apt install onesixtyone

# Fingerprint web management consoles
httpx -l pacs_ports.txt -title -tech-detect -status-code -favicon -o pacs_http.txt
# Known PACS exposures, default creds, CVEs
nuclei -l pacs_http.txt -tags lenel,genetec,hid,zkteco,iot,default-login,exposure -s critical,high,medium -rl 30 -j -o pacs_nuclei.jsonl
nuclei -l pacs_http.txt -as -s critical,high -rl 30 -c 15 -bs 15 -timeout 10 -silent -o pacs_auto.txt

# Brute hidden admin/diagnostic paths on consoles
ffuf -u https://CONTROLLER/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,401,403 -ac
katana -u https://CONTROLLER -jc -d 3 -o pacs_endpoints.txt

# Backend DB / management host enumeration (often domain-joined Windows)
nxc smb 10.0.20.0/24 -u '' -p '' --shares          # netexec; apt install netexec
nxc mssql CONTROLLER -u sa -p ''                    # OnGuard/WIN-PAK SQL backends
ldapsearch -x -H ldap://DC -b "dc=corp,dc=local" "(servicePrincipalName=*OnGuard*)"
```

Credential/RF tooling (when physical RF work is in scope — name the hardware in the report):
- `proxmark3` (Proxmark3 RDV4) for LF/HF read, clone, sniff, and downgrade attacks.
- `mfoc` / `mfcuk` (apt install mfoc mfcuk) + `libnfc` for MIFARE Classic key recovery.
- `flipperzero` for field LF/HF read/emulate; Chameleon Ultra/Mini for HF emulation.
- `hid-attack`/`OSDP` tooling: `osdp-conformance`, ESPKey/`gecko`-style Wiegand implants for capture (hardware).

## Methodology

1. **Map the deployment** — Identify vendor and product from console banners, favicons, nuclei tags, SNMP sysDescr, and TLS cert CNs. Vendor dictates everything downstream (Mercury panels behave very differently from ZKTeco).
2. **Enumerate the IP services** — Web consoles, thick-client RPC, embedded SSH/Telnet, the SQL/Postgres backend, SNMP, and any BACnet/Modbus/ONVIF the same hosts speak.
3. **Attack authentication on the management plane** — Default and shipped credentials, unauthenticated APIs, weak session handling. This is where most full compromises live.
4. **Assess the controller firmware/config** — Pull firmware or config backups; look for hardcoded keys, plaintext credential databases, and door-relay command endpoints.
5. **Assess the reader↔controller link** — Wiegand has no authentication; OSDP may be in clear (Secure Channel disabled). Determine whether credentials transit in clear or replayable form.
6. **Assess the credential** — Identify card tech; for legacy/broken tech, demonstrate read→clone; for facility-code-only systems, demonstrate enumeration.
7. **Demonstrate door actuation** — If a finding lets you command an unlock or write a valid credential, prove it minimally (logs/relay state), don't fling doors open.
8. **Chain to the network** — A domain-joined OnGuard server or a flat OT VLAN turns a PACS finding into a corporate-network foothold.

## Key Weaknesses / Techniques

**Default and hardcoded credentials.** PACS ships with well-known logins that survive into production: ZKTeco `admin/admin` and `admin/123456`, S2 NetBox `admin/admin`, many HID/Honeywell web UIs with vendor defaults, SQL `sa` with blank/known passwords on OnGuard/WIN-PAK backends.
```
nxc mssql CONTROLLER -u sa -p '' --local-auth
hydra -L users.txt -P pacs_defaults.txt CONTROLLER http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
```

**Unauthenticated controller APIs / door command endpoints.** Several controllers expose door state and unlock relays without auth or with trivial auth. ZKTeco devices (CVE-2023-3938..3943) allow auth bypass and command injection; some Mercury/LenelS2 web endpoints expose `/config`, `/cgi-bin/` actions. Verify before invoking any unlock — read state only first.
```
curl -sk https://CONTROLLER/api/door/status
nuclei -u https://CONTROLLER -tags zkteco,cve -s critical,high
```

**OSDP Secure Channel disabled / Wiegand cleartext.** Wiegand carries the raw card number with zero authentication between reader and controller — a tap (ESPKey-class implant) captures and replays it. OSDP without Secure Channel (SCBK not provisioned, install mode left on) is equally sniffable. Assess whether SCBK is enforced.

**Broken credential cryptography.**
- 125 kHz Prox/EM4100: just a facility code + card number, no crypto. Read once, clone forever.
- MIFARE Classic Crypto1 is broken — recover keys offline:
```
mfoc -O dump.mfd            # nested attack, needs one known key
mfcuk -C -R 0:A -s 250 -S 250   # darkside, recovers a key from scratch
nfc-mfclassic w a clone.mfd dump.mfd   # write recovered dump to a blank
```
- iCLASS legacy uses a global shared key; HID Prox/iCLASS legacy are clonable on Proxmark3 (`hf iclass dump`, `lf hid clone`).

**Facility-code / sequential-ID enumeration.** Many sites use one facility code and sequential card numbers. A single captured badge plus a writable card lets you enumerate valid IDs (`lf hid clone -w H10301 --fc <FC> --cn <N>`), demonstrating that any employee badge can be forged from one read.

**Firmware/config disclosure.** Controller firmware and config backups frequently contain plaintext credentials, door schedules, and crypto keys.
```
binwalk -e firmware.bin           # apt install binwalk
trufflehog filesystem ./extracted --only-verified
gitleaks dir ./extracted -v
grep -rIaE 'password|SCBK|aes|secret|0x[0-9A-Fa-f]{32}' ./extracted
```

**Backend database access = master key.** The OnGuard/WIN-PAK/NetBox SQL/Postgres DB holds the credential table, cardholder PII, and door config. Read access lets you enumerate every valid badge; write access lets you provision your own.
```
sqlmap -u "https://CONSOLE/report?id=1" --batch --dbs   # if a console param is injectable
nxc mssql CONTROLLER -u sa -p 'PASS' -q "SELECT TOP 5 * FROM AccessControl.dbo.BADGE"
```

## Validation

- **Management compromise:** Authenticate with the discovered credential/bypass and read a non-public object (cardholder list count, door inventory). Screenshot/log, don't modify cardholders.
- **Door actuation:** If a finding commands a relay, prove it on a single in-scope test door and capture the controller audit log entry plus relay/sensor state, then stop. Coordinate timing with the client.
- **Credential clone:** Read a provided test badge, write it to a blank, and demonstrate the clone reads identically (`lf hid read` / `hf mf dump` before vs after) — validate against a test reader, not a live production door, unless explicitly authorized.
- **Wiegand/OSDP capture:** Show a captured frame decoding to the same facility code + card number as the source badge.
- **DB exposure:** Run a `SELECT COUNT(*)` against the credential table to prove read access without exfiltrating PII.

## False Positives

- A reachable web console that enforces unique strong credentials and rejects all defaults — exposure, not a finding.
- MIFARE DESFire EV2/EV3 and iCLASS Seos with properly provisioned diversified keys: reads return ciphertext you cannot recover; do not report as clonable.
- OSDP with Secure Channel enabled (SCBK provisioned) — sniffed traffic is encrypted; replay fails.
- "Open" relay endpoints that are actually behind a reverse proxy requiring mutual TLS or a VLAN you only reached because the engagement put you on the OT segment (note the prerequisite).
- SNMP `public` that exposes only generic interface stats with no PACS data or write community.
- A demo/test controller on the bench VLAN mistaken for production — confirm asset ownership.

## Chaining & Impact

- Default web login → controller config → SCBK/credential keys → clone any badge → physical entry to restricted areas.
- Unauthenticated door API → relay unlock → tailgate-free entry; combined with disabled-camera ONVIF on the same host, no visual record.
- SQL `sa` on OnGuard backend → provision a valid cardholder + badge for yourself → persistent authorized-looking access; same DB host is usually domain-joined → `nxc`/secretsdump → corporate AD foothold.
- MIFARE Classic key recovery → master-key reuse across all doors → site-wide cloning.
- Flat OT/PACS VLAN → BACnet/Modbus on shared controllers → HVAC/elevator influence; PACS host as a pivot into the camera (ONVIF/RTSP) and building-automation networks.

## Pro Tips

1. Start on the wire, not at the door — the management server (often a neglected, domain-joined Windows box) is usually the fastest full compromise and the safest to test.
2. Vendor-fingerprint early: favicon hash, TLS cert CN, and SNMP sysDescr identify Lenel/Genetec/ZKTeco/HID instantly and select the right CVE/default-cred set.
3. Card tech tells you the effort: LF Prox/EM and MIFARE Classic are clone-in-minutes; DESFire EV2+/Seos with diversified keys are not — don't waste cycles, report the strong ones as adequate.
4. "Read mode" first on every controller API — query door/relay state before any command; never issue an unlock without confirming the specific test door and client sign-off.
5. Wiegand is the system's soft underbelly: the reader side of any door is untrusted territory, and an inline tap defeats even an otherwise-hardened backend.
6. Check whether OSDP is running in install/learn mode — many integrators leave SCBK unprovisioned, leaving "secure" OSDP effectively cleartext.
7. The credential database is the crown jewel; read-only proof (counts, schema) is sufficient impact — avoid pulling cardholder PII.
8. Correlate every actuation test with the controller's own audit log so the client can verify your activity and you can prove the finding cleanly.
