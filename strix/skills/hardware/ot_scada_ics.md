---
name: ot_scada_ics
description: Authorized assessment of OT/SCADA/ICS networks — safe protocol fingerprinting, PLC/HMI/historian enumeration, and impact analysis without disrupting live process.
---

# OT / SCADA / ICS

Operational Technology networks run physical processes: PLCs (Programmable Logic Controllers), RTUs, HMIs, SCADA masters, historians, and engineering workstations speaking purpose-built protocols (Modbus, S7comm, EtherNet/IP, DNP3, BACnet, OPC UA, EtherCAT, IEC 60870-5-104, IEC 61850/MMS). Most were designed without authentication or encryption and assume a trusted physical perimeter. The attacker objective is to reach the control plane — read/write coils, registers, and ladder logic; manipulate setpoints; or pivot from IT to OT through dual-homed engineering hosts. The dominant risk here is not data theft but **physical harm and process disruption**, so every action must be read-only and rate-limited until impact is explicitly authorized. Treat unsolicited writes, function-code fuzzing, and stop/run commands as out of scope unless a signed test window says otherwise.

## Attack Surface

**Field/control devices**
- PLCs/RTUs: Modbus/TCP 502, S7comm 102, EtherNet/IP 44818 + 2222, DNP3 20000, BACnet/IP 47808 (0xBAC0), IEC-104 2404, OPC UA 4840/4843, FINS 9600, Niagara Fox 1911/4911, ProConOS 20547
- HMIs / SCADA masters: web panels (80/443/8080), VNC 5900, RDP 3389, embedded historians
- Historians: OSIsoft PI 5450, Wonderware, GE Proficy; SQL backends (1433/1521/3306)
- Engineering workstations (EWS): TIA Portal, RSLogix/Studio 5000, Unity Pro, CODESYS — dual-homed IT/OT bridges

**Management / IT bridge**
- Industrial switches/firewalls (Hirschmann, Moxa, Stratix) with telnet/SNMP/web
- Data diodes, OPC/Modbus gateways, protocol converters
- VPN/jump hosts and remote-access appliances into the OT DMZ (Purdue Level 3.5)
- Cellular/RTU radios, serial-to-IP terminal servers (Lantronix, Moxa NPort) on 4001+

**Exposure paths**
- Internet-facing PLCs/HMIs (Shodan/Censys-style discovery)
- Flat networks with no Purdue segmentation; VLAN hopping into Level 2
- Default/hardcoded credentials, unauthenticated firmware/config download

## Recon & Enumeration

Install the OT-specific tooling not already in the sandbox:

```bash
pip install pymodbus pycomm3 cpppo                 # Modbus, EtherNet/IP clients
pip install python-snap7                           # S7comm (needs libsnap7)
pip install opcua bacpypes scapy                   # OPC UA, BACnet, raw packet crafting
git clone https://github.com/digitalbond/Redpoint  # ICS-focused nmap NSE scripts
nmap --script-updatedb                             # after copying Redpoint .nse to scripts/
```

**Passive first.** OT recon is fragile; prefer listening to scanning where you have a SPAN/tap:

```bash
tcpdump -ni eth0 -w ot.pcap 'tcp port 502 or tcp port 102 or udp port 47808 or tcp port 44818'
# Then identify protocols offline; do NOT replay captured writes.
```

**Discovery (slow, single-threaded, no aggressive timing):**

```bash
naabu -host 10.20.0.0/24 -p 102,502,2222,4840,20000,44818,47808,2404,1911,9600 -rate 100 -o ot_ports.txt
nmap -sT -Pn -n --max-rate 50 --scan-delay 100ms -p 102,502,4840,20000,44818,2404 -iL targets.txt -oA ot_tcp
```

**Safe protocol fingerprinting** (read-only identity/device-info queries only):

```bash
# Modbus device identification (FC 43/14) and unit-id sweep — read, never write
nmap -sT -Pn -p502 --script modbus-discover --script-args='modbus-discover.aggressive=false' <ip>
# S7comm CPU identity (SZL read, no STOP/RUN)
nmap -sT -Pn -p102 --script s7-info <ip>
# EtherNet/IP / CIP identity object
nmap -sT -Pn -p44818 --script enip-info <ip>
# BACnet device object + vendor
nmap -sU -Pn -p47808 --script bacnet-info <ip>
# Redpoint: DNP3, ProConOS, Niagara Fox, CODESYS, Omron FINS
nmap -sT -Pn -p20000 --script dnp3-info <ip>
nmap -sT -Pn -p1911,4911 --script fox-info <ip>
```

**HMI / web layer** (treat like any web app, but gently):

```bash
httpx -l ot_web.txt -title -tech-detect -status-code -sc -o ot_http.txt
nuclei -l ot_web.txt -tags iot,scada,default-login -s critical,high -rl 20 -c 5 -timeout 15 -retries 1 -j -o ot_nuclei.jsonl
nuclei -l ot_web.txt -t http/exposed-panels/ -rl 20 -c 5 -silent   # HMI/PLC web panels
ffuf -u https://<hmi>/FUZZ -w /usr/share/wordlists/dirb/common.txt -rate 20 -t 5
```

**Firmware / config** pulled from EWS shares, TFTP, or device web UI:

```bash
binwalk -Me firmware.bin
trufflehog filesystem ./extracted --only-verified     # hardcoded creds/keys in firmware
gitleaks dir ./extracted                              # config secrets, VPN PSKs
semgrep --config p/secrets ./project_files            # ladder-logic export, SCADA config dumps
```

## Methodology

1. **Confirm scope & safety envelope.** Get the device inventory, Purdue level map, and an explicit list of which hosts allow active probing vs. passive-only. Identify safety-instrumented systems (SIS) — these are always passive-only.
2. **Map segmentation.** From the entry foothold (usually IT or OT-DMZ), enumerate reachable subnets. Verify whether Purdue boundaries (firewalls between Level 3.5/3/2) actually filter, or if it is a flat network.
3. **Passive collection.** If a tap/SPAN exists, capture and inventory protocols, device IDs, master/slave relationships, and polling intervals before touching anything.
4. **Targeted discovery.** Slow naabu/nmap sweep of OT ports only, low rate, with scan-delay. Avoid `-sV` version probes against control ports — they send malformed payloads.
5. **Identity fingerprinting.** Use protocol-native read-only identity queries (Modbus FC43, S7 SZL, CIP Identity, BACnet ReadProperty) to get vendor/model/firmware. Map to known CVEs.
6. **Auth & access review.** Test default/hardcoded creds on HMIs, switches, EWS, and historians. Check for unauthenticated config/firmware/ladder-logic download.
7. **Read-only register inventory.** With written authorization, read (never write) holding/input registers and coils to demonstrate exposure of process variables. Stay within polling that matches existing master cadence.
8. **IT→OT pivot analysis.** Identify dual-homed EWS, jump hosts, and shared credentials that bridge corporate AD into OT (use `nxc smb`, `ldapsearch`, BloodHound on the IT side only).
9. **Document impact, do not execute it.** Describe what a write/stop/logic-download would achieve; demonstrate the *capability* (reachable port + writable function code accepted on a lab/spare device) rather than acting on production.

## Key Weaknesses / Techniques

**No authentication on control protocols.** Modbus, S7comm (v1/v2), DNP3, EtherNet/IP, and BACnet accept commands from anyone who can route to them. Demonstrate read access only:

```python
# pymodbus — READ holding registers (FC03). Read-only, single request.
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient("10.20.0.10", port=502, timeout=5)
c.connect()
rr = c.read_holding_registers(address=0, count=10, slave=1)
print(rr.registers)            # process values exposed without auth
c.close()
```

**Hardcoded / default credentials.** Siemens/Rockwell/Schneider devices ship with documented defaults; HMIs often keep `admin/admin`, VNC with no password. Verify with the device's own auth, not write commands.

**Unauthenticated firmware & project download.** Many PLCs allow reading the full ladder-logic/project over the protocol or web UI — intellectual property and a blueprint for precise manipulation. Confirm by downloading to file, then analyze offline with `binwalk`/`semgrep`.

**Known CVEs by stack.** Map fingerprint → CVE:
- Siemens S7-300/400 STOP via crafted S7comm (older firmware)
- CODESYS pre-auth RCE / directory traversal (CVE-2022-31806 class)
- Schneider Modicon UMAS auth bypass
- Niagara/Tridium Fox path traversal & cred disclosure
Validate version-only via fingerprint; do not fire memory-corruption PoCs at production.

**Replay & lack of integrity.** Most protocols have no message authentication, so a captured legitimate command can be replayed. Note this as a finding from passive capture; do not replay against live process.

**Flat network / no segmentation.** If a Level 3.5 host can reach Modbus 502 on Level 1, that is itself a critical finding — prove reachability with a TCP connect, not a write.

**IT-side exposure.** Internet-facing devices: search engine fingerprints, exposed VPN appliances, EWS reachable from corporate VLAN. Confirm with `httpx`/`nmap` banner only.

## Validation

- **Reachability PoC:** a successful TCP handshake to the control port plus a benign protocol read (device identity / single register) — captured in pcap with timestamps and source/destination.
- **Identity PoC:** vendor/model/firmware string returned by Modbus FC43, S7 SZL, or CIP Identity object, tied to a specific CVE advisory.
- **Auth-bypass PoC:** screenshot/log of HMI or config download obtained without credentials.
- **Segmentation PoC:** connection succeeding *across* a Purdue boundary that policy says should block it; pair with a denied connection from a correctly-segmented source.
- For each finding record: target IP, port, protocol, exact request bytes, response, timestamp, and confirmation the action was non-mutating. Demonstrate any write/disrupt capability only on a designated lab/spare device, never production.

## False Positives

- **Honeypots/decoys.** Conpot and similar emulate Modbus/S7/SNMP with implausibly uniform banners, every port open, or device IDs that don't match real hardware. Cross-check vendor/firmware consistency and timing.
- **Gateways masquerading as PLCs.** A Modbus/OPC gateway answers 502 but fronts many downstream slaves; the "device" you fingerprinted may be the converter, not the controller.
- **Version banners without exploitability.** A CVE-matching firmware string is not proof the patch is absent or the feature is enabled — confirm preconditions.
- **Open port ≠ writable.** Some devices accept the connection but reject writes via ACL or keyswitch in RUN/PROG position; reachability is the finding, not assumed control.
- **Stale historian data.** Register values may come from a cache/historian, not the live device.

## Chaining & Impact

- Internet-facing HMI default creds → SCADA master → setpoint visibility across the whole plant.
- IT phishing → dual-homed EWS → TIA Portal/Studio 5000 → ladder-logic download then (authorized) modified-logic upload = precise, persistent process manipulation.
- Flat network reachability → unauthenticated Modbus write capability → ability to change coils/registers (setpoints, valve states) → physical process impact / safety event.
- Firmware secrets (trufflehog) → VPN PSK / shared admin cred → broader OT lateral movement.
- Engineering project file → exact process model → targeted, deniable manipulation that stays within alarm thresholds.

## Pro Tips

1. Passive beats active every time in OT — a SPAN port and `tcpdump` reveal device IDs, masters, and polling cadence with zero risk.
2. Never run `nmap -sV`, `-sU` floods, or NSE `*-brute`/aggressive scripts against control ports; version probes send malformed packets that have crashed PLCs.
3. Match your request rate to the existing master's polling interval — an extra poller at a wildly different cadence can desync watchdogs.
4. A PLC with its keyswitch in RUN often refuses writes/logic-downloads; note the physical state, it changes the realistic impact.
5. Identify SIS/safety controllers first and put them strictly out of active scope — disrupting safety logic is the worst possible outcome.
6. The juiciest target is usually the engineering workstation, not the PLC: it holds projects, credentials, and the IT/OT bridge.
7. Fingerprint, then map offline to ICS-CERT/vendor advisories; reserve any exploit firing for lab/spare hardware in the test window.
8. Document the *capability* and reachability; in OT the demonstrated path to impact is the deliverable, not the triggered outage.
