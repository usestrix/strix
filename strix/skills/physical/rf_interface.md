---
name: rf_interface
description: Assessing satellite, radio, and RF interfaces — signal capture, protocol decoding, link-layer abuse, and management-plane exposure
---

# Satellite / Radio / RF Interface

An "RF interface" asset is any system whose primary or auxiliary trust boundary is a radio link: satellite ground terminals (VSAT, Inmarsat, Starlink-class user terminals), LoRa/LoRaWAN gateways, ISM-band telemetry (433/868/915 MHz), Zigbee/Z-Wave/Thread controllers, BLE/Wi-Fi co-processors, GNSS receivers, ADS-B/AIS receivers, and the SDR or modem hardware feeding them. The asset identifier may be a frequency, a NORAD/satellite ID, a device callsign/EUI, a gateway IP, or a modem model. The attacker's objective is to assess the full path: the over-the-air protocol (capture, decode, replay, inject, spoof), the link/session security (keys, auth, freshness), and — critically — the management plane (the web UI, SSH, SNMP, proprietary TCP control port, or cloud backhaul) that almost always sits behind the radio and is the fastest route to durable impact. Treat the RF side and the IP/management side as one continuous attack surface.

## Attack Surface

**Over-the-air (physical/link layer)**
- Uplink/downlink RF carriers — modulation (FSK/GFSK/LoRa CSS/PSK/QAM), framing, FEC, scrambling
- Beacon/broadcast frames (GNSS nav messages, ADS-B, AIS, LoRaWAN join/beacon)
- Join/pairing/association exchanges (LoRaWAN OTAA join, Zigbee Trust Center, BLE pairing)
- Unauthenticated or replayable command/telemetry frames

**Management & control plane (the high-value target)**
- Web admin UI on the terminal/gateway/modem (HTTP/HTTPS, often :80/:443/:8080/:8443)
- SSH/Telnet (often vendor default creds), SNMP (v1/v2c community strings)
- Proprietary TCP/UDP control ports (e.g. modem NMS, satellite terminal "console" sockets)
- Debug/diagnostic interfaces: UART/JTAG headers, USB serial, AT command channels
- Cloud/NMS backhaul: MQTT, REST APIs, LoRaWAN Network Server, vendor SaaS

**Firmware & supply chain**
- OTA firmware update channel (signed? encrypted? rollback-protected?)
- Extractable firmware images (web download, flash dump, vendor portal)
- Hardcoded keys, default LoRaWAN AppKeys, GNSS/SDR driver blobs

## Recon & Enumeration

Most engagements split into an RF-capture track and a management-plane track. Run both.

**Management plane — network discovery (do this first; fastest impact):**
```
naabu -host 192.0.2.10 -top-ports 1000 -o ports.txt
nmap -sV -sC -p- -T4 --version-all 192.0.2.10 -oA rf_mgmt
# Satellite/modem/SDR control ports worth probing explicitly:
nmap -sV -p 22,23,80,161,443,1883,4533,5760,8080,8443,8080,9000,30000 192.0.2.10
httpx -l hosts.txt -title -tech-detect -status-code -ports 80,443,8080,8443 -o httpx.txt
nuclei -u https://192.0.2.10 -as -s critical,high -rl 30 -c 10 -timeout 10 -j -o nuclei.jsonl
wafw00f https://192.0.2.10
```

**SNMP / management protocols (extremely common on terminals & gateways):**
```
nmap -sU -p 161 --script snmp-info,snmp-sysdescr 192.0.2.10
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 192.0.2.10
snmpwalk -v2c -c public 192.0.2.10 .1.3.6.1.2.1   # walk MIB-2; vendor MIBs hold config/keys
```

**Web UI content discovery & auth:**
```
ffuf -u https://192.0.2.10/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc all -fc 404
katana -u https://192.0.2.10 -jc -d 3 -o crawl.txt
jwt_tool <token>            # if the UI/API issues JWTs
```

**RF capture & decode (install SDR toolchain as needed):**
```
apt-get install -y rtl-sdr gqrx-sdr gnuradio multimon-ng rtl-433 dump1090-mutability
pip install urh                              # Universal Radio Hacker (GUI + headless)
# Survey the band for activity, find the carrier:
rtl_power -f 400M:1G:1M -g 40 -i 10 sweep.csv
# Generic ISM/telemetry decode (huge protocol library, great first pass):
rtl_433 -A -f 433.92M                        # -A = analyze/guess modulation
# ADS-B (aircraft) / dump for any 1090 MHz receiver under test:
dump1090 --interactive --net
# Pager/POCSAG/FLEX & misc digital modes:
rtl_fm -f 152.0M -s 22050 | multimon-ng -t raw -a POCSAG1200 -
```

**LoRa / LoRaWAN, GNSS, satellite specifics (install as needed):**
```
pip install LoRaWAN                           # frame parsing/MIC checks
# inspect IQ captures visually:
apt-get install -y inspectrum
# GNSS spoofing/sim research (authorized lab only):
git clone https://github.com/osqzss/gps-sdr-sim && cd gps-sdr-sim && make
```

**Firmware (if an image is obtainable):**
```
binwalk -e firmware.bin                       # carve filesystems/bootloaders
syft dir:_firmware.bin.extracted -o table     # SBOM of extracted rootfs
grype dir:_firmware.bin.extracted             # known-vuln components
trufflehog filesystem _firmware.bin.extracted # hardcoded keys/creds
gitleaks dir _firmware.bin.extracted
semgrep --config auto _firmware.bin.extracted/squashfs-root
trivy fs _firmware.bin.extracted
```

## Methodology

1. **Confirm scope & RF authorization.** Transmitting on most bands is regulated. Confirm written authorization, the exact frequencies/devices in scope, and whether active TX (replay/injection/spoofing) is permitted or capture-only. Default to capture-only until injection is explicitly approved.
2. **Map the asset.** Identify the device model, the radio standard(s), and every IP-reachable surface. Run the management-plane discovery (`naabu`/`nmap`/`httpx`) immediately — the web/SSH/SNMP plane is usually the path of least resistance.
3. **Triage the management plane.** Default creds, exposed SNMP, outdated firmware CVEs (`nuclei -as`), unauthenticated admin endpoints, JWT/session weaknesses. A satellite terminal with `admin/admin` on :8080 is a full compromise without ever touching RF.
4. **Survey the spectrum.** `rtl_power` sweep to locate the active carrier; identify center frequency, bandwidth, and bursting pattern.
5. **Capture IQ & demodulate.** Record at the carrier, view in `inspectrum`/URH, identify modulation, symbol rate, sync word, framing, and FEC.
6. **Decode the protocol.** Use `rtl_433`/`multimon-ng`/URH protocol library or hand-roll a demod chain. Recover frame structure: preamble, address/EUI, sequence/counter, payload, CRC/MIC.
7. **Assess link security.** Is the frame authenticated (MIC/HMAC)? Encrypted? Does it carry a freshness counter (frame counter / nonce)? Are join/pairing exchanges protected?
8. **Test replay & injection (if authorized).** Re-transmit a captured frame; observe whether the receiver acts on it. Then test crafted/modified frames.
9. **Test spoofing & desync** of broadcast/beacon protocols (GNSS, ADS-B, AIS) in an isolated/shielded environment only.
10. **Pivot RF → IP and IP → RF.** Use management-plane access to dump radio keys/config; use recovered RF keys to authenticate to the network server/cloud.
11. **Firmware analysis** of any obtainable image for hardcoded keys, the OTA mechanism, and shared/global secrets.
12. **Validate, document, stop at proof.** PoC with minimal-impact evidence; never disrupt a live satellite/aviation/maritime service.

## Key Weaknesses / Techniques

**Replay attacks (no/weak freshness).** Many telemetry, remote-control, and IoT-radio frames have no rolling counter or accept stale counters. Capture a command frame and re-send it.
```
# Capture a burst at the carrier, then re-transmit the same IQ (authorized TX only):
urh_cli --device HackRF --frequency 433920000 --sample-rate 2000000 --receive -f capture.complex
urh_cli --device HackRF --frequency 433920000 --sample-rate 2000000 --transmit -f capture.complex
```
Confirm the receiver actuates (door opens, relay toggles, telemetry value changes).

**Missing message authentication / integrity.** If frames lack a MIC/HMAC, you can modify payload bytes and recompute only the CRC. Decode → flip target field → recompute CRC → encode → TX. CRC is error-detection, not authentication.

**Predictable / replayable LoRaWAN join & frame counters.** Test ABP devices with frame-counter reset enabled (counter rolls to 0 on reboot → replay of old frames accepted). For OTAA, capture join-accept handling; verify `DevNonce` is tracked server-side to block join replay. Parse and verify the MIC:
```
python3 - <<'EOF'
from LoRaWAN import lorawan, MalformedPacket
# Load AppKey/NwkSKey recovered from firmware/config, parse a captured PHYPayload,
# and check whether the MIC validates and whether the frame counter is enforced.
EOF
```

**Default / shared / hardcoded keys.** LoRaWAN AppKeys baked per-model, default Zigbee Trust Center link key (`ZigBeeAlliance09`), global firmware keys. Extract via `binwalk`/`trufflehog` and test against a live device.

**GNSS / ADS-B / AIS spoofing (unauthenticated broadcast).** These protocols have no message authentication. In a shielded enclosure, generate spoofed nav frames to assess receiver hardening (does it sanity-check position jumps, time, multi-constellation consistency?). Never radiate spoofed GNSS/ADS-B/AIS outside an RF-tight enclosure.

**Management-plane vulns behind the radio (usually the real win):**
- Default credentials (`admin/admin`, `admin/<serial>`, vendor docs).
- Unauthenticated config/diagnostic endpoints exposing keys: `curl -sk https://192.0.2.10/cgi-bin/config.cgi`
- SNMP read-write community → rewrite radio config: `snmpset -v2c -c private 192.0.2.10 <oid> ...`
- Command injection in terminal web UIs (ping/traceroute/firmware-name fields):
  ```
  curl -sk "https://192.0.2.10/diag?host=127.0.0.1;id"
  ```
- Insecure OTA: unsigned/unencrypted firmware → push a modified image.
- AT-command injection over exposed serial/USB/TCP modem channels.

**SSRF/cloud backhaul.** Terminals that proxy to a vendor NMS or cloud API can be steered at internal/metadata endpoints — apply standard SSRF methodology to any URL-handling field.

## Validation

1. **Replay:** show a captured frame, re-transmitted unmodified, causes the receiver to act (logged state change, actuator movement, telemetry mutation). Capture before/after.
2. **Injection/forgery:** demonstrate a crafted frame (modified field + valid CRC, or valid forged MIC using a recovered key) is accepted. Include the decoded original and modified frames side by side.
3. **Key recovery:** show the extracted key (from firmware/SNMP/config) and prove it validates/decrypts live traffic (MIC check passes, payload decrypts to sensible values).
4. **Management plane:** for default creds / injection / CVE, capture the authenticated session or command output (`id`, config dump) as proof.
5. **Reproducibility:** record exact center frequency, sample rate, modulation, gain, and the capture/TX commands so the finding is repeatable.

## False Positives

- **Decode noise.** `rtl_433 -A` guesses modulation; a "decoded" frame may be random RF or another device on the band. Verify the decode is stable and tied to the asset (toggle the device, confirm correlated frames).
- **Replay that does nothing.** Receiver accepted the RF but took no action (or rejected via counter/MIC silently). Replay is only a finding if it causes observable effect.
- **Encrypted ≠ broken.** Capturing ciphertext is not a vulnerability; confirm you can replay, forge, or decrypt.
- **Your own interference.** Bench TX can desync a link without a real auth bypass — confirm the receiver *accepted and acted on* the frame, not that it merely glitched.
- **Out-of-scope emitters.** ISM bands are crowded; a finding on a neighbor's weather sensor is not your asset.
- **Lab-only spoofing.** GNSS/ADS-B/AIS spoofing in a shielded box proves receiver behavior, not necessarily a real-world exploitable condition for that deployment.

## Chaining & Impact

- **Management default creds → radio key dump → OTA frame forgery:** log into the terminal/gateway, read the stored NwkSKey/AppKey, then forge authenticated commands the network treats as legitimate.
- **Firmware hardcoded key → fleet-wide forgery:** one extracted global key forges/decrypts traffic for every device of that model.
- **Replay → actuation → safety/physical impact:** replayed control frames toggle relays, gates, SCADA/RTU telemetry, or satellite-terminal config.
- **SNMP RW → reconfigure carrier/frequency → DoS or redirect** the link, or pivot the management config to expose more services.
- **Command injection / unsigned OTA → terminal RCE → persistent foothold** bridging the RF segment to the IP network and cloud backhaul.
- **GNSS spoofing → time/position manipulation** affecting downstream timing-dependent systems (assess in lab; flag deployment risk).

## Pro Tips

1. **Hit the management plane first.** A web UI with default creds or an exposed SNMP community beats hours of DSP. RF is the headline; IP is usually the win.
2. **Capture-only until TX is explicitly authorized.** Transmitting is regulated and can interfere with safety-of-life systems (aviation/maritime/satellite). Get it in writing.
3. **`rtl_power` then `inspectrum`/URH.** Sweep to find energy, then look at the IQ before guessing — symbol rate and framing are obvious visually.
4. **Counters are the tell.** Whether replay works hinges on frame-counter/nonce enforcement. Reboot ABP/IoT devices and watch for counter reset.
5. **CRC is not auth.** If there's only a CRC, assume forgery is possible and prove it by flipping a byte and recomputing.
6. **Pull keys from firmware before brute-forcing RF.** `binwalk` + `trufflehog` on the image often hands you AppKeys, default creds, and the OTA pubkey.
7. **Shield spoofing tests.** GNSS/ADS-B/AIS injection belongs in a Faraday enclosure or via cabled/attenuated injection — never over the air.
8. **Correlate to confirm.** Toggle the physical device and match the on-air frame change; that single step kills most false-positive decodes.
9. **Don't disrupt live links.** For satellite/aviation/maritime assets, stop at proof — availability impact can be real-world dangerous and out of scope.
